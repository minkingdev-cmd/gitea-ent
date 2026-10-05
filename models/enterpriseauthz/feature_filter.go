// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"

	"gitea.dev/models/db"
	"gitea.dev/modules/cache"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/log"
	"gitea.dev/modules/setting"

	"xorm.io/builder"
)

var ErrFeatureQueryUnavailable = errors.New("feature_policy_unavailable")

// RepoFeatureEnabledCond filters content before pagination using the current owner.
// repoIDSQL must be a trusted SQL column, never request input.
func RepoFeatureEnabledCond(ctx context.Context, key authz.FeatureKey, repoIDSQL string) builder.Cond {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return builder.NewCond()
	}
	return RepoFeatureCandidateCond(ctx, key, repoIDSQL)
}

// RepoFeatureCandidateCond 仅构建候选条件，不决定是否过滤原生查询。
func RepoFeatureCandidateCond(_ context.Context, key authz.FeatureKey, repoIDSQL string) builder.Cond {
	scope := "(fg.scope_type = 'system' AND fg.scope_id = 0) OR (fg.scope_type = 'org' AND fg.scope_id IN (SELECT r.owner_id FROM repository r INNER JOIN `user` u ON u.id = r.owner_id AND u.type = 1 WHERE r.id = " + repoIDSQL + ")) OR (fg.scope_type = 'repo' AND fg.scope_id = " + repoIDSQL + ")"
	// The first ancestor lock wins, including required above a stale disabled child.
	return builder.Expr("EXISTS (SELECT 1 FROM enterprise_feature_definition fd WHERE fd.key = ? AND fd.catalog_version = ? AND fd.config_schema_version = 1 AND fd.default_state = 'enabled' AND fd.capability_kind = 'native_gate' AND fd.policy_revision >= 1)", key, authz.FeatureCatalogVersion).And(builder.Expr("COALESCE((SELECT fg.state FROM enterprise_feature_grant fg WHERE fg.feature_key = ? AND ("+scope+") AND fg.state IN ('disabled','required') ORDER BY CASE fg.scope_type WHEN 'system' THEN 0 WHEN 'org' THEN 1 ELSE 2 END LIMIT 1), 'enabled') <> 'disabled'", key)).And(builder.Expr("NOT EXISTS (SELECT 1 FROM enterprise_feature_grant fg WHERE fg.feature_key = ? AND ("+scope+") AND (fg.state NOT IN ('disabled','enabled','required','inherited') OR fg.revision < 1 OR fg.config_json <> '{}'))", key))
}

// ValidateFeatureQueryBoundary performs one catalog check per query, not per row.
func ValidateFeatureQueryBoundary(ctx context.Context, key authz.FeatureKey) (bool, error) {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return false, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !setting.AuditRecordEnabled() {
		if setting.EnterpriseAuthz.FailClosedOnError {
			return false, ErrFeatureQueryUnavailable
		}
		authz.FeatureQueryFallback.WithLabelValues("audit_unavailable").Inc()
		log.Error("Enterprise aggregate feature query evidence unavailable; using explicit native fallback")
		return false, nil
	}
	definition, exists, err := db.Get[FeatureDefinition](ctx, builder.Eq{"key": key})
	if err == nil && exists {
		err = definition.Validate()
	} else if err == nil {
		err = errors.New("feature_seed_missing")
	}
	if err != nil {
		if !setting.EnterpriseAuthz.FailClosedOnError {
			authz.FeatureQueryFallback.WithLabelValues("policy_unavailable").Inc()
			log.Error("Enterprise feature query fell back to native permissions: feature_policy_unavailable")
			return false, nil
		}
		return false, ErrFeatureQueryUnavailable
	}
	return true, nil
}

func FeatureQueryCond(ctx context.Context, key authz.FeatureKey, repoIDSQL string) (builder.Cond, error) {
	apply, err := ValidateFeatureQueryBoundary(ctx, key)
	if err != nil {
		return nil, err
	}
	if !apply {
		return builder.NewCond(), nil
	}
	return RepoFeatureEnabledCond(ctx, key, repoIDSQL), nil
}

type featureProjectionSnapshot struct {
	grants map[Scope]*FeatureGrant
	err    error
}

// RepoFeatureVisible batches policy reads for repository projections in one request.
func RepoFeatureVisible(ctx context.Context, key authz.FeatureKey, repoID, ownerID int64, isOrg bool) (bool, error) {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return true, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	snapshot, _ := cache.GetWithContextCache(ctx, "enterprise.feature.projection", key, func(ctx context.Context, key authz.FeatureKey) (featureProjectionSnapshot, error) {
		apply, err := ValidateFeatureQueryBoundary(ctx, key)
		if err != nil || !apply {
			return featureProjectionSnapshot{err: err}, nil
		}
		var rows []*FeatureGrant
		err = db.GetEngine(ctx).Where(builder.Eq{"feature_key": key}).Find(&rows)
		if err != nil {
			if ctx.Err() != nil {
				return featureProjectionSnapshot{err: ctx.Err()}, nil
			}
			if !setting.EnterpriseAuthz.FailClosedOnError {
				authz.FeatureQueryFallback.WithLabelValues("policy_unavailable").Inc()
				log.Error("Enterprise feature projection fell back to native permissions: feature_policy_unavailable")
				return featureProjectionSnapshot{}, nil
			}
			return featureProjectionSnapshot{err: ErrFeatureQueryUnavailable}, nil
		}
		result := make(map[Scope]*FeatureGrant, len(rows))
		for _, grant := range rows {
			result[grant.Scope()] = grant
		}
		return featureProjectionSnapshot{grants: result}, nil
	})
	if snapshot.err != nil {
		return false, snapshot.err
	}
	scopes := []Scope{{Type: ScopeSystem}, {Type: ScopeRepo, ID: repoID}}
	if isOrg {
		scopes = []Scope{{Type: ScopeSystem}, {Type: ScopeOrg, ID: ownerID}, {Type: ScopeRepo, ID: repoID}}
	}
	layers := make([]authz.FeatureLayer, 0, len(scopes))
	for _, scope := range scopes {
		if grant := snapshot.grants[scope]; grant != nil {
			if err := grant.Validate(); err != nil {
				return false, ErrFeatureQueryUnavailable
			}
			layers = append(layers, authz.FeatureLayer{Scope: FeatureScopeName(scope.Type), ID: scope.ID, State: grant.State, Revision: grant.Revision})
		}
	}
	metadata, _ := authz.LookupFeature(key)
	result, err := authz.ResolveFeature(metadata, layers)
	return err == nil && result.State != authz.FeatureDisabled, err
}
