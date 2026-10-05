// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"

	"gitea.dev/models/db"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"

	"xorm.io/builder"
)

func OwnerFeatureEnabledCond(ctx context.Context, key authz.FeatureKey, ownerIDSQL string) builder.Cond {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return builder.NewCond()
	}
	return ownerFeatureCandidateCond(ctx, key, ownerIDSQL)
}

func ownerFeatureCandidateCond(_ context.Context, key authz.FeatureKey, ownerIDSQL string) builder.Cond {
	scope := "(fg.scope_type='system' AND fg.scope_id=0) OR (fg.scope_type='org' AND fg.scope_id=" + ownerIDSQL + " AND EXISTS (SELECT 1 FROM `user` u WHERE u.id=" + ownerIDSQL + " AND u.type=1))"
	return builder.Expr("EXISTS (SELECT 1 FROM `user` u WHERE u.id=" + ownerIDSQL + ")").And(builder.Expr("COALESCE((SELECT fg.state FROM enterprise_feature_grant fg WHERE fg.feature_key=? AND ("+scope+") AND fg.state IN ('disabled','required') ORDER BY CASE fg.scope_type WHEN 'system' THEN 0 ELSE 1 END LIMIT 1),'enabled')<>'disabled'", key)).And(builder.Expr("NOT EXISTS (SELECT 1 FROM enterprise_feature_grant fg WHERE fg.feature_key=? AND ("+scope+") AND (fg.state NOT IN ('disabled','enabled','required','inherited') OR fg.revision<1 OR fg.config_json<>'{}'))", key))
}

func PackageFeatureEnabledCond(ctx context.Context) builder.Cond {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return builder.NewCond()
	}
	return PackageFeatureCandidateCond(ctx)
}

func PackageFeatureCandidateCond(ctx context.Context) builder.Cond {
	return ownerFeatureCandidateCond(ctx, authz.FeaturePackages, "package.owner_id").And(builder.Eq{"package.repo_id": 0}.Or(builder.Expr("EXISTS (SELECT 1 FROM repository r WHERE r.id=package.repo_id)").And(RepoFeatureCandidateCond(ctx, authz.FeaturePackages, "package.repo_id"))))
}

func PackageFeatureQueryCond(ctx context.Context) (builder.Cond, error) {
	apply, err := ValidateFeatureQueryBoundary(ctx, authz.FeaturePackages)
	if err != nil {
		return nil, err
	}
	if !apply {
		return builder.NewCond(), nil
	}
	return PackageFeatureEnabledCond(ctx), nil
}

func DeniedCargoIndexRepositoryIDs(ctx context.Context) ([]int64, error) {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return nil, nil
	}
	apply, err := ValidateFeatureQueryBoundary(ctx, authz.FeaturePackages)
	if err != nil {
		return nil, err
	}
	if !apply {
		return nil, nil
	}
	return deniedCargoIndexRepositoryIDs(ctx, nil)
}

func CandidateDeniedCargoIndexRepositoryIDs(ctx context.Context, repoIDs ...int64) ([]int64, error) {
	if !setting.EnterpriseAuthz.Enabled {
		return nil, nil
	}
	definition, exists, err := db.Get[FeatureDefinition](ctx, builder.Eq{"key": authz.FeaturePackages})
	if err != nil || !exists || definition.Validate() != nil {
		return nil, ErrFeatureQueryUnavailable
	}
	return deniedCargoIndexRepositoryIDs(ctx, repoIDs)
}

func deniedCargoIndexRepositoryIDs(ctx context.Context, repoIDs []int64) ([]int64, error) {
	actualPackageDenied := builder.Select("package.id").From("package").Where(builder.And(builder.Expr("package.owner_id=idx.owner_id"), builder.Eq{"package.type": "cargo"}, builder.Not{PackageFeatureCandidateCond(ctx)}))
	packageSQL, packageArgs, err := builder.ToSQL(actualPackageDenied)
	if err != nil {
		return nil, ErrFeatureQueryUnavailable
	}
	sourceDenied := builder.Select("cs.id").From("enterprise_cargo_index_source cs").Where(builder.And(builder.Expr("cs.index_repo_id=idx.id"), builder.Or(builder.Expr("NOT EXISTS (SELECT 1 FROM repository r WHERE r.id=cs.source_repo_id)"), builder.Not{RepoFeatureCandidateCond(ctx, authz.FeaturePackages, "cs.source_repo_id")})))
	sourceSQL, sourceArgs, err := builder.ToSQL(sourceDenied)
	if err != nil {
		return nil, ErrFeatureQueryUnavailable
	}
	cond := builder.And(builder.Eq{"idx.internal_usage": "cargo-index"}, builder.Or(builder.Not{ownerFeatureCandidateCond(ctx, authz.FeaturePackages, "idx.owner_id")}, builder.Not{RepoFeatureCandidateCond(ctx, authz.FeaturePackages, "idx.id")}, builder.Expr("EXISTS ("+packageSQL+")", packageArgs...), builder.Expr("EXISTS ("+sourceSQL+")", sourceArgs...)))
	if len(repoIDs) > 0 {
		cond = cond.And(builder.In("idx.id", repoIDs))
	}
	var ids []int64
	err = db.GetEngine(ctx).Table("repository").Alias("idx").Where(cond).Cols("idx.id").Find(&ids)
	if err != nil {
		return nil, ErrFeatureQueryUnavailable
	}
	return ids, nil
}
