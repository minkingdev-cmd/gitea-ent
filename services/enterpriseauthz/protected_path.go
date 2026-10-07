// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	"gitea.dev/modules/web/middleware"

	"xorm.io/builder"
)

var ErrMergeGateRuleLimit = errors.New("merge_gate_rules_limit_exceeded")

type ProtectedPathRuleInput struct {
	Config           []byte
	ExpectedRevision int64
}

type ProtectedPathPolicy struct {
	Rule         authz_model.ProtectedPathRule
	Config       authz.ProtectedPathConfig
	RoleRevision int64
	Unresolved   bool
}

func LockMergeGatePolicyScopes(ctx context.Context, scope authz_model.Scope) error {
	if err := authz_model.LockFeatures(ctx, []authz.FeatureKey{authz.FeaturePullRequests}); err != nil {
		return err
	}
	if scope.Type != authz_model.ScopeRepo {
		return authz_model.LockScope(ctx, scope)
	}
	repo, err := repo_model.GetRepositoryByID(ctx, scope.ID)
	if err != nil {
		return err
	}
	owner, err := user_model.GetUserByID(ctx, repo.OwnerID)
	if err != nil {
		return err
	}
	if owner.IsOrganization() {
		if err := authz_model.LockScope(ctx, authz_model.Scope{Type: authz_model.ScopeOrg, ID: owner.ID}); err != nil {
			return err
		}
	}
	if err := authz_model.LockScope(ctx, scope); err != nil {
		return err
	}
	fresh, err := repo_model.GetRepositoryByID(ctx, scope.ID)
	if err != nil {
		return err
	}
	if fresh.OwnerID != owner.ID {
		return ErrRevisionConflict
	}
	return nil
}

func authorizeProtectedPaths(ctx context.Context, actor *user_model.User, scope authz_model.Scope, write bool) error {
	if !setting.EnterpriseMergeGate.Enabled {
		return util.ErrNotExist
	}
	resolved, err := authorizePolicy(ctx, actor, scope)
	if err != nil {
		return err
	}
	if token, exists := middleware.GetContextData(ctx)["ApiTokenScope"].(auth_model.AccessTokenScope); exists {
		publicOnly, err := token.PublicOnly()
		if err != nil || publicOnly {
			return util.ErrPermissionDenied
		}
	}
	if err := featureCredential(ctx, actor, scope, write); err != nil {
		return err
	}
	if resolved.repo != nil {
		if resolved.actor.IsAdmin {
			resolved.actor.IsAdmin, err = access_model.HasSystemManagementAuthority(ctx, resolved.actor)
			if err != nil {
				return ErrPolicyStorage
			}
		}
		permission, err := access_model.GetDoerRepoPermission(ctx, resolved.repo, resolved.actor)
		if err != nil {
			return ErrPolicyStorage
		}
		if !permission.CanRead(unit.TypeCode) {
			return util.ErrPermissionDenied
		}
		if write {
			decision, err := evaluate(ctx, EvaluateInput{Actor: resolved.actor, Repo: resolved.repo, Permission: &permission, Credential: RequestCredentialCeiling(ctx, actor), Action: authz.ManageSensitivePaths, ConditionContext: authz.ConditionContext{Source: "api"}}, true)
			if err != nil {
				return ErrPolicyStorage
			}
			if decision.CandidateDecision != "allow" {
				return util.ErrPermissionDenied
			}
		}
	}
	return nil
}

func ListProtectedPathRules(ctx context.Context, actor *user_model.User, scope authz_model.Scope, options PolicyListOptions) ([]authz_model.ProtectedPathRule, int64, error) {
	limit, offset, err := options.pagination()
	if err != nil {
		return nil, 0, err
	}
	var result []authz_model.ProtectedPathRule
	var count int64
	err = db.WithIndependentReadTx(ctx, func(tx context.Context) error {
		if err := authorizeProtectedPaths(tx, actor, scope, false); err != nil {
			return err
		}
		cond := builder.Eq{"scope_type": scope.Type, "scope_id": scope.ID, "deleted": false}
		var err error
		count, err = db.GetEngine(tx).Where(cond).Count(new(authz_model.ProtectedPathRule))
		if err != nil {
			return ErrPolicyStorage
		}
		if err := db.GetEngine(tx).Where(cond).OrderBy("id").Limit(limit, offset).Find(&result); err != nil {
			return ErrPolicyStorage
		}
		for _, rule := range result {
			if rule.Validate() != nil {
				return ErrPolicyStorage
			}
		}
		return nil
	})
	return result, count, safePolicyError(err)
}

func GetProtectedPathRule(ctx context.Context, actor *user_model.User, scope authz_model.Scope, id int64) (*authz_model.ProtectedPathRule, error) {
	var result *authz_model.ProtectedPathRule
	err := db.WithIndependentReadTx(ctx, func(tx context.Context) error {
		if err := authorizeProtectedPaths(tx, actor, scope, false); err != nil {
			return err
		}
		var err error
		result, err = readProtectedPathRule(tx, scope, id)
		return err
	})
	return result, safePolicyError(err)
}

func readProtectedPathRule(ctx context.Context, scope authz_model.Scope, id int64) (*authz_model.ProtectedPathRule, error) {
	rule, exists, err := db.Get[authz_model.ProtectedPathRule](ctx, builder.Eq{"id": id, "scope_type": scope.Type, "scope_id": scope.ID})
	if err != nil {
		return nil, ErrPolicyStorage
	}
	if !exists {
		return nil, util.ErrNotExist
	}
	if rule.Validate() != nil {
		return nil, ErrPolicyStorage
	}
	return rule, nil
}

func PutProtectedPathRule(ctx context.Context, actor *user_model.User, scope authz_model.Scope, id int64, input ProtectedPathRuleInput) (*authz_model.ProtectedPathRule, error) {
	config, canonical, err := authz.ParseProtectedPathConfig(input.Config)
	if err != nil || id < 0 || input.ExpectedRevision < 0 {
		return nil, ErrInvalidPolicy
	}
	if err := authorizeProtectedPaths(ctx, actor, scope, true); err != nil {
		return nil, safePolicyError(err)
	}
	var result *authz_model.ProtectedPathRule
	err = withPolicyMutation(ctx, actor, scope, func(tx context.Context, resolved *managementScope) error {
		if err := authorizeProtectedPaths(tx, actor, scope, true); err != nil {
			return err
		}
		if resolved.repo != nil {
			if err := resolved.repo.LoadOwner(tx); err != nil {
				return ErrPolicyStorage
			}
		}
		if _, err := readRole(tx, resolved, config.RequiredRoleID, true); err != nil {
			if errors.Is(err, util.ErrNotExist) {
				return ErrInvalidPolicy
			}
			return err
		}
		rule := &authz_model.ProtectedPathRule{ID: id, ScopeType: scope.Type, ScopeID: scope.ID, OwnerID: resolved.ownerID, ConfigJSON: canonical, RequiredRoleID: config.RequiredRoleID, Enabled: config.Enabled, CreatedBy: resolved.actor.ID, UpdatedBy: resolved.actor.ID}
		beforeRevision := int64(0)
		beforeHash := ""
		if id != 0 {
			before, err := readProtectedPathRule(tx, scope, id)
			if err != nil {
				return err
			}
			beforeRevision = before.Revision
			hash := sha256.Sum256([]byte(before.ConfigJSON))
			beforeHash = hex.EncodeToString(hash[:])
		}
		if err := authz_model.SaveProtectedPathRule(tx, rule, input.ExpectedRevision); err != nil {
			if errors.Is(err, authz_model.ErrMergeGateRevision) {
				return ErrRevisionConflict
			}
			return ErrPolicyStorage
		}
		result = rule
		if beforeRevision == rule.Revision {
			return nil
		}
		action := audit_model.EnterpriseProtectedPathUpdate
		if id == 0 {
			action = audit_model.EnterpriseProtectedPathCreate
		}
		hash := sha256.Sum256([]byte(rule.ConfigJSON))
		return recordPolicyEvent(tx, resolved, action, map[string]any{"rule_id": rule.ID, "before_revision": beforeRevision, "after_revision": rule.Revision, "before_config_hash": beforeHash, "after_config_hash": hex.EncodeToString(hash[:]), "owner_id": rule.OwnerID, "required_role_id": rule.RequiredRoleID})
	})
	return result, safePolicyError(err)
}

func DeleteProtectedPathRule(ctx context.Context, actor *user_model.User, scope authz_model.Scope, id, expectedRevision int64) error {
	if expectedRevision <= 0 || id <= 0 {
		return ErrInvalidPolicy
	}
	if err := authorizeProtectedPaths(ctx, actor, scope, true); err != nil {
		return safePolicyError(err)
	}
	err := withPolicyMutation(ctx, actor, scope, func(tx context.Context, resolved *managementScope) error {
		if err := authorizeProtectedPaths(tx, actor, scope, true); err != nil {
			return err
		}
		rule, err := readProtectedPathRule(tx, scope, id)
		if err != nil {
			return err
		}
		rule.Deleted, rule.Enabled, rule.UpdatedBy = true, false, resolved.actor.ID
		if err := authz_model.SaveProtectedPathRule(tx, rule, expectedRevision); err != nil {
			if errors.Is(err, authz_model.ErrMergeGateRevision) {
				return ErrRevisionConflict
			}
			return ErrPolicyStorage
		}
		return recordPolicyEvent(tx, resolved, audit_model.EnterpriseProtectedPathDelete, map[string]any{"rule_id": id, "before_revision": expectedRevision, "after_revision": rule.Revision})
	})
	return safePolicyError(err)
}

func EffectiveProtectedPathRules(ctx context.Context, repoID int64) ([]ProtectedPathPolicy, error) {
	if !setting.EnterpriseMergeGate.Enabled {
		return nil, nil
	}
	var policies []ProtectedPathPolicy
	err := func(tx context.Context) error {
		repo, err := repo_model.GetRepositoryByID(tx, repoID)
		if err != nil {
			return ErrPolicyStorage
		}
		if err := repo.LoadOwner(tx); err != nil {
			return ErrPolicyStorage
		}
		scopes := []authz_model.Scope{{Type: authz_model.ScopeSystem}}
		if repo.Owner.IsOrganization() {
			scopes = append(scopes, authz_model.Scope{Type: authz_model.ScopeOrg, ID: repo.OwnerID})
		}
		scopes = append(scopes, authz_model.Scope{Type: authz_model.ScopeRepo, ID: repoID})
		var conditions []builder.Cond
		for _, scope := range scopes {
			conditions = append(conditions, builder.Eq{"scope_type": scope.Type, "scope_id": scope.ID})
		}
		var rules []authz_model.ProtectedPathRule
		if err := db.GetEngine(tx).Where(builder.And(builder.Or(conditions...), builder.Eq{"enabled": true, "deleted": false})).OrderBy("id").Limit(authz.MaxProtectedPathRules + 1).Find(&rules); err != nil {
			return ErrPolicyStorage
		}
		if len(rules) > authz.MaxProtectedPathRules {
			return ErrMergeGateRuleLimit
		}
		for _, scope := range scopes {
			for _, rule := range rules {
				if rule.Scope() != scope {
					continue
				}
				if err := rule.Validate(); err != nil {
					return ErrPolicyStorage
				}
				config, _, _ := authz.ParseProtectedPathConfig([]byte(rule.ConfigJSON))
				policy := ProtectedPathPolicy{Rule: rule, Config: config, Unresolved: scope.Type != authz_model.ScopeSystem && rule.OwnerID != repo.OwnerID}
				role, exists, err := db.Get[authz_model.RoleDefinition](tx, builder.Eq{"id": rule.RequiredRoleID})
				if err != nil {
					return ErrPolicyStorage
				}
				if !exists || !slices.Contains(scopes[:slices.Index(scopes, scope)+1], role.Scope()) {
					policy.Unresolved = true
				} else {
					if role.Revision < 1 {
						return ErrPolicyStorage
					}
					policy.RoleRevision = role.Revision
				}
				policies = append(policies, policy)
			}
		}
		return nil
	}
	if db.InTransaction(ctx) {
		readErr := err(ctx)
		return policies, readErr
	}
	if readErr := db.WithIndependentReadTx(ctx, err); readErr != nil {
		return nil, readErr
	}
	return policies, nil
}

func MergeGateReviewerRoles(ctx context.Context, reviewerID int64, repo *repo_model.Repository) ([]int64, error) {
	reviewer, err := user_model.GetUserByID(ctx, reviewerID)
	if user_model.IsErrUserNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, ErrPolicyStorage
	}
	if !roleEligible(reviewer) {
		return nil, nil
	}
	_, roles, err := resolveRoles(ctx, reviewer, repo)
	if err != nil {
		return nil, ErrPolicyStorage
	}
	ids := make([]int64, 0, len(roles))
	for id, role := range roles {
		if role.Revision < 1 {
			return nil, ErrPolicyStorage
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids, nil
}
