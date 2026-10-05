// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	repo_model "gitea.dev/models/repo"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func RequiredChecksChanged(ctx context.Context, rule *git_model.ProtectedBranch) (bool, error) {
	current, err := git_model.GetProtectedBranchRuleByID(ctx, rule.RepoID, rule.ID)
	if err != nil {
		return false, err
	}
	if current == nil {
		old, next, err := protectionMutationRules(ctx, rule.RepoID, rule)
		if err != nil {
			return false, err
		}
		return hasStatusChecks(rule) || protectionPriorityChecksChanged(old, next), nil
	}
	changed := current.EnableStatusCheck != rule.EnableStatusCheck || !statusCheckContextsEqual(current.StatusCheckContexts, rule.StatusCheckContexts) || (hasStatusChecks(current) || hasStatusChecks(rule)) && (current.RuleName != rule.RuleName || current.Priority != rule.Priority)
	old, next, err := protectionMutationRules(ctx, rule.RepoID, rule)
	if err != nil {
		return false, err
	}
	return changed || protectionPriorityChecksChanged(old, next), nil
}

func requireProtectionExecution(ctx context.Context, repo *repo_model.Repository, rule *git_model.ProtectedBranch) error {
	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
		if repo == nil || rule == nil || rule.RepoID != repo.ID {
			return &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
		}
		if rule.ID > 0 {
			current, exists, err := db.GetByID[git_model.ProtectedBranch](ctx, rule.ID)
			if err != nil {
				return err
			}
			if !exists || current.RepoID != repo.ID {
				return &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
			}
		}
	}
	intent := authz_service.SettingsIntent(authz.ManageBranchProtection, rule.RuleName)
	if err := authz_service.RequireExecutionTarget(ctx, repo, authz.ManageBranchProtection, intent); err != nil {
		return err
	}
	changed, err := RequiredChecksChanged(ctx, rule)
	if err != nil {
		return err
	}
	if changed {
		return authz_service.RequireExecutionTarget(ctx, repo, authz.ManageCI, intent)
	}
	return nil
}

func UpdateProtectedBranch(ctx context.Context, repo *repo_model.Repository, rule *git_model.ProtectedBranch, opts git_model.WhitelistOptions) error {
	if err := requireProtectionExecution(ctx, repo, rule); err != nil {
		return err
	}
	return withProtectionFeatureLock(ctx, repo, func(ctx context.Context) error {
		if err := requireProtectionExecution(ctx, repo, rule); err != nil {
			return err
		}
		old, err := git_model.GetProtectedBranchRuleByID(ctx, repo.ID, rule.ID)
		if err != nil {
			return err
		}
		if err := requireStatusChecksIntent(ctx, repo.ID, old, rule); err != nil {
			return err
		}
		oldRules, nextRules, err := protectionMutationRules(ctx, repo.ID, rule)
		if err != nil {
			return err
		}
		if err := requireStatusChecksPriority(ctx, repo.ID, oldRules, nextRules); err != nil {
			return err
		}
		return git_model.UpdateProtectBranch(ctx, repo, rule, opts)
	})
}

func DeleteProtectedBranch(ctx context.Context, repo *repo_model.Repository, ruleID int64) error {
	rule, err := git_model.GetProtectedBranchRuleByID(ctx, repo.ID, ruleID)
	if err != nil {
		return err
	}
	if rule != nil {
		intent := authz_service.SettingsIntent(authz.ManageBranchProtection, rule.RuleName)
		if err := authz_service.RequireExecutionTarget(ctx, repo, authz.ManageBranchProtection, intent); err != nil {
			return err
		}
		if rule.EnableStatusCheck || len(rule.StatusCheckContexts) > 0 {
			if err := authz_service.RequireExecutionTarget(ctx, repo, authz.ManageCI, intent); err != nil {
				return err
			}
		}
	}
	return withProtectionFeatureLock(ctx, repo, func(ctx context.Context) error {
		old, err := git_model.GetProtectedBranchRuleByID(ctx, repo.ID, ruleID)
		if err != nil {
			return err
		}
		if err := requireStatusChecksIntent(ctx, repo.ID, old, nil); err != nil {
			return err
		}
		return git_model.DeleteProtectedBranch(ctx, repo, ruleID)
	})
}

func UpdateProtectBranchPriorities(ctx context.Context, repo *repo_model.Repository, ids []int64) error {
	if err := authz_service.RequireExecutionTarget(ctx, repo, authz.ManageBranchProtection, authz_service.SettingsIntent(authz.ManageBranchProtection, "priority")); err != nil {
		return err
	}
	old, next, err := protectionPriorities(ctx, repo.ID, ids)
	if err != nil {
		return err
	}
	if protectionPriorityChecksChanged(old, next) {
		if err := authz_service.RequireExecutionTarget(ctx, repo, authz.ManageCI, authz_service.SettingsIntent(authz.ManageBranchProtection, "priority")); err != nil {
			return err
		}
	}
	return withProtectionFeatureLock(ctx, repo, func(ctx context.Context) error {
		old, next, err := protectionPriorities(ctx, repo.ID, ids)
		if err != nil {
			return err
		}
		if err := requireStatusChecksPriority(ctx, repo.ID, old, next); err != nil {
			return err
		}
		return git_model.UpdateProtectBranchPriorities(ctx, repo, ids)
	})
}

func withProtectionFeatureLock(ctx context.Context, repo *repo_model.Repository, update func(context.Context) error) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
			if err := authz_model.LockScope(ctx, authz_model.Scope{Type: authz_model.ScopeRepo, ID: repo.ID}); err != nil {
				if rejection := authz_service.FeatureGuardError(err); rejection != nil {
					return rejection
				}
			}
			current, err := repo_model.GetRepositoryByID(ctx, repo.ID)
			if err != nil {
				return &authz_service.ExecutionError{Reason: "policy_read_failed", Status: 503}
			}
			if current.OwnerID != repo.OwnerID {
				return &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
			}
			if err := authz_model.LockFeatures(ctx, []authz.FeatureKey{authz.FeatureRequiredStatusChecks}); err != nil {
				if rejection := authz_service.FeatureGuardError(err); rejection != nil {
					return rejection
				}
			}
		}
		return update(ctx)
	})
}
