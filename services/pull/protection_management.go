// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"slices"

	"gitea.dev/models/db"
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
		return rule.EnableStatusCheck || len(rule.StatusCheckContexts) > 0, nil
	}
	return current.EnableStatusCheck != rule.EnableStatusCheck || !slices.Equal(current.StatusCheckContexts, rule.StatusCheckContexts), nil
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
	return git_model.UpdateProtectBranch(ctx, repo, rule, opts)
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
	return git_model.DeleteProtectedBranch(ctx, repo, ruleID)
}

func UpdateProtectBranchPriorities(ctx context.Context, repo *repo_model.Repository, ids []int64) error {
	if err := authz_service.RequireExecutionTarget(ctx, repo, authz.ManageBranchProtection, authz_service.SettingsIntent(authz.ManageBranchProtection, "priority")); err != nil {
		return err
	}
	return git_model.UpdateProtectBranchPriorities(ctx, repo, ids)
}
