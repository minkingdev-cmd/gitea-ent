// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"

	repo_model "gitea.dev/models/repo"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
)

func SettingsIntent(action authz.Action, target string) string {
	if action == authz.ManageSecret {
		target = strings.ToUpper(target)
	}
	return fmt.Sprintf("settings:%s:%x", action, sha256.Sum256([]byte(target)))
}

func RequireSettingsExecution(ctx context.Context, repoID int64, action authz.Action, intent string) error {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return nil
	}
	repo, err := repo_model.GetRepositoryByID(ctx, repoID)
	if err != nil {
		if repo_model.IsErrRepoNotExist(err) {
			return &ExecutionError{Reason: "invalid_execution_context", Status: 403}
		}
		return &ExecutionError{Reason: "policy_read_failed", Status: 503}
	}
	return RequireExecutionTarget(ctx, repo, action, intent)
}
