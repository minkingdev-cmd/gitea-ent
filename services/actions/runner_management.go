// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package actions

import (
	"context"
	"strconv"

	actions_model "gitea.dev/models/actions"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func requireRunnerExecution(ctx context.Context, repoID, runnerID int64) error {
	if repoID == 0 {
		return nil
	}
	return authz_service.RequireSettingsExecution(ctx, repoID, authz.ManageCI, authz_service.SettingsIntent(authz.ManageCI, "runner:"+strconv.FormatInt(runnerID, 10)))
}

func NewRunnerToken(ctx context.Context, ownerID, repoID int64) (*actions_model.ActionRunnerToken, error) {
	if err := requireRunnerExecution(ctx, repoID, 0); err != nil {
		return nil, err
	}
	return actions_model.NewRunnerToken(ctx, ownerID, repoID)
}

func requireRunnerObjectExecution(ctx context.Context, runner *actions_model.ActionRunner) error {
	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
		current, err := actions_model.GetRunnerByID(ctx, runner.ID)
		if err != nil {
			return err
		}
		if current.RepoID != runner.RepoID || current.OwnerID != runner.OwnerID {
			return &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
		}
	}
	return requireRunnerExecution(ctx, runner.RepoID, runner.ID)
}

func UpdateRunner(ctx context.Context, runner *actions_model.ActionRunner, cols ...string) error {
	if err := requireRunnerObjectExecution(ctx, runner); err != nil {
		return err
	}
	return actions_model.UpdateRunner(ctx, runner, cols...)
}

func DeleteRunner(ctx context.Context, runnerID int64) error {
	runner, err := actions_model.GetRunnerByID(ctx, runnerID)
	if err != nil {
		return err
	}
	if err := requireRunnerExecution(ctx, runner.RepoID, runner.ID); err != nil {
		return err
	}
	return actions_model.DeleteRunner(ctx, runnerID)
}

func SetRunnerDisabled(ctx context.Context, runner *actions_model.ActionRunner, disabled bool) error {
	if err := requireRunnerObjectExecution(ctx, runner); err != nil {
		return err
	}
	return actions_model.SetRunnerDisabled(ctx, runner, disabled)
}
