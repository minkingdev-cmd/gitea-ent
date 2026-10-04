// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"
	"fmt"
	"net/http"

	audit_model "gitea.dev/models/audit"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/services/audit"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func refreshLifecycleTarget(ctx context.Context, actor *user_model.User, repo *repo_model.Repository) (*user_model.User, error) {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return actor, nil
	}
	if actor == nil || repo == nil {
		return nil, &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	}
	currentActor, err := user_model.GetUserByID(ctx, actor.ID)
	if err != nil {
		return nil, err
	}
	currentActor.ExtDoerData = actor.ExtDoerData
	if currentActor.IsAdmin {
		currentActor.IsAdmin, err = access_model.HasSystemManagementAuthority(ctx, currentActor)
		if err != nil {
			return nil, err
		}
	}
	currentRepo, err := repo_model.GetRepositoryByID(ctx, repo.ID)
	if err != nil {
		return nil, err
	}
	if err = currentRepo.LoadOwner(ctx); err != nil {
		return nil, err
	}
	*repo = *currentRepo
	return currentActor, nil
}

func checkLifecycleDangerZone(ctx context.Context, actor *user_model.User, repo *repo_model.Repository) error {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return nil
	}
	permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
	if err != nil {
		return err
	}
	if !access_model.CanDoerManageRepoDangerZone(ctx, actor, repo, &permission) {
		return &authz_service.ExecutionError{Reason: "native_visibility_denied", Status: http.StatusForbidden}
	}
	return nil
}

func beginLifecycleExecution(ctx context.Context, actor *user_model.User, repo *repo_model.Repository, action authz.Action, intent string, targetOwnerID int64) (context.Context, *authz_service.Admission, error) {
	input := authz_service.ExecutionInput{EvaluateInput: authz_service.EvaluateInput{
		Actor: actor, Repo: repo, Action: action, TargetOwnerID: targetOwnerID, Credential: authz_service.RequestCredentialCeiling(ctx, actor), ConditionContext: authz.ConditionContext{Source: authz_service.ExecutionSource(ctx)},
	}, Intent: intent}
	if authz_service.HasExecution(ctx) {
		return ctx, nil, authz_service.RequireExecutionInput(ctx, input)
	}
	executionCtx, admission, err := authz_service.BeginExecution(ctx, []authz_service.ExecutionInput{input})
	if err == nil {
		err = admission.Start(executionCtx)
	}
	return executionCtx, admission, err
}

func finishLifecycleExecution(ctx context.Context, admission *authz_service.Admission, err error) {
	outcome := authz_service.NativeSuccess
	if err != nil {
		outcome = authz_service.NativeFailed
	}
	admission.Finish(ctx, outcome, authz_service.StageOperation)
}

func deleteIntent(repoID int64) string { return fmt.Sprintf("delete:%d", repoID) }

func checkLifecycleArchiveNative(ctx context.Context, actor *user_model.User, repo *repo_model.Repository) error {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return nil
	}
	if audit.OriginFromContext(ctx) != audit_model.OriginAPI {
		return checkLifecycleDangerZone(ctx, actor, repo)
	}
	permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
	if err != nil {
		return err
	}
	if !permission.IsAdmin() {
		return &authz_service.ExecutionError{Reason: "native_visibility_denied", Status: http.StatusForbidden}
	}
	return nil
}
