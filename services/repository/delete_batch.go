// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"

	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func PrepareOrganizationRepositoryDeletion(ctx context.Context, actor *user_model.User, ownerID int64, repoIDs []int64) (context.Context, *authz_service.Admission, error) {
	executionCtx, admission, err := authz_service.BeginPreparedExecution(ctx, func(ctx context.Context) ([]authz_service.ExecutionInput, error) {
		owner, err := user_model.GetUserByID(ctx, ownerID)
		if err != nil {
			return nil, err
		}
		if !owner.IsOrganization() {
			return nil, &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
		}
		inputs := make([]authz_service.ExecutionInput, 0, len(repoIDs))
		for _, id := range repoIDs {
			repo, err := repo_model.GetRepositoryByID(ctx, id)
			if err != nil {
				return nil, err
			}
			actor, err = refreshLifecycleTarget(ctx, actor, repo)
			if err != nil {
				return nil, err
			}
			if repo.OwnerID != ownerID {
				return nil, &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
			}
			if err := checkLifecycleDangerZone(ctx, actor, repo); err != nil {
				return nil, &authz_service.ExecutionError{Reason: "native_visibility_denied", Status: 403}
			}
			inputs = append(inputs, authz_service.ExecutionInput{EvaluateInput: authz_service.EvaluateInput{Actor: actor, Repo: repo, Action: authz.Delete, Credential: authz_service.RequestCredentialCeiling(ctx, actor), ConditionContext: authz.ConditionContext{Source: authz_service.ExecutionSource(ctx)}}, Intent: deleteIntent(id)})
		}
		return inputs, nil
	})
	if err == nil {
		err = admission.Start(executionCtx)
	}
	return executionCtx, admission, err
}
