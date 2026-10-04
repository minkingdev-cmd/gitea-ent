// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"time"

	"gitea.dev/models/db"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	"gitea.dev/services/audit"
	authz_service "gitea.dev/services/enterpriseauthz"
)

type accessExecutionKey struct{}

type accessExecutionState struct {
	orgID, actorID   int64
	intent, identity string
	owners           map[int64]int64
}

func accessIdentity(ctx context.Context, orgID int64) (string, error) {
	actor := audit.DoerFromContext(ctx)
	if actor == nil || actor.ID <= 0 {
		return "", accessRejection("invalid_execution_context", http.StatusForbidden)
	}
	ceiling := authz_service.RequestCredentialCeiling(ctx, actor)
	var err error
	if orgID > 0 {
		ceiling, err = authz_service.OrganizationAccessCredentialCeiling(ctx, actor, orgID)
		if err != nil {
			return "", err
		}
	}
	return accessIntent("identity", struct {
		ActorID, OrgID int64
		Source         string
		Credential     authz_service.CredentialCeiling
	}{actor.ID, orgID, authz_service.ExecutionSource(ctx), ceiling}), nil
}

func requireAccessMutation(ctx context.Context, orgID int64, intent string, repos []*repo_model.Repository) error {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return nil
	}
	state, ok := ctx.Value(accessExecutionKey{}).(accessExecutionState)
	if !ok || state.orgID != orgID || state.intent != intent {
		return accessRejection("invalid_execution_context", http.StatusForbidden)
	}
	identity, err := accessIdentity(ctx, orgID)
	if err != nil {
		return err
	}
	if identity != state.identity {
		return accessRejection("invalid_execution_context", http.StatusForbidden)
	}
	actor := audit.DoerFromContext(ctx)
	ceiling := authz_service.RequestCredentialCeiling(ctx, actor)
	if orgID > 0 {
		ceiling, err = authz_service.OrganizationAccessCredentialCeiling(ctx, actor, orgID)
		if err != nil {
			return err
		}
	}
	for _, expected := range repos {
		current, err := repo_model.GetRepositoryByID(ctx, expected.ID)
		if err != nil {
			return accessRejection("policy_read_failed", http.StatusServiceUnavailable)
		}
		if owner, found := state.owners[current.ID]; !found || owner != current.OwnerID || current.OwnerID != expected.OwnerID {
			return accessRejection("invalid_execution_context", http.StatusForbidden)
		}
		if err := authz_service.RequireExecutionInput(ctx, authz_service.ExecutionInput{EvaluateInput: authz_service.EvaluateInput{Actor: actor, Repo: current, Action: authz.ManageAccess, Credential: ceiling, ConditionContext: authz.ConditionContext{Source: authz_service.ExecutionSource(ctx)}}, Intent: intent}); err != nil {
			return err
		}
	}
	return nil
}

func accessIntent(kind string, target any) string {
	data, _ := json.Marshal(target)
	return fmt.Sprintf("access:%s:%x", kind, sha256.Sum256(data))
}

func accessRejection(reason string, status int) error {
	return &authz_service.ExecutionError{Reason: reason, Status: status}
}

func beginAccessMutation(ctx context.Context, orgID int64, intent string, repos func(context.Context) ([]*repo_model.Repository, error), teamChange bool) (context.Context, func(error), error) {
	noop := func(error) {}
	if !setting.EnterpriseAuthz.Enabled {
		return ctx, noop, nil
	}
	if !setting.EnterpriseAuthz.Enforce {
		return beginAccessObservation(ctx, orgID, repos)
	}
	if _, exists := ctx.Value(accessExecutionKey{}).(accessExecutionState); exists {
		selected, err := repos(ctx)
		if err != nil {
			return ctx, noop, accessRejection("policy_read_failed", http.StatusServiceUnavailable)
		}
		return ctx, noop, requireAccessMutation(ctx, orgID, intent, selected)
	}
	actor := audit.DoerFromContext(ctx)
	if actor == nil || actor.ID <= 0 {
		return ctx, noop, accessRejection("invalid_execution_context", http.StatusForbidden)
	}
	if db.InTransaction(ctx) {
		return ctx, noop, accessRejection("invalid_execution_context", http.StatusForbidden)
	}
	state := accessExecutionState{orgID: orgID, actorID: actor.ID, intent: intent, owners: make(map[int64]int64)}
	var prepareErr error
	executionCtx, admission, err := authz_service.BeginPreparedExecution(ctx, func(bounded context.Context) (inputs []authz_service.ExecutionInput, err error) {
		defer func() {
			if err != nil && bounded.Err() != nil {
				if ctx.Err() != nil {
					err = accessRejection("execution_canceled", http.StatusForbidden)
				} else {
					err = accessRejection("execution_timeout", http.StatusServiceUnavailable)
				}
			}
			prepareErr = err
		}()
		selected, err := repos(bounded)
		if err != nil {
			return nil, err
		}
		if len(selected) > 1000 {
			return nil, accessRejection("context_limit_exceeded", http.StatusForbidden)
		}
		currentActor, err := user_model.GetUserByID(bounded, actor.ID)
		if err != nil {
			return nil, err
		}
		currentActor.ExtDoerData = actor.ExtDoerData
		if currentActor.IsAdmin {
			currentActor.IsAdmin, err = access_model.HasSystemManagementAuthority(bounded, currentActor)
			if err != nil {
				return nil, err
			}
		}
		if !currentActor.IsActive || currentActor.ProhibitLogin {
			return nil, accessRejection("actor_inactive", http.StatusForbidden)
		}
		ceiling := authz_service.RequestCredentialCeiling(bounded, actor)
		if orgID > 0 {
			ceiling, err = authz_service.OrganizationAccessCredentialCeiling(bounded, actor, orgID)
			if err != nil {
				return nil, err
			}
		}
		state.identity, err = accessIdentity(bounded, orgID)
		if err != nil {
			return nil, err
		}
		for _, expected := range selected {
			repo, err := repo_model.GetRepositoryByID(bounded, expected.ID)
			if err != nil {
				return nil, err
			}
			if repo.OwnerID != expected.OwnerID || orgID > 0 && repo.OwnerID != orgID {
				return nil, accessRejection("invalid_execution_context", http.StatusForbidden)
			}
			if err = repo.LoadOwner(bounded); err != nil {
				return nil, err
			}
			permission, err := access_model.GetDoerRepoPermission(bounded, repo, currentActor)
			if err != nil {
				return nil, err
			}
			if !permission.IsAdmin() || teamChange && !access_model.CanDoerManageOrgRepoCollaboratorTeam(bounded, repo, &permission) {
				return nil, accessRejection("native_visibility_denied", http.StatusForbidden)
			}
			if err = CheckEnterpriseRepoAuthorizationChange(bounded, currentActor, repo); err != nil {
				return nil, accessRejection("native_visibility_denied", http.StatusForbidden)
			}
			state.owners[repo.ID] = repo.OwnerID
			inputs = append(inputs, authz_service.ExecutionInput{EvaluateInput: authz_service.EvaluateInput{Actor: actor, Repo: repo, Action: authz.ManageAccess, Credential: ceiling, ConditionContext: authz.ConditionContext{Source: authz_service.ExecutionSource(ctx)}}, Intent: intent})
		}
		return inputs, nil
	})
	if prepareErr != nil {
		if rejection, ok := prepareErr.(*authz_service.ExecutionError); ok {
			return ctx, noop, rejection
		}
		return ctx, noop, accessRejection("policy_read_failed", http.StatusServiceUnavailable)
	}
	if err == nil {
		err = admission.Start(executionCtx)
	}
	if err != nil {
		return ctx, noop, err
	}
	executionCtx = context.WithValue(executionCtx, accessExecutionKey{}, state)
	return executionCtx, func(err error) {
		outcome := authz_service.NativeSuccess
		if err != nil {
			outcome = authz_service.NativeFailed
		}
		admission.Finish(executionCtx, outcome, authz_service.StageOperation)
	}, nil
}

func beginCollaborationMutation(ctx context.Context, repo *repo_model.Repository, userID int64, mode int, remove bool) (context.Context, func(error), error) {
	intent := collaborationIntent(repo.ID, userID, mode, remove)
	return beginAccessMutation(ctx, 0, intent, func(context.Context) ([]*repo_model.Repository, error) { return []*repo_model.Repository{repo}, nil }, false)
}

func collaborationIntent(repoID, userID int64, mode int, remove bool) string {
	return accessIntent("collaborator", struct {
		RepoID, UserID int64
		Mode           int
		Remove         bool
	}{repoID, userID, mode, remove})
}

func beginAccessObservation(ctx context.Context, orgID int64, selectRepos func(context.Context) ([]*repo_model.Repository, error)) (context.Context, func(error), error) {
	ctx = authz_service.WithOperation(ctx)
	started := time.Now()
	bounded, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	repos, err := selectRepos(bounded)
	if err != nil {
		return ctx, func(error) {}, nil
	}
	actor := audit.DoerFromContext(ctx)
	ceiling := authz_service.RequestCredentialCeiling(ctx, actor)
	if orgID > 0 {
		ceiling, err = authz_service.OrganizationAccessCredentialCeiling(bounded, actor, orgID)
		if err != nil {
			return ctx, func(error) {}, nil
		}
	}
	observations := make([]*authz_service.Observation, 0, min(len(repos), 1000))
	for _, repo := range repos[:min(len(repos), 1000)] {
		if bounded.Err() != nil {
			break
		}
		input := authz_service.EvaluateInput{Actor: actor, Repo: repo, Action: authz.ManageAccess, Credential: ceiling, ConditionContext: authz.ConditionContext{Source: authz_service.ExecutionSource(ctx)}}
		_, observation := authz_service.BeginPreparedObservation(bounded, input, func(ctx context.Context, input authz_service.EvaluateInput) (authz_service.EvaluateInput, error) {
			permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
			input.Permission = &permission
			return input, err
		})
		observations = append(observations, observation)
	}
	remaining := max(0, 200*time.Millisecond-time.Since(started))
	return ctx, func(err error) {
		finishCtx, cancel := context.WithTimeout(ctx, remaining)
		defer cancel()
		outcome := authz_service.NativeSuccess
		if err != nil {
			outcome = authz_service.NativeFailed
		}
		for _, observation := range observations {
			observation.Finish(finishCtx, outcome, authz_service.StageOperation)
		}
	}, nil
}
