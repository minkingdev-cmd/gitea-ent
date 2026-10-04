// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package automerge

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"

	issues_model "gitea.dev/models/issues"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	authz_service "gitea.dev/services/enterpriseauthz"
	pull_service "gitea.dev/services/pull"
)

type ScheduleOptions struct {
	ReplaceExisting bool
}

func autoMergeBranchCleanupContext(ctx context.Context, actor *user_model.User, headRepoID int64, headBranch string) (context.Context, *authz_service.Observation, error) {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return ctx, nil, nil
	}
	repo, err := repo_model.GetRepositoryByID(ctx, headRepoID)
	if err != nil {
		return ctx, nil, err
	}
	permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
	if err != nil {
		return ctx, nil, err
	}
	ctx, observation := authz_service.WithObservationContext(ctx, authz_service.EvaluateInput{
		Actor: actor, Repo: repo, Permission: &permission, Action: authz.PushBranch,
		Credential:       authz_service.CredentialCeiling{Read: true, Write: true},
		ConditionContext: authz.ConditionContext{Source: "auto_merge", Branch: headBranch, BranchKnown: true},
	})
	return ctx, observation, nil
}

func beginAutoMergeSchedule(ctx context.Context, actor *user_model.User, pr *issues_model.PullRequest, style repo_model.MergeStyle, message string, deleteBranch bool) (context.Context, *authz_service.Admission, *user_model.User, error) {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return ctx, nil, actor, nil
	}
	invalid := &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	if actor == nil || pr == nil || actor.ID <= 0 || pr.ID <= 0 {
		return ctx, nil, actor, invalid
	}
	current, err := user_model.GetUserByID(ctx, actor.ID)
	if err != nil {
		return ctx, nil, actor, err
	}
	current.ExtDoerData = actor.ExtDoerData
	if !current.IsActive || current.ProhibitLogin {
		return ctx, nil, current, &authz_service.ExecutionError{Reason: "actor_inactive", Status: http.StatusForbidden}
	}
	if current.IsAdmin {
		current.IsAdmin, err = access_model.HasSystemManagementAuthority(ctx, current)
		if err != nil {
			return ctx, nil, current, err
		}
	}
	stored, err := issues_model.GetPullRequestByID(ctx, pr.ID)
	if err != nil {
		return ctx, nil, current, err
	}
	*pr = *stored
	if err := pr.LoadBaseRepo(ctx); err != nil {
		return ctx, nil, current, err
	}
	prUnit, err := pr.BaseRepo.GetUnit(ctx, unit.TypePullRequests)
	if err != nil {
		return ctx, nil, current, err
	}
	if !prUnit.PullRequestsConfig().IsMergeStyleAllowed(style) {
		return ctx, nil, current, pull_service.ErrInvalidMergeStyle{ID: pr.BaseRepo.ID, Style: style}
	}
	permission, err := access_model.GetDoerRepoPermission(ctx, pr.BaseRepo, current)
	if err != nil {
		return ctx, nil, current, err
	}
	if err := pull_service.CheckPullMergeable(ctx, current, &permission, pr, pull_service.MergeCheckTypeAuto, style, false); err != nil {
		return ctx, nil, current, err
	}
	source, ceiling := authz_service.ExecutionAttributionForActor(ctx, current, pr.BaseRepoID)
	intent := fmt.Sprintf("auto-merge-schedule:%d:%s:%t:%x", pr.ID, style, deleteBranch, sha256.Sum256([]byte(message)))
	executionCtx, admission, err := authz_service.BeginExecution(ctx, []authz_service.ExecutionInput{{EvaluateInput: authz_service.EvaluateInput{Actor: current, Repo: pr.BaseRepo, Credential: ceiling, Action: authz.MergePullRequest, ConditionContext: authz.ConditionContext{Source: source, Branch: pr.BaseBranch, BranchKnown: true}}, Intent: intent}})
	if err == nil {
		err = admission.Start(executionCtx)
	}
	return executionCtx, admission, current, err
}
