// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"net/http"

	issues_model "gitea.dev/models/issues"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitrepo"
	"gitea.dev/modules/setting"
	authz_service "gitea.dev/services/enterpriseauthz"
)

type MergeOptions struct {
	Force bool
}

type mergeExecution struct {
	ctx         context.Context
	admission   *authz_service.Admission
	nativeGuard func(context.Context, *user_model.User, *repo_model.Repository) error
}

func (execution *mergeExecution) finish(err error) {
	if execution == nil || execution.admission == nil {
		return
	}
	outcome := authz_service.NativeSuccess
	if err != nil {
		outcome = authz_service.NativeFailed
	}
	execution.admission.Finish(execution.ctx, outcome, authz_service.StageOperation)
}

func refreshPullMutation(ctx context.Context, pr *issues_model.PullRequest, doer *user_model.User) (*user_model.User, error) {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return doer, nil
	}
	if pr == nil || doer == nil || doer.ID <= 0 {
		return nil, &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	}
	actor, err := user_model.GetUserByID(ctx, doer.ID)
	if err != nil {
		return nil, err
	}
	actor.ExtDoerData = doer.ExtDoerData
	if !actor.IsActive || actor.ProhibitLogin {
		return nil, &authz_service.ExecutionError{Reason: "actor_inactive", Status: http.StatusForbidden}
	}
	if actor.IsAdmin {
		actor.IsAdmin, err = access_model.HasSystemManagementAuthority(ctx, actor)
		if err != nil {
			return nil, err
		}
	}
	if pr.ID > 0 {
		current, err := issues_model.GetPullRequestByID(ctx, pr.ID)
		if err != nil {
			return nil, err
		}
		*pr = *current
	}
	pr.BaseRepo, pr.HeadRepo = nil, nil
	if err := pr.LoadBaseRepo(ctx); err != nil {
		return nil, err
	}
	if err := pr.LoadHeadRepo(ctx); err != nil {
		return nil, err
	}
	return actor, nil
}

func checkMergeExecutionNative(ctx context.Context, pr *issues_model.PullRequest, doer *user_model.User, style repo_model.MergeStyle, checkType MergeCheckType, force bool) error {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return nil
	}
	permission, err := access_model.GetDoerRepoPermission(ctx, pr.BaseRepo, doer)
	if err != nil {
		return err
	}
	prUnit, err := pr.BaseRepo.GetUnit(ctx, unit.TypePullRequests)
	if err != nil {
		return err
	}
	if !prUnit.PullRequestsConfig().IsMergeStyleAllowed(style) {
		return ErrInvalidMergeStyle{ID: pr.BaseRepo.ID, Style: style}
	}
	return CheckPullMergeable(ctx, doer, &permission, pr, checkType, style, force)
}

func checkManualMergeExecutionNative(ctx context.Context, pr *issues_model.PullRequest, actor *user_model.User, automatic bool) error {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return nil
	}
	if !automatic {
		return checkMergeExecutionNative(ctx, pr, actor, repo_model.MergeStyleManuallyMerged, MergeCheckTypeManually, false)
	}
	prUnit, err := pr.BaseRepo.GetUnit(ctx, unit.TypePullRequests)
	if err != nil {
		return err
	}
	if !prUnit.PullRequestsConfig().AutodetectManualMerge {
		return ErrInvalidMergeStyle{ID: pr.BaseRepoID, Style: repo_model.MergeStyleManuallyMerged}
	}
	permission, err := access_model.GetDoerRepoPermission(ctx, pr.BaseRepo, actor)
	if err != nil {
		return err
	}
	return CheckPullMergeable(ctx, actor, &permission, pr, MergeCheckTypeManually, repo_model.MergeStyleManuallyMerged, false)
}

func checkUpdateExecutionNative(ctx context.Context, pr *issues_model.PullRequest, actor *user_model.User, rebase bool) error {
	permission, err := access_model.GetDoerRepoPermission(ctx, pr.BaseRepo, actor)
	if err != nil {
		return err
	}
	if !permission.CanRead(unit.TypeCode) {
		return &authz_service.ExecutionError{Reason: "native_visibility_denied", Status: http.StatusForbidden}
	}
	qualification, err := CheckUserAllowedToUpdate(ctx, pr, actor)
	if err != nil {
		return err
	}
	if rebase && !qualification.RebaseAllowed || !rebase && !qualification.MergeAllowed {
		return &authz_service.ExecutionError{Reason: "native_visibility_denied", Status: http.StatusForbidden}
	}
	return nil
}

func beginPullGitExecution(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, gitRepo gitrepo.RepositoryFacade, branch, oldCommit, newCommit string, merge, push bool, execution *mergeExecution) (context.Context, authz.HookOperationTicket, func(), error) {
	noop := func() {}
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return ctx, "", noop, nil
	}
	source, ceiling := authz_service.ExecutionAttributionForActor(ctx, doer, repo.ID)
	inputs := []authz_service.GitExecutionInput{{Actor: doer, Repo: repo, Credential: ceiling, Source: source, Ref: git.RefNameFromBranch(branch), OldCommitID: oldCommit, NewCommitID: newCommit, GitRepo: gitRepo, Merge: merge, NativeGuard: execution.nativeGuard}}
	executionCtx, admission, err := authz_service.BeginGitExecution(authz_service.ExecutionParentContext(ctx), inputs)
	if err == nil {
		err = admission.Start(executionCtx)
	}
	if err != nil {
		return ctx, "", noop, err
	}
	execution.ctx, execution.admission = executionCtx, admission
	ctx = authz_service.DetachedObservationContext(ctx, executionCtx)
	if !push {
		return executionCtx, "", noop, nil
	}
	release := noop
	if admission != nil {
		release, err = authz_service.RegisterGitExecution(executionCtx, admission, inputs)
		if err != nil {
			return ctx, "", noop, err
		}
	}
	parent := authz.PushBranch
	owned := []authz_service.HookOwnedObservation{{Action: authz.PushBranch, Branch: branch}, {Action: authz.PushProtectedBranch, Branch: branch}}
	if merge {
		parent = authz.MergePullRequest
		owned = []authz_service.HookOwnedObservation{{Action: parent, Branch: branch}}
	}
	ticket := authz_service.NewHookOperationTicket(executionCtx, authz_service.EvaluateInput{Actor: doer, Repo: repo, Credential: ceiling, Action: parent, ConditionContext: authz.ConditionContext{Source: source, Branch: branch, BranchKnown: true}}, owned)
	return ctx, ticket, release, nil
}
