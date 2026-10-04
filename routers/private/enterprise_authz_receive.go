// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package private

import (
	"context"
	"errors"
	"net/http"

	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/private"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	gitea_context "gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func receiveExecutionInputs(ctx *gitea_context.PrivateContext, operation *authz_service.HookOperation, opts *private.HookOptions) []authz_service.GitExecutionInput {
	source := "system"
	ceiling := authz_service.CredentialCeiling{}
	if operation != nil {
		source, ceiling = operation.Source(), operation.Credential()
	}
	inputs := make([]authz_service.GitExecutionInput, 0, len(opts.RefFullNames))
	for i, ref := range opts.RefFullNames {
		if ref.IsBranch() {
			inputs = append(inputs, authz_service.GitExecutionInput{Actor: ctx.Doer, Repo: ctx.Repo.Repository, Credential: ceiling, Source: source, Ref: ref, OldCommitID: opts.OldCommitIDs[i], NewCommitID: opts.NewCommitIDs[i], GitRepo: ctx.Repo.GitRepo, Env: generateGitEnv(opts), NativeGuard: func(snapshot context.Context, actor *user_model.User, repo *repo_model.Repository) error {
				invalid := &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
				failure := &authz_service.ExecutionError{Reason: "policy_read_failed", Status: http.StatusServiceUnavailable}
				current, err := repo_model.GetRepositoryByID(snapshot, repo.ID)
				if repo_model.IsErrRepoNotExist(err) {
					return invalid
				}
				if err != nil {
					return failure
				}
				if current.OwnerID != repo.OwnerID {
					return invalid
				}
				if actor.IsAdmin {
					trusted, err := access_model.HasSystemManagementAuthority(snapshot, actor)
					if err != nil {
						return failure
					}
					actor.IsAdmin = trusted
				}
				permission, err := access_model.GetDoerRepoPermission(snapshot, current, actor)
				if err != nil {
					return failure
				}
				fresh := *ctx
				fresh.Doer = actor
				fresh.Repo = &gitea_context.Repository{Repository: current, GitRepo: ctx.Repo.GitRepo, Permission: permission}
				check := &preReceiveContext{PrivateContext: &fresh, env: generateGitEnv(opts), opts: opts, policyContext: snapshot}
				if err := checkPreReceiveBranch(check, opts.OldCommitIDs[i], opts.NewCommitIDs[i], ref); err != nil {
					if err.status == http.StatusInternalServerError {
						return failure
					}
					return &authz_service.ExecutionError{Reason: "native_visibility_denied", Status: http.StatusForbidden}
				}
				return nil
			}})
		}
	}
	return inputs
}

func admitReceiveBranches(operationCtx context.Context, ctx *gitea_context.PrivateContext, operation *authz_service.HookOperation, opts *private.HookOptions) bool {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce || opts.IsWiki {
		return true
	}
	inputs := receiveExecutionInputs(ctx, operation, opts)
	if len(inputs) == 0 || authz_service.ReuseActiveGitExecution(operationCtx, operation, inputs) {
		return true
	}
	executionCtx, admission, err := authz_service.BeginGitExecution(operationCtx, inputs)
	if err == nil {
		err = admission.Start(executionCtx)
	}
	if err != nil {
		if rejection, ok := errors.AsType[*authz_service.ExecutionError](err); ok {
			ctx.PrivateUserErrorf(rejection.Status, "%s", rejection.Reason)
		} else {
			ctx.PrivateUserErrorf(http.StatusServiceUnavailable, "authorization_unavailable")
		}
		return false
	}
	return true
}

func receiveOperation(ctx *gitea_context.PrivateContext, opts *private.HookOptions) (context.Context, *authz_service.HookOperation) {
	if !setting.EnterpriseAuthz.Enabled || opts.IsWiki {
		return ctx, nil
	}
	return authz_service.RestoreHookOperation(ctx, opts.AuthzOperation, ctx.Repo.Repository.ID, opts.UserID, opts.UserExtDoerData)
}

func observeReceiveBranch(operationCtx context.Context, ctx *gitea_context.PrivateContext, operation *authz_service.HookOperation, oldCommitID string, ref git.RefName) func() {
	if operation == nil || !ref.IsBranch() {
		return func() {}
	}
	branch := ref.BranchName()
	if operation.Owns(authz.MergePullRequest, branch) {
		return func() {}
	}
	input := authz_service.EvaluateInput{Actor: ctx.Doer, Repo: ctx.Repo.Repository, Permission: &ctx.Repo.Permission, Credential: operation.Credential(), Action: authz.PushBranch, ConditionContext: authz.ConditionContext{Source: operation.Source(), Branch: branch, BranchKnown: true}}
	created := git.IsEmptyCommitID(oldCommitID)
	operationCtx, observations := authz_service.BeginHookBranchObservations(operationCtx, operation, input, created)
	return func() {
		outcome := authz_service.NativeUnknown
		if status := ctx.WrittenStatus(); status == http.StatusForbidden || status == http.StatusUnauthorized {
			outcome = authz_service.NativeDenied
		} else if status >= 400 {
			outcome = authz_service.NativeFailed
		}
		for _, observation := range observations {
			observation.Finish(operationCtx, outcome, authz_service.StagePreReceive)
		}
	}
}

func finishReceiveBranches(ctx *gitea_context.PrivateContext, opts *private.HookOptions) {
	operationCtx, operation := receiveOperation(ctx, opts)
	if operation == nil {
		return
	}
	if setting.EnterpriseAuthz.Enforce && len(opts.RefFullNames) == len(opts.OldCommitIDs) && len(opts.RefFullNames) == len(opts.NewCommitIDs) {
		for _, input := range receiveExecutionInputs(ctx, operation, opts) {
			authz_service.CompleteGitExecution(operationCtx, operation, input)
		}
	}
	for _, ref := range opts.RefFullNames {
		if !ref.IsBranch() {
			continue
		}
		branch := ref.BranchName()
		if operation.Owns(authz.MergePullRequest, branch) {
			continue
		}
		for _, action := range []authz.Action{authz.CreateBranch, authz.PushBranch, authz.PushProtectedBranch, authz.ManageCodeowners} {
			authz_service.CompleteHookObservation(operationCtx, operation, action, branch, authz_service.NativeSuccess, authz_service.StageTransport)
		}
	}
}

func attachReceiveExecution(ctx *gitea_context.PrivateContext, opts *private.HookOptions) {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce || len(opts.RefFullNames) != len(opts.OldCommitIDs) || len(opts.RefFullNames) != len(opts.NewCommitIDs) {
		return
	}
	_, operation := receiveOperation(ctx, opts)
	attached, ok := authz_service.AttachActiveGitExecution(ctx.RequestContext, operation, receiveExecutionInputs(ctx, operation, opts))
	if ok {
		ctx.RequestContext = reqctx.FromContext(attached)
	}
}
