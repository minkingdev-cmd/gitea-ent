// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package private

import (
	"context"
	"net/http"

	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/private"
	"gitea.dev/modules/setting"
	gitea_context "gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
)

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
