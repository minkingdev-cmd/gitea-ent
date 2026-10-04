// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package files

import (
	"context"
	"errors"
	"slices"

	audit_model "gitea.dev/models/audit"
	git_model "gitea.dev/models/git"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	"gitea.dev/services/audit"
	authz_service "gitea.dev/services/enterpriseauthz"
	issue_service "gitea.dev/services/issue"
)

type fileMutationKey struct{}

type fileMutationResult struct {
	actorID, repoID int64
	branch          string
	pushed          bool
	ticket          authz.HookOperationTicket
}

func observeFileMutation(ctx context.Context, repo *repo_model.Repository, actor *user_model.User, oldBranch, newBranch string, paths []string, complete bool, stages ...authz_service.NativeStage) (context.Context, func(error)) {
	if !setting.EnterpriseAuthz.Enabled {
		return ctx, func(error) {}
	}
	oldBranch = util.IfZero(oldBranch, repo.DefaultBranch)
	newBranch = util.IfZero(newBranch, oldBranch)
	source := "file_editor"
	if audit.OriginFromContext(ctx) == audit_model.OriginAPI {
		source = "api"
	}
	paths = slices.Clone(paths)
	complete = complete && len(paths) > 0 && len(paths) <= authz.MaxContextPaths
	if !complete {
		paths = nil
	}
	input := authz_service.EvaluateInput{Actor: actor, Repo: repo, Credential: authz_service.RequestCredentialCeiling(ctx, actor), Action: authz.PushBranch, ConditionContext: authz.ConditionContext{Source: source, Branch: newBranch, BranchKnown: newBranch != "", Paths: paths, PathsComplete: complete}}
	createsBranch := false
	operationCtx, observation := authz_service.BeginPreparedObservation(ctx, input, func(ctx context.Context, input authz_service.EvaluateInput) (authz_service.EvaluateInput, error) {
		permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
		if err != nil {
			return input, err
		}
		input.Permission = &permission
		protected, err := git_model.GetFirstMatchProtectedBranchRule(ctx, repo.ID, newBranch)
		if err != nil {
			return input, err
		}
		if protected != nil {
			input.Action = authz.PushProtectedBranch
		}
		if oldBranch != newBranch || repo.IsEmpty {
			exists, err := git_model.IsBranchExist(ctx, repo.ID, newBranch)
			if err != nil {
				return input, err
			}
			createsBranch = !exists
		}
		return input, nil
	})
	observations := []*authz_service.Observation{observation}
	if observation != nil {
		if createsBranch {
			input.Action = authz.CreateBranch
			_, created := authz_service.BeginResolvedObservation(operationCtx, input, func(ctx context.Context) (*access_model.Permission, error) {
				permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
				return &permission, err
			})
			observations = append(observations, created)
		}
		if complete && slices.ContainsFunc(paths, issue_service.IsCodeOwnerFile) {
			input.Action = authz.ManageCodeowners
			_, codeowners := authz_service.BeginResolvedObservation(operationCtx, input, func(ctx context.Context) (*access_model.Permission, error) {
				permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
				return &permission, err
			})
			observations = append(observations, codeowners)
		}
	}
	owned := []authz_service.HookOwnedObservation{{Action: authz.PushBranch, Branch: newBranch}, {Action: authz.PushProtectedBranch, Branch: newBranch}}
	if oldBranch != newBranch || repo.IsEmpty {
		owned = append(owned, authz_service.HookOwnedObservation{Action: authz.CreateBranch, Branch: newBranch})
	}
	if complete && slices.ContainsFunc(paths, issue_service.IsCodeOwnerFile) {
		owned = append(owned, authz_service.HookOwnedObservation{Action: authz.ManageCodeowners, Branch: newBranch})
	}
	result := &fileMutationResult{actorID: actor.ID, repoID: repo.ID, branch: newBranch}
	result.ticket = authz_service.NewHookOperationTicket(operationCtx, input, owned)
	if store := reqctx.FromContext(operationCtx); store != nil {
		store.SetContextValue(fileMutationKey{}, result)
	} else {
		operationCtx = context.WithValue(operationCtx, fileMutationKey{}, result)
	}
	return operationCtx, func(err error) {
		outcome := authz_service.NativeFailed
		if result.pushed {
			outcome = authz_service.NativeSuccess
		} else if errors.Is(err, util.ErrPermissionDenied) || git.IsErrPushRejected(err) {
			outcome = authz_service.NativeDenied
		}
		stage := authz_service.StageOperation
		if len(stages) > 0 {
			stage = stages[0]
		}
		for _, observation := range observations {
			observation.Finish(operationCtx, outcome, stage)
		}
	}
}

func markFileMutationPushed(ctx context.Context, repoID, actorID int64, branch string) {
	if !setting.EnterpriseAuthz.Enabled {
		return
	}
	result, ok := ctx.Value(fileMutationKey{}).(*fileMutationResult)
	if ok && result.repoID == repoID && result.actorID == actorID && result.branch == branch {
		result.pushed = true
	}
}

func fileMutationPaths(files []*ChangeRepoFile) ([]string, bool) {
	var paths []string
	complete := len(files) > 0
	for _, file := range files {
		if file == nil || file.DeleteRecursively {
			complete = false
			continue
		}
		paths = append(paths, CleanGitTreePath(file.TreePath))
		if file.FromTreePath != "" {
			paths = append(paths, CleanGitTreePath(file.FromTreePath))
		}
	}
	return paths, complete
}

func ObserveFileMutationRejection(ctx context.Context, repo *repo_model.Repository, actor *user_model.User, oldBranch, newBranch string, outcome authz_service.NativeOutcome) {
	if !setting.EnterpriseAuthz.Enabled {
		return
	}
	stage := authz_service.StageOperation
	err := errors.New("native_file_validation_failed")
	if outcome == authz_service.NativeDenied {
		stage = authz_service.StageAuthorization
		err = util.ErrPermissionDenied
	}
	_, finish := observeFileMutation(ctx, repo, actor, oldBranch, newBranch, nil, false, stage)
	finish(err)
}

func fileMutationTicket(ctx context.Context, repoID, actorID int64, branch string) authz.HookOperationTicket {
	result, ok := ctx.Value(fileMutationKey{}).(*fileMutationResult)
	if ok && result.repoID == repoID && result.actorID == actorID && result.branch == branch {
		return result.ticket
	}
	return ""
}
