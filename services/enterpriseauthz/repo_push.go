// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"

	audit_model "gitea.dev/models/audit"
	git_model "gitea.dev/models/git"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/services/audit"
)

func WithRepoPushObservation(ctx context.Context, actor *user_model.User, repoID int64, branch string) (context.Context, *Observation) {
	return withRepoBranchObservation(ctx, actor, repoID, branch, authz.PushBranch)
}

func WithRepoCreateBranchObservation(ctx context.Context, actor *user_model.User, repoID int64, branch string) (context.Context, *Observation) {
	return withRepoBranchObservation(ctx, actor, repoID, branch, authz.CreateBranch)
}

func withRepoBranchObservation(ctx context.Context, actor *user_model.User, repoID int64, branch string, action authz.Action) (context.Context, *Observation) {
	if !setting.EnterpriseAuthz.Enabled || actor == nil {
		return ctx, nil
	}
	source := "system"
	credential := RequestCredentialCeiling(ctx, actor)
	switch audit.OriginFromContext(ctx) {
	case audit_model.OriginAPI:
		source = "api"
	case audit_model.OriginUI:
		source = "web"
	}
	if bound, ok := ctx.Value(boundObservationKey{}).(boundObservation); ok && bound.actorID == actor.ID && bound.repoID == repoID {
		if (bound.action == action || action == authz.PushBranch && bound.action == authz.PushProtectedBranch) && bound.branchKnown && bound.branch == branch {
			return ctx, bound.observation
		}
		source, credential = bound.source, bound.credential
	}
	input := EvaluateInput{Actor: actor, Repo: &repo_model.Repository{ID: repoID}, Credential: credential, Action: action, ConditionContext: authz.ConditionContext{Source: source, Branch: branch, BranchKnown: true}}
	return WithPreparedObservationContext(ctx, input, func(ctx context.Context, input EvaluateInput) (EvaluateInput, error) {
		repo, err := repo_model.GetRepositoryByID(ctx, repoID)
		if err != nil {
			return input, err
		}
		input.Repo = repo
		permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
		if err != nil {
			return input, err
		}
		input.Permission = &permission
		protected, err := git_model.GetFirstMatchProtectedBranchRule(ctx, repoID, branch)
		if err != nil {
			return input, err
		}
		if protected != nil && action == authz.PushBranch {
			input.Action = authz.PushProtectedBranch
		}
		return input, nil
	})
}
