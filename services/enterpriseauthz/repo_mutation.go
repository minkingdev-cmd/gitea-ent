// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"

	audit_model "gitea.dev/models/audit"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/services/audit"
)

func WithRepoMutationObservation(ctx context.Context, actor *user_model.User, repo *repo_model.Repository, action authz.Action) (context.Context, *Observation) {
	return withRepoMutationObservation(ctx, actor, repo, action, 0)
}

func WithRepoTransferObservation(ctx context.Context, actor *user_model.User, repo *repo_model.Repository, targetOwnerID int64) (context.Context, *Observation) {
	return withRepoMutationObservation(ctx, actor, repo, authz.Transfer, targetOwnerID)
}

func withRepoMutationObservation(ctx context.Context, actor *user_model.User, repo *repo_model.Repository, action authz.Action, targetOwnerID int64) (context.Context, *Observation) {
	if !setting.EnterpriseAuthz.Enabled || repo == nil {
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
	input := EvaluateInput{Actor: actor, Repo: repo, Credential: credential, Action: action, TargetOwnerID: targetOwnerID, ConditionContext: authz.ConditionContext{Source: source}}
	if bound, ok := ctx.Value(boundObservationKey{}).(boundObservation); ok && bound.actorID == actorID(input) && bound.repoID == repo.ID {
		if bound.action == action {
			return ctx, bound.observation
		}
		input.ConditionContext.Source, input.Credential = bound.source, bound.credential
	}
	return WithPreparedObservationContext(ctx, input, func(ctx context.Context, input EvaluateInput) (EvaluateInput, error) {
		permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
		input.Permission = &permission
		return input, err
	})
}
