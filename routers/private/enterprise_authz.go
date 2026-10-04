// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package private

import (
	"context"
	"strconv"

	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func observeSSHCloneAuthorization(ctx context.Context, repo *repo_model.Repository, actor *user_model.User, keyID int64) {
	if !setting.EnterpriseAuthz.Enabled {
		return
	}
	ceiling := authz_service.CredentialCeiling{Read: true, Write: true, Reference: "ssh-key:" + strconv.FormatInt(keyID, 10)}
	if actor.ExtDoerData != nil {
		ceiling.NativeOnly = true
		ceiling.Reference = actor.ExtDoerData.EncodeToString()
	}
	observationCtx, observation := authz_service.BeginResolvedObservation(ctx, authz_service.EvaluateInput{Actor: actor, Repo: repo, Credential: ceiling, Action: authz.Clone, ConditionContext: authz.ConditionContext{Source: "ssh"}}, func(ctx context.Context) (*access_model.Permission, error) {
		permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
		return &permission, err
	})
	observation.Finish(observationCtx, authz_service.NativeUnknown, authz_service.StageAuthorization)
}

func sshReceiveOperationTicket(ctx context.Context, repo *repo_model.Repository, actor *user_model.User, keyID int64) authz.HookOperationTicket {
	ceiling := authz_service.CredentialCeiling{Read: true, Write: true, Reference: "ssh-key:" + strconv.FormatInt(keyID, 10)}
	if actor.ExtDoerData != nil {
		ceiling.NativeOnly = true
		ceiling.Reference = actor.ExtDoerData.EncodeToString()
	}
	return authz_service.NewHookOperationTicket(ctx, authz_service.EvaluateInput{Actor: actor, Repo: repo, Credential: ceiling, Action: authz.PushBranch, ConditionContext: authz.ConditionContext{Source: "ssh"}}, nil)
}
