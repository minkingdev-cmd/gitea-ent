// Copyright 2022 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package secrets

import (
	"gitea.dev/models/db"
	repo_model "gitea.dev/models/repo"
	secret_model "gitea.dev/models/secret"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/log"
	"gitea.dev/modules/util"
	"gitea.dev/modules/web"
	"gitea.dev/routers/common"
	"gitea.dev/services/audit"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
	"gitea.dev/services/forms"
	secret_service "gitea.dev/services/secrets"
)

func SetSecretsContext(ctx *context.Context, ownerID, repoID int64) {
	secrets, _, err := secret_service.ListManagementSecrets(ctx, &secret_model.FindSecretsOptions{OwnerID: ownerID, RepoID: repoID})
	if err != nil {
		if common.WriteExecutionError(ctx.Base, err) {
			return
		}
		ctx.ServerError("FindSecrets", err)
		return
	}

	ctx.Data["Secrets"] = secrets
	ctx.Data["DataMaxLength"] = secret_model.SecretDataMaxLength
	ctx.Data["DescriptionMaxLength"] = secret_model.SecretDescriptionMaxLength
}

func secretOwnerRepoIDs(owner *user_model.User, repo *repo_model.Repository) (ownerID, repoID int64) {
	if owner != nil {
		ownerID = owner.ID
	}
	if repo != nil {
		repoID = repo.ID
	}
	return ownerID, repoID
}

func PerformSecretsPost(ctx *context.Context, owner *user_model.User, repo *repo_model.Repository, redirectURL string) {
	defer common.ObserveRepoSettingMutation(ctx.Base, ctx.Doer, repo, &ctx.Repo.Permission, authz.ManageSecret)()
	form := web.GetForm[*forms.AddSecretForm](ctx)
	ownerID, repoID := secretOwnerRepoIDs(owner, repo)

	finishExecution, allowed := common.BeginRepoExecution(ctx.Base, ctx.Doer, repo, "web", authz_service.SettingsIntent(authz.ManageSecret, form.Name), authz.ManageSecret)
	if !allowed {
		return
	}
	defer finishExecution()
	s, created, err := secret_service.CreateOrUpdateSecret(ctx, ownerID, repoID, form.Name, util.NormalizeStringEOL(form.Data), form.Description)
	if err != nil {
		if common.WriteExecutionError(ctx.Base, err) {
			return
		}
		ctx.JSONErrorAuto(err)
		return
	}

	actions := audit.SecretUpdate
	if created {
		actions = audit.SecretAdd
	}
	audit.RecordScoped(ctx, owner, repo, actions, "secret", s.Name)

	common.MarkRepoSettingSuccess(ctx.Base, authz.ManageSecret)
	ctx.Flash.Success(ctx.Tr("secrets.save_success", s.Name))
	ctx.JSONRedirect(redirectURL)
}

func PerformSecretsDelete(ctx *context.Context, owner *user_model.User, repo *repo_model.Repository, redirectURL string) {
	defer common.ObserveRepoSettingMutation(ctx.Base, ctx.Doer, repo, &ctx.Repo.Permission, authz.ManageSecret)()
	id := ctx.FormInt64("id")
	ownerID, repoID := secretOwnerRepoIDs(owner, repo)

	if repo != nil {
		found, err := db.Find[secret_model.Secret](ctx, secret_model.FindSecretsOptions{RepoID: repoID, SecretID: id})
		if err != nil || len(found) != 1 {
			ctx.JSONError(ctx.Tr("secrets.deletion.failed"))
			return
		}
		finishExecution, allowed := common.BeginRepoExecution(ctx.Base, ctx.Doer, repo, "web", authz_service.SettingsIntent(authz.ManageSecret, found[0].Name), authz.ManageSecret)
		if !allowed {
			return
		}
		defer finishExecution()
	}
	s, err := secret_service.DeleteSecretByID(ctx, ownerID, repoID, id)
	if err != nil {
		if common.WriteExecutionError(ctx.Base, err) {
			return
		}
		log.Error("DeleteSecretByID(%d) failed: %v", id, err)
		ctx.JSONError(ctx.Tr("secrets.deletion.failed"))
		return
	}

	audit.RecordScoped(ctx, owner, repo, audit.SecretRemove, "secret", s.Name)

	common.MarkRepoSettingSuccess(ctx.Base, authz.ManageSecret)
	ctx.Flash.Success(ctx.Tr("secrets.deletion.success"))
	ctx.JSONRedirect(redirectURL)
}
