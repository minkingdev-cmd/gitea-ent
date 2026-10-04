// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package webhook

import (
	"context"
	"strconv"

	webhook_model "gitea.dev/models/webhook"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func CreateWebhook(ctx context.Context, hook *webhook_model.Webhook) error {
	if hook.RepoID > 0 {
		if err := authz_service.RequireSettingsExecution(ctx, hook.RepoID, authz.ManageWebhook, authz_service.SettingsIntent(authz.ManageWebhook, "webhook:create")); err != nil {
			return err
		}
	}
	return webhook_model.CreateWebhook(ctx, hook)
}

func UpdateWebhook(ctx context.Context, hook *webhook_model.Webhook) error {
	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
		current, err := webhook_model.GetWebhookByID(ctx, hook.ID)
		if err != nil {
			return err
		}
		if current.RepoID != hook.RepoID || current.OwnerID != hook.OwnerID {
			return &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
		}
	}
	if hook.RepoID > 0 {
		if err := authz_service.RequireSettingsExecution(ctx, hook.RepoID, authz.ManageWebhook, authz_service.SettingsIntent(authz.ManageWebhook, "webhook:"+strconv.FormatInt(hook.ID, 10))); err != nil {
			return err
		}
	}
	return webhook_model.UpdateWebhook(ctx, hook)
}

func DeleteWebhookByRepoID(ctx context.Context, repoID, hookID int64) error {
	if err := authz_service.RequireSettingsExecution(ctx, repoID, authz.ManageWebhook, authz_service.SettingsIntent(authz.ManageWebhook, "webhook:"+strconv.FormatInt(hookID, 10))); err != nil {
		return err
	}
	return webhook_model.DeleteWebhookByRepoID(ctx, repoID, hookID)
}
