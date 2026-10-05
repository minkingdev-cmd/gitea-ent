// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package webhook

import (
	"context"
	"strconv"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	webhook_model "gitea.dev/models/webhook"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func lockWebhookScope(ctx context.Context, hook *webhook_model.Webhook) error {
	if hook.RepoID > 0 {
		repo, err := repo_model.GetRepositoryByID(ctx, hook.RepoID)
		if err != nil {
			return err
		}
		if err := authz_model.LockScope(ctx, authz_model.Scope{Type: authz_model.ScopeOrg, ID: repo.OwnerID}); err != nil {
			return err
		}
		return authz_model.LockScope(ctx, authz_model.Scope{Type: authz_model.ScopeRepo, ID: hook.RepoID})
	}
	if hook.OwnerID > 0 {
		return authz_model.LockScope(ctx, authz_model.Scope{Type: authz_model.ScopeOrg, ID: hook.OwnerID})
	}
	return nil
}

func CreateWebhook(ctx context.Context, hook *webhook_model.Webhook) error {
	if hook.RepoID > 0 {
		if err := authz_service.RequireSettingsExecution(ctx, hook.RepoID, authz.ManageWebhook, authz_service.SettingsIntent(authz.ManageWebhook, "webhook:create")); err != nil {
			return err
		}
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
			if err := lockWebhookScope(ctx, hook); err != nil {
				return err
			}
			if err := authz_model.LockFeatures(ctx, []authz.FeatureKey{authz.FeatureWebhooks}); err != nil {
				if denied := authz_service.FeatureGuardError(err); denied != nil {
					return denied
				}
			}
		}
		if err := requireWebhookFeature(ctx, hook, 0, 0); err != nil {
			return err
		}
		return webhook_model.CreateWebhook(ctx, hook)
	})
}

func UpdateWebhook(ctx context.Context, hook *webhook_model.Webhook) error {
	if hook.RepoID > 0 {
		if err := authz_service.RequireSettingsExecution(ctx, hook.RepoID, authz.ManageWebhook, authz_service.SettingsIntent(authz.ManageWebhook, "webhook:"+strconv.FormatInt(hook.ID, 10))); err != nil {
			return err
		}
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		if setting.EnterpriseAuthz.Enabled {
			if setting.EnterpriseAuthz.Enforce {
				if err := lockWebhookScope(ctx, hook); err != nil {
					return err
				}
			}
			current, err := webhook_model.GetWebhookByID(ctx, hook.ID)
			if err != nil {
				return err
			}
			if setting.EnterpriseAuthz.Enforce && (current.RepoID != hook.RepoID || current.OwnerID != hook.OwnerID || current.IsSystemWebhook != hook.IsSystemWebhook) {
				return &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
			}
			if !webhookDisableOnly(current, hook) {
				if setting.EnterpriseAuthz.Enforce {
					if err := authz_model.LockFeatures(ctx, []authz.FeatureKey{authz.FeatureWebhooks}); err != nil {
						if denied := authz_service.FeatureGuardError(err); denied != nil {
							return denied
						}
					}
				}
				if err := requireWebhookFeature(ctx, hook, 0, 0); err != nil {
					return err
				}
			}
		}
		return webhook_model.UpdateWebhook(ctx, hook)
	})
}

func DeleteWebhookByRepoID(ctx context.Context, repoID, hookID int64) error {
	if err := authz_service.RequireSettingsExecution(ctx, repoID, authz.ManageWebhook, authz_service.SettingsIntent(authz.ManageWebhook, "webhook:"+strconv.FormatInt(hookID, 10))); err != nil {
		return err
	}
	return webhook_model.DeleteWebhookByRepoID(ctx, repoID, hookID)
}
