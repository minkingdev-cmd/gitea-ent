// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package webhook

import (
	"context"

	authz_model "gitea.dev/models/enterpriseauthz"
	webhook_model "gitea.dev/models/webhook"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	webhook_module "gitea.dev/modules/webhook"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func requireWebhookFeature(ctx context.Context, hook *webhook_model.Webhook, repoID, ownerID int64) error {
	if setting.EnterpriseAuthz.Enabled && hook.ID > 0 {
		current, err := webhook_model.GetWebhookByID(ctx, hook.ID)
		if err != nil {
			return authz_service.FeatureGuardError(err)
		}
		hook = current
	}
	if err := authz_service.RequireFeature(ctx, authz.FeatureWebhooks, authz_model.Scope{Type: authz_model.ScopeSystem}); err != nil {
		return err
	}
	if hook.OwnerID > 0 {
		if err := authz_service.RequireOwnerFeature(ctx, hook.OwnerID, authz.FeatureWebhooks); err != nil {
			return err
		}
	}
	if hook.RepoID > 0 {
		if err := authz_service.RequireRepoFeature(ctx, hook.RepoID, authz.FeatureWebhooks); err != nil {
			return err
		}
	}
	if repoID > 0 {
		return authz_service.RequireRepoFeature(ctx, repoID, authz.FeatureWebhooks)
	}
	if ownerID > 0 {
		return authz_service.RequireOwnerFeature(ctx, ownerID, authz.FeatureWebhooks)
	}
	return nil
}

func requireHookTaskFeature(ctx context.Context, hook *webhook_model.Webhook, task *webhook_model.HookTask) error {
	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce && ((!task.SourceResolved && hook.RepoID == 0) || (task.EventType == webhook_module.HookEventPackage && task.SourceOwnerID <= 0)) {
		return &authz_service.ExecutionError{Reason: "webhook_source_unavailable", Status: 403}
	}
	if err := requireWebhookFeature(ctx, hook, task.SourceRepoID, task.SourceOwnerID); err != nil {
		return err
	}
	repoID, ownerID := task.SourceRepoID, task.SourceOwnerID
	if !task.SourceResolved && hook.RepoID > 0 {
		repoID = hook.RepoID
	}
	return requireWebhookBusinessFeature(ctx, task.EventType, repoID, ownerID)
}

func requireWebhookBusinessFeature(ctx context.Context, event webhook_module.HookEventType, repoID, ownerID int64) error {
	var key authz.FeatureKey
	switch event {
	case webhook_module.HookEventIssues, webhook_module.HookEventIssueAssign, webhook_module.HookEventIssueLabel, webhook_module.HookEventIssueMilestone, webhook_module.HookEventIssueComment:
		key = authz.FeatureIssues
	case webhook_module.HookEventPullRequest, webhook_module.HookEventPullRequestAssign, webhook_module.HookEventPullRequestLabel, webhook_module.HookEventPullRequestMilestone, webhook_module.HookEventPullRequestComment, webhook_module.HookEventPullRequestReviewApproved, webhook_module.HookEventPullRequestReviewRejected, webhook_module.HookEventPullRequestReviewComment, webhook_module.HookEventPullRequestSync, webhook_module.HookEventPullRequestReviewRequest, webhook_module.HookEventPullRequestReview:
		key = authz.FeaturePullRequests
	case webhook_module.HookEventWiki:
		key = authz.FeatureWiki
	case webhook_module.HookEventPackage:
		key = authz.FeaturePackages
	default:
		return nil
	}
	if key == authz.FeaturePackages && ownerID > 0 {
		if err := authz_service.RequireOwnerFeature(ctx, ownerID, key); err != nil {
			return err
		}
	}
	if repoID > 0 {
		return authz_service.RequireRepoFeature(ctx, repoID, key)
	}
	if ownerID > 0 {
		return authz_service.RequireOwnerFeature(ctx, ownerID, key)
	}
	return authz_service.RequireFeature(ctx, key, authz_model.Scope{Type: authz_model.ScopeSystem})
}

func webhookDisableOnly(current, next *webhook_model.Webhook) bool {
	return !next.IsActive && current.RepoID == next.RepoID && current.OwnerID == next.OwnerID && current.IsSystemWebhook == next.IsSystemWebhook && current.URL == next.URL && current.Name == next.Name && current.HTTPMethod == next.HTTPMethod && current.ContentType == next.ContentType && current.Secret == next.Secret && current.Events == next.Events && current.Type == next.Type && current.Meta == next.Meta && current.HeaderAuthorizationEncrypted == next.HeaderAuthorizationEncrypted
}
