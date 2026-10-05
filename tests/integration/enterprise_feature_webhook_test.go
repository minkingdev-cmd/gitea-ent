// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	webhook_model "gitea.dev/models/webhook"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	webhook_module "gitea.dev/modules/webhook"
	authz_service "gitea.dev/services/enterpriseauthz"
	webhook_service "gitea.dev/services/webhook"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseFeatureWebhookDeliveryRechecksSource(t *testing.T) {
	for _, entry := range []struct {
		name  string
		event webhook_module.HookEventType
		key   authz.FeatureKey
	}{
		{"owner_transfer", webhook_module.HookEventPush, authz.FeatureWebhooks},
		{"missing_definition", webhook_module.HookEventPush, authz.FeatureWebhooks},
		{"issues_revocation", webhook_module.HookEventIssues, authz.FeatureIssues},
		{"pull_requests_revocation", webhook_module.HookEventPullRequestReviewComment, authz.FeaturePullRequests},
		{"wiki_revocation", webhook_module.HookEventWiki, authz.FeatureWiki},
		{"packages_revocation", webhook_module.HookEventPackage, authz.FeaturePackages},
	} {
		t.Run(entry.name, func(t *testing.T) {
			defer tests.PrepareTestEnv(t)()
			featureTestMode(t)
			setting.EnterpriseAuthz.Enforce = true
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
			defer server.Close()
			hook := &webhook_model.Webhook{IsSystemWebhook: true, URL: server.URL, Type: webhook_module.GITEA, ContentType: webhook_model.ContentTypeJSON, IsActive: true, HookEvent: &webhook_module.HookEvent{SendEverything: true}}
			require.NoError(t, hook.UpdateEvent())
			require.NoError(t, webhook_model.CreateWebhook(t.Context(), hook))
			task, err := webhook_model.CreateHookTask(t.Context(), &webhook_model.HookTask{HookID: hook.ID, SourceRepoID: 1, SourceOwnerID: 2, SourceResolved: true, PayloadContent: `{"private":"persisted-content"}`, PayloadVersion: 2, EventType: entry.event})
			require.NoError(t, err)
			pending, err := webhook_model.GetHookTaskByID(t.Context(), task.ID)
			require.NoError(t, err)
			require.False(t, pending.IsDelivered)
			require.True(t, pending.SourceResolved)
			status := http.StatusForbidden
			switch entry.name {
			case "owner_transfer":
				_, err = db.GetEngine(t.Context()).ID(1).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 3})
				require.NoError(t, err)
				require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: entry.key, ScopeType: authz_model.ScopeOrg, ScopeID: 3, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
			case "missing_definition":
				_, err = db.GetEngine(t.Context()).Where("`key`=?", entry.key).Delete(new(authz_model.FeatureDefinition))
				require.NoError(t, err)
				status = http.StatusServiceUnavailable
			default:
				require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: entry.key, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
			}
			task.EventType = webhook_module.HookEventPush
			task.SourceRepoID, task.SourceOwnerID = 0, 0
			err = webhook_service.Deliver(t.Context(), task)
			var executionErr *authz_service.ExecutionError
			require.ErrorAs(t, err, &executionErr)
			require.Equal(t, status, executionErr.Status)
			require.Zero(t, requests.Load())
			persisted, err := webhook_model.GetHookTaskByID(t.Context(), task.ID)
			require.NoError(t, err)
			require.False(t, persisted.IsSucceed)
			require.NotNil(t, persisted.ResponseInfo)
			require.Equal(t, status, persisted.ResponseInfo.Status)
			require.Empty(t, persisted.RequestContent)
			require.Equal(t, entry.event, persisted.EventType)
			require.EqualValues(t, 1, persisted.SourceRepoID)
			require.EqualValues(t, 2, persisted.SourceOwnerID)
			require.Error(t, webhook_service.ReplayHookTask(t.Context(), hook, task.UUID))
			count, err := db.GetEngine(t.Context()).Where("hook_id=?", hook.ID).Count(new(webhook_model.HookTask))
			require.NoError(t, err)
			require.EqualValues(t, 1, count)
			require.Zero(t, requests.Load())
		})
	}
}
