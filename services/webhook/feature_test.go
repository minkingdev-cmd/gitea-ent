// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package webhook

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	webhook_model "gitea.dev/models/webhook"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	webhook_module "gitea.dev/modules/webhook"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

func TestWebhookFeatureRevocationBeforeDelivery(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer server.Close()
	hook := &webhook_model.Webhook{RepoID: 1, URL: server.URL, Type: webhook_module.GITEA, ContentType: webhook_model.ContentTypeJSON, IsActive: true}
	require.NoError(t, webhook_model.CreateWebhook(t.Context(), hook))
	task, err := webhook_model.CreateHookTask(t.Context(), &webhook_model.HookTask{HookID: hook.ID, PayloadContent: "{}", PayloadVersion: 2, EventType: webhook_module.HookEventPush})
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureWebhooks, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	require.Error(t, Deliver(t.Context(), task))
	require.Zero(t, requests.Load())
	persisted, err := webhook_model.GetHookTaskByID(t.Context(), task.ID)
	require.NoError(t, err)
	require.False(t, persisted.IsSucceed)
}

func TestWebhookRequiresTrustedEventSource(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	hook := &webhook_model.Webhook{IsSystemWebhook: true, URL: "http://127.0.0.1", IsActive: true, Type: webhook_module.GITEA, HookEvent: &webhook_module.HookEvent{SendEverything: true}}
	require.NoError(t, hook.UpdateEvent())
	require.NoError(t, webhook_model.CreateWebhook(t.Context(), hook))
	require.ErrorContains(t, PrepareWebhooks(t.Context(), EventSource{}, webhook_module.HookEventPush, &api.PushPayload{}), "invalid_webhook_source")
	require.ErrorContains(t, PrepareWebhook(t.Context(), hook, webhook_module.HookEventPush, &api.PushPayload{}), "invalid_webhook_source")
	unittest.AssertNotExistsBean(t, &webhook_model.HookTask{HookID: hook.ID})
}

func TestWebhookFeatureAllowsTrustedDelivery(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer server.Close()
	hook := &webhook_model.Webhook{IsSystemWebhook: true, URL: server.URL, Type: webhook_module.GITEA, ContentType: webhook_model.ContentTypeJSON, IsActive: true}
	require.NoError(t, CreateWebhook(t.Context(), hook))
	task, err := webhook_model.CreateHookTask(t.Context(), &webhook_model.HookTask{HookID: hook.ID, SourceRepoID: 1, SourceResolved: true, PayloadContent: "{}", PayloadVersion: 2, EventType: webhook_module.HookEventPush})
	require.NoError(t, err)
	require.NoError(t, Deliver(t.Context(), task))
	require.EqualValues(t, 1, requests.Load())
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureWebhooks, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	require.ErrorContains(t, ReplayHookTask(t.Context(), hook, task.UUID), "feature_disabled")
	count, err := db.GetEngine(t.Context()).Where("hook_id=?", hook.ID).Count(new(webhook_model.HookTask))
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	legacy, err := webhook_model.CreateHookTask(t.Context(), &webhook_model.HookTask{HookID: hook.ID, PayloadContent: "{}", PayloadVersion: 2, EventType: webhook_module.HookEventPush})
	require.NoError(t, err)
	require.ErrorContains(t, Deliver(t.Context(), legacy), "webhook_source_unavailable")
	require.EqualValues(t, 1, requests.Load())
	updatedHook := *hook
	updatedHook.IsActive = false
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureWebhooks, ScopeType: authz_model.ScopeSystem, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	require.NoError(t, UpdateWebhook(t.Context(), &updatedHook))
	updatedHook.URL = "https://different.example"
	require.ErrorContains(t, UpdateWebhook(t.Context(), &updatedHook), "feature_disabled")
}

func TestWebhookPreparationInTransaction(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	hook := &webhook_model.Webhook{RepoID: 1, URL: "http://localhost/tx-test", Type: webhook_module.GITEA, ContentType: webhook_model.ContentTypeJSON, IsActive: true, HookEvent: &webhook_module.HookEvent{SendEverything: true}}
	require.NoError(t, hook.UpdateEvent())
	require.NoError(t, webhook_model.CreateWebhook(t.Context(), hook))
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		return PrepareWebhook(ctx, hook, webhook_module.HookEventPush, &api.PushPayload{Commits: []*api.PayloadCommit{{}}})
	}))
	task := unittest.AssertExistsAndLoadBean(t, &webhook_model.HookTask{HookID: hook.ID})
	require.True(t, task.SourceResolved)
	require.EqualValues(t, 1, task.SourceRepoID)
}

func TestWebhookBusinessFeatureRevocationBeforeDelivery(t *testing.T) {
	for _, entry := range []struct {
		event webhook_module.HookEventType
		key   authz.FeatureKey
	}{
		{webhook_module.HookEventIssues, authz.FeatureIssues},
		{webhook_module.HookEventPullRequestReviewComment, authz.FeaturePullRequests},
		{webhook_module.HookEventWiki, authz.FeatureWiki},
		{webhook_module.HookEventPackage, authz.FeaturePackages},
	} {
		t.Run(string(entry.event), func(t *testing.T) {
			require.NoError(t, unittest.PrepareTestDatabase())
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
			t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
			defer server.Close()
			hook := &webhook_model.Webhook{IsSystemWebhook: true, URL: server.URL, Type: webhook_module.GITEA, ContentType: webhook_model.ContentTypeJSON, IsActive: true}
			require.NoError(t, webhook_model.CreateWebhook(t.Context(), hook))
			task, err := webhook_model.CreateHookTask(t.Context(), &webhook_model.HookTask{HookID: hook.ID, SourceRepoID: 1, SourceOwnerID: 2, SourceResolved: true, PayloadContent: `{"private":"persisted-content"}`, PayloadVersion: 2, EventType: entry.event})
			require.NoError(t, err)
			require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: entry.key, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
			task.EventType = webhook_module.HookEventPush
			task.SourceRepoID, task.SourceOwnerID = 0, 0
			require.ErrorContains(t, Deliver(t.Context(), task), "feature_disabled")
			require.Zero(t, requests.Load())
			persisted, err := webhook_model.GetHookTaskByID(t.Context(), task.ID)
			require.NoError(t, err)
			require.False(t, persisted.IsSucceed)
			require.ErrorContains(t, ReplayHookTask(t.Context(), hook, task.UUID), "feature_disabled")
		})
	}
}

func TestWebhookPackageChecksPackageOwnerIndependently(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	hook := &webhook_model.Webhook{IsSystemWebhook: true, URL: "http://localhost/never", Type: webhook_module.GITEA, ContentType: webhook_model.ContentTypeJSON, IsActive: true}
	require.NoError(t, webhook_model.CreateWebhook(t.Context(), hook))
	task, err := webhook_model.CreateHookTask(t.Context(), &webhook_model.HookTask{HookID: hook.ID, SourceRepoID: 1, SourceOwnerID: 3, SourceResolved: true, EventType: webhook_module.HookEventPackage, PayloadContent: "{}", PayloadVersion: 2})
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeOrg, ScopeID: 3, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	require.ErrorContains(t, Deliver(t.Context(), task), "feature_disabled")
	unittest.AssertExistsAndLoadBean(t, &webhook_model.HookTask{ID: task.ID, IsSucceed: false})
}

func TestWebhookRechecksCurrentOwnerAndPolicyAvailability(t *testing.T) {
	for _, fault := range []string{"owner_transfer", "missing_definition", "policy_storage"} {
		t.Run(fault, func(t *testing.T) {
			require.NoError(t, unittest.PrepareTestDatabase())
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
			t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
			defer server.Close()
			hook := &webhook_model.Webhook{IsSystemWebhook: true, URL: server.URL, Type: webhook_module.GITEA, ContentType: webhook_model.ContentTypeJSON, IsActive: true}
			require.NoError(t, webhook_model.CreateWebhook(t.Context(), hook))
			task, err := webhook_model.CreateHookTask(t.Context(), &webhook_model.HookTask{HookID: hook.ID, SourceRepoID: 1, SourceOwnerID: 2, SourceResolved: true, PayloadContent: "{}", PayloadVersion: 2, EventType: webhook_module.HookEventPush})
			require.NoError(t, err)
			status := http.StatusForbidden
			if fault == "owner_transfer" {
				_, err = db.GetEngine(t.Context()).ID(1).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 3})
				require.NoError(t, err)
				require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureWebhooks, ScopeType: authz_model.ScopeOrg, ScopeID: 3, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
			} else if fault == "policy_storage" {
				hook := &webhookPolicyQueryFailure{enabled: true}
				db.GetXORMEngineForTesting().AddHook(hook)
				t.Cleanup(func() { hook.enabled = false })
				status = http.StatusServiceUnavailable
			} else {
				_, err = db.GetEngine(t.Context()).Where("`key`=?", authz.FeatureWebhooks).Delete(new(authz_model.FeatureDefinition))
				require.NoError(t, err)
				status = http.StatusServiceUnavailable
			}
			err = Deliver(t.Context(), task)
			var executionErr *authz_service.ExecutionError
			require.ErrorAs(t, err, &executionErr)
			require.Equal(t, status, executionErr.Status)
			require.Zero(t, requests.Load())
			persisted := unittest.AssertExistsAndLoadBean(t, &webhook_model.HookTask{ID: task.ID})
			require.False(t, persisted.IsSucceed)
			require.NotNil(t, persisted.ResponseInfo)
			require.Equal(t, status, persisted.ResponseInfo.Status)
			require.Error(t, ReplayHookTask(t.Context(), hook, task.UUID))
			count, err := db.GetEngine(t.Context()).Where("hook_id=?", hook.ID).Count(new(webhook_model.HookTask))
			require.NoError(t, err)
			require.EqualValues(t, 1, count)
		})
	}
}

type webhookPolicyQueryFailure struct{ enabled bool }

func (h *webhookPolicyQueryFailure) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.enabled && strings.HasPrefix(c.SQL, "SELECT") && strings.Contains(c.SQL, "enterprise_feature_definition") {
		return c.Ctx, errors.New("injected feature policy storage failure")
	}
	return c.Ctx, nil
}
func (*webhookPolicyQueryFailure) AfterProcess(*contexts.ContextHook) error { return nil }
