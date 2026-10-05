// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package activities_test

import (
	"context"
	"testing"

	activities_model "gitea.dev/models/activities"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

func TestFeatureFiltersFeedsAndNotificationCounts(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce = true, true
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureIssues, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	require.NoError(t, db.Insert(t.Context(), &activities_model.Action{UserID: 2, ActUserID: 2, RepoID: 1, OpType: activities_model.ActionCreateIssue, Content: "1|hidden", CreatedUnix: 2000000001}, &activities_model.Action{UserID: 2, ActUserID: 2, RepoID: 1, OpType: activities_model.ActionCreatePullRequest, Content: "2|visible", CreatedUnix: 2000000000}))
	actions, _, err := activities_model.GetFeeds(t.Context(), activities_model.GetFeedsOptions{RequestedRepo: repo, Actor: user, ListOptions: db.ListOptions{Page: 1, PageSize: 1}})
	require.NoError(t, err)
	require.Len(t, actions, 1)
	require.Equal(t, activities_model.ActionCreatePullRequest, actions[0].OpType)
	opts := &activities_model.FindNotificationOptions{UserID: 1, IssueID: 1}
	count, err := activities_model.CountNotifications(t.Context(), opts)
	require.NoError(t, err)
	require.Zero(t, count)
}

func TestFeatureNotificationQueryInfrastructureModes(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	_, err := db.GetEngine(t.Context()).Where("`key` = ?", authz.FeatureIssues).Delete(new(authz_model.FeatureDefinition))
	require.NoError(t, err)
	opts := &activities_model.FindNotificationOptions{UserID: 1, IssueID: 1}
	_, err = activities_model.CountNotifications(t.Context(), opts)
	require.ErrorIs(t, err, authz_model.ErrFeatureQueryUnavailable)
	_, err = activities_model.FindNotifications(t.Context(), opts)
	require.ErrorIs(t, err, authz_model.ErrFeatureQueryUnavailable)
	_, err = activities_model.GetNotificationByID(t.Context(), 1)
	require.ErrorIs(t, err, authz_model.ErrFeatureQueryUnavailable)
	setting.EnterpriseAuthz.FailClosedOnError = false
	count, err := activities_model.CountNotifications(t.Context(), opts)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	notifications, err := activities_model.FindNotifications(t.Context(), opts)
	require.NoError(t, err)
	require.Len(t, notifications, 1)
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = activities_model.CountNotifications(canceled, opts)
	require.ErrorIs(t, err, context.Canceled)
	setting.EnterpriseAuthz.Enforce = false
	count, err = activities_model.CountNotifications(t.Context(), opts)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	setting.EnterpriseAuthz.Enabled = false
	count, err = activities_model.CountNotifications(t.Context(), opts)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
}

func TestFeatureQueryAuditFacilityModes(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDisabled))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	opts := &activities_model.FindNotificationOptions{UserID: 1, IssueID: 1}
	_, err := activities_model.CountNotifications(t.Context(), opts)
	require.ErrorIs(t, err, authz_model.ErrFeatureQueryUnavailable)
	setting.EnterpriseAuthz.FailClosedOnError = false
	count, err := activities_model.CountNotifications(t.Context(), opts)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	setting.EnterpriseAuthz.Enforce = false
	count, err = activities_model.CountNotifications(t.Context(), opts)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
}

func TestNotificationQueryShadowCandidate(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true}))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureIssues, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	counter := authz.FeatureQueryCandidate.WithLabelValues(string(authz.FeatureIssues), "would_deny")
	before := shadowCounterValue(counter)
	count, err := activities_model.CountNotifications(t.Context(), &activities_model.FindNotificationOptions{UserID: 1, IssueID: 1})
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	require.InDelta(t, before+1, shadowCounterValue(counter), 0)
	before = shadowCounterValue(counter)
	count, err = activities_model.CountNotifications(t.Context(), &activities_model.FindNotificationOptions{UserID: 2, IssueID: 1})
	require.NoError(t, err)
	require.Zero(t, count)
	require.InDelta(t, before, shadowCounterValue(counter), 0)
}

func shadowCounterValue(counter prometheus.Counter) float64 {
	var metric dto.Metric
	if err := counter.Write(&metric); err != nil {
		panic(err)
	}
	return metric.GetCounter().GetValue()
}

func TestFeedQueryShadowCandidatePreservesNativePermissions(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true}))
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureIssues, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	require.NoError(t, db.Insert(t.Context(), &activities_model.Action{UserID: 2, ActUserID: 2, RepoID: 1, OpType: activities_model.ActionCreateIssue, Content: "1|shadow", CreatedUnix: 2000000001}))
	counter := authz.FeatureQueryCandidate.WithLabelValues(string(authz.FeatureIssues), "would_deny")
	before := shadowCounterValue(counter)
	_, _, err := activities_model.GetFeeds(t.Context(), activities_model.GetFeedsOptions{RequestedRepo: repo, Actor: actor, ListOptions: db.ListOptions{Page: 100, PageSize: 1}})
	require.NoError(t, err)
	require.InDelta(t, before+1, shadowCounterValue(counter), 0)
	before = shadowCounterValue(counter)
	repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
	_, _, err = activities_model.GetFeeds(t.Context(), activities_model.GetFeedsOptions{RequestedRepo: repo, Actor: actor, ListOptions: db.ListOptions{Page: 100, PageSize: 1}})
	require.NoError(t, err)
	require.InDelta(t, before, shadowCounterValue(counter), 0)
}
