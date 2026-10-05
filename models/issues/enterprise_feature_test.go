// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package issues_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	issues_model "gitea.dev/models/issues"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

func TestFeatureIssueQueryFiltersBeforePagination(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce = true, true
	grant := &authz_model.FeatureGrant{FeatureKey: authz.FeatureIssues, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}
	require.NoError(t, db.Insert(t.Context(), grant))
	opts := &issues_model.IssuesOptions{RepoIDs: []int64{1}, Paginator: &db.ListOptions{Page: 1, PageSize: 1}, SortType: "oldest"}
	ids, total, err := issues_model.IssueIDs(t.Context(), opts)
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Equal(t, []int64{2}, ids)
	count, err := issues_model.CountIssues(t.Context(), opts)
	require.NoError(t, err)
	require.Equal(t, total, count)
	setting.EnterpriseAuthz.Enforce = false
	_, total, err = issues_model.IssueIDs(t.Context(), opts)
	require.NoError(t, err)
	require.EqualValues(t, 5, total)
}

func TestFeatureFiltersTrackedTimeAndStopwatches(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureIssues, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	times, err := issues_model.GetTrackedTimes(t.Context(), &issues_model.FindTrackedTimesOptions{IssueID: 1})
	require.NoError(t, err)
	require.Empty(t, times)
	count, err := issues_model.CountTrackedTimes(t.Context(), &issues_model.FindTrackedTimesOptions{IssueID: 1})
	require.NoError(t, err)
	require.Zero(t, count)
	watches, err := issues_model.GetUserStopwatches(t.Context(), 1, db.ListOptions{Page: 1, PageSize: 1})
	require.NoError(t, err)
	require.Empty(t, watches)
	count, err = issues_model.CountUserStopwatches(t.Context(), 1)
	require.NoError(t, err)
	require.Zero(t, count)
	times, err = issues_model.GetTrackedTimes(t.Context(), &issues_model.FindTrackedTimesOptions{IssueID: 2})
	require.NoError(t, err)
	require.Len(t, times, 3)
}

func TestFeatureFiltersDependencyTargetsBeforeCount(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureIssues, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	require.NoError(t, db.Insert(t.Context(), &issues_model.IssueDependency{UserID: 1, IssueID: 2, DependencyID: 1}, &issues_model.IssueDependency{UserID: 1, IssueID: 2, DependencyID: 3}))
	issue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 2})
	deps, total, err := issue.BlockedByDependencies(t.Context(), db.ListOptions{Page: 1, PageSize: 1})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Len(t, deps, 1)
	require.EqualValues(t, 3, deps[0].Issue.ID)
	source := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 3})
	deps, err = source.BlockingDependencies(t.Context())
	require.NoError(t, err)
	require.Len(t, deps, 1)
	noBlockers, err := issues_model.IssueNoDependenciesLeft(t.Context(), issue)
	require.NoError(t, err)
	require.False(t, noBlockers)
}

func TestFeatureIssueQueryShadowCandidate(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true}))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureIssues, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	opts := &issues_model.IssuesOptions{RepoIDs: []int64{1}, Paginator: &db.ListOptions{Page: 1, PageSize: 1}, SortType: "oldest"}
	counter := authz.FeatureQueryCandidate.WithLabelValues(string(authz.FeatureIssues), "would_deny")
	before := shadowCounterValue(counter)
	ids, total, err := issues_model.IssueIDs(t.Context(), opts)
	require.NoError(t, err)
	require.EqualValues(t, 5, total)
	require.Len(t, ids, 1)
	require.InDelta(t, before+1, shadowCounterValue(counter), 0)
	opts.RepoIDs = []int64{2}
	allow := authz.FeatureQueryCandidate.WithLabelValues(string(authz.FeatureIssues), "would_allow")
	before = shadowCounterValue(allow)
	_, _, err = issues_model.IssueIDs(t.Context(), opts)
	require.NoError(t, err)
	require.InDelta(t, before+1, shadowCounterValue(allow), 0)
	setting.EnterpriseAuthz.Enabled = false
	before = shadowCounterValue(allow)
	_, _, err = issues_model.IssueIDs(t.Context(), opts)
	require.NoError(t, err)
	require.InDelta(t, before, shadowCounterValue(allow), 0)
}

func shadowCounterValue(counter prometheus.Counter) float64 {
	var metric dto.Metric
	if err := counter.Write(&metric); err != nil {
		panic(err)
	}
	return metric.GetCounter().GetValue()
}

func TestFeatureIssueShadowQueryFailureKeepsNative(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, FailClosedOnError: true}))
	hook := &shadowQueryFailure{enabled: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	t.Cleanup(func() { hook.enabled = false })
	counter := authz.FeatureQueryCandidate.WithLabelValues(string(authz.FeatureIssues), "error")
	before := shadowCounterValue(counter)
	count, err := issues_model.CountIssues(t.Context(), &issues_model.IssuesOptions{RepoIDs: []int64{1}})
	require.NoError(t, err)
	require.EqualValues(t, 5, count)
	require.InDelta(t, before+1, shadowCounterValue(counter), 0)
}

type shadowQueryFailure struct{ enabled bool }

func (h *shadowQueryFailure) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.enabled && strings.Contains(c.SQL, "enterprise_feature_grant") {
		return c.Ctx, errors.New("candidate grant storage unavailable")
	}
	return c.Ctx, nil
}
func (*shadowQueryFailure) AfterProcess(*contexts.ContextHook) error { return nil }
