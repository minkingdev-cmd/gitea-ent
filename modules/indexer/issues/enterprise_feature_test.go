// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package issues

import (
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/indexer/issues/bleve"
	"gitea.dev/modules/indexer/issues/internal"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

func TestFeatureBleveSearchFiltersBeforePagination(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureIssues, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	b := bleve.NewIndexer(t.TempDir())
	_, err := b.Init(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { b.Close() })
	require.NoError(t, b.Index(t.Context(), &internal.IndexerData{ID: 1, RepoID: 1, Title: "feature needle", CreatedUnix: 1, IsPull: false}, &internal.IndexerData{ID: 2, RepoID: 1, Title: "feature needle", CreatedUnix: 2, IsPull: true}, &internal.IndexerData{ID: 3, RepoID: 1, Title: "feature needle", CreatedUnix: 3, IsPull: true}))
	before := globalIndexer.Load()
	var ix internal.Indexer = b
	globalIndexer.Store(&ix)
	t.Cleanup(func() { globalIndexer.Store(before) })
	ids, total, err := SearchIssues(t.Context(), &SearchOptions{Keyword: "needle", RepoIDs: []int64{1}, Paginator: &db.ListOptions{Page: 1, PageSize: 1}, SortBy: internal.SortByCreatedAsc})
	require.NoError(t, err)
	require.EqualValues(t, 2, total)
	require.Equal(t, []int64{2}, ids)
}

func TestFeatureBleveShadowSearchCandidate(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true}))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureIssues, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	b := bleve.NewIndexer(t.TempDir())
	_, err := b.Init(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { b.Close() })
	require.NoError(t, b.Index(t.Context(),
		&internal.IndexerData{ID: 1, RepoID: 1, Title: "hidden marker", IsPull: false, CreatedUnix: 1},
		&internal.IndexerData{ID: 2, RepoID: 2, Title: "visible marker", IsPull: false, CreatedUnix: 2},
		&internal.IndexerData{ID: 3, RepoID: 1, Title: "pull marker", IsPull: true, CreatedUnix: 3}))
	before := globalIndexer.Load()
	var ix internal.Indexer = b
	globalIndexer.Store(&ix)
	t.Cleanup(func() { globalIndexer.Store(before) })
	opts := &SearchOptions{Keyword: "marker", RepoIDs: []int64{1, 2}, Paginator: &db.ListOptions{Page: 2, PageSize: 1}}
	counter := authz.FeatureQueryCandidate.WithLabelValues(string(authz.FeatureIssues), "would_deny")
	old := shadowSearchCounter(counter)
	_, total, err := SearchIssues(t.Context(), opts)
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.InDelta(t, old+1, shadowSearchCounter(counter), 0)
	opts.Keyword = "visible"
	old = shadowSearchCounter(counter)
	_, total, err = SearchIssues(t.Context(), opts)
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.InDelta(t, old, shadowSearchCounter(counter), 0)
	opts.Keyword = "marker"
	opts.RepoIDs = []int64{2}
	old = shadowSearchCounter(counter)
	_, total, err = SearchIssues(t.Context(), opts)
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.InDelta(t, old, shadowSearchCounter(counter), 0)
	require.Empty(t, opts.ExcludedIssueRepoIDs)
}

func shadowSearchCounter(counter prometheus.Counter) float64 {
	var metric dto.Metric
	if err := counter.Write(&metric); err != nil {
		panic(err)
	}
	return metric.GetCounter().GetValue()
}
