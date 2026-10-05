// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package code

import (
	"context"
	"slices"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/indexer/code/internal"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	_ "gitea.dev/models/packages"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

type featureSearchIndexer struct {
	internal.Indexer
	calls    int
	excluded []int64
}

func (idx *featureSearchIndexer) Search(_ context.Context, opts *internal.SearchOptions) (int64, []*internal.SearchResult, []*internal.SearchResultLanguages, error) {
	idx.calls++
	idx.excluded = slices.Clone(opts.ExcludedRepoIDs)
	return 0, nil, nil, nil
}

func TestFeatureCodeSearchExcludesOnlyMarkedIndexes(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	_, err := db.GetEngine(t.Context()).ID(1).Cols("internal_usage").Update(&repo_model.Repository{InternalUsage: repo_model.InternalUsageCargoIndex})
	require.NoError(t, err)
	for _, repoID := range []int64{1, 2} {
		require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: repoID, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	}
	idx := &featureSearchIndexer{Indexer: internal.NewDummyIndexer()}
	var searcher internal.Indexer = idx
	before := globalIndexer.Swap(&searcher)
	t.Cleanup(func() { globalIndexer.Store(before) })
	opts := &SearchOptions{Keyword: "needle", RepoIDs: []int64{1, 2}, Paginator: &db.ListOptions{Page: 1, PageSize: 1}}
	_, _, _, err = PerformSearch(t.Context(), opts)
	require.NoError(t, err)
	require.Equal(t, []int64{1}, idx.excluded)
	require.Empty(t, opts.ExcludedRepoIDs)

	for _, enabled := range []bool{false, true} {
		setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce = enabled, false
		_, _, _, err = PerformSearch(t.Context(), opts)
		require.NoError(t, err)
		require.Empty(t, idx.excluded)
	}

	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce = true, true
	_, err = db.GetEngine(t.Context()).Where("key=?", authz.FeaturePackages).Delete(new(authz_model.FeatureDefinition))
	require.NoError(t, err)
	calls := idx.calls
	_, _, _, err = PerformSearch(t.Context(), opts)
	require.ErrorIs(t, err, authz_model.ErrFeatureQueryUnavailable)
	require.Equal(t, calls, idx.calls)
}

type shadowCodeIndexer struct {
	internal.Indexer
	candidateCalls int
}

func (idx *shadowCodeIndexer) Search(_ context.Context, opts *internal.SearchOptions) (int64, []*internal.SearchResult, []*internal.SearchResultLanguages, error) {
	if slices.Equal(opts.RepoIDs, []int64{1}) && opts.Keyword == "needle" && opts.Language == "Rust" {
		idx.candidateCalls++
		return 1, []*internal.SearchResult{{RepoID: 1, Filename: "crate.rs", Content: "needle", StartIndex: 0, EndIndex: 6}}, nil, nil
	}
	return 2, nil, nil, nil
}

func TestFeatureCodeShadowCandidateSearch(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true}))
	_, err := db.GetEngine(t.Context()).ID(1).Cols("internal_usage").Update(&repo_model.Repository{InternalUsage: repo_model.InternalUsageCargoIndex})
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	idx := &shadowCodeIndexer{Indexer: internal.NewDummyIndexer()}
	var ix internal.Indexer = idx
	before := globalIndexer.Swap(&ix)
	t.Cleanup(func() { globalIndexer.Store(before) })
	counter := authz.FeatureQueryCandidate.WithLabelValues(string(authz.FeaturePackages), "would_deny")
	old := shadowCodeCounter(counter)
	opts := &SearchOptions{Keyword: "needle", Language: "Rust", RepoIDs: []int64{1, 2}, Paginator: db.NewAbsoluteListOptions(10, 1)}
	total, hits, _, err := PerformSearch(t.Context(), opts)
	require.NoError(t, err)
	require.EqualValues(t, 2, total)
	require.Empty(t, hits)
	require.Equal(t, 1, idx.candidateCalls)
	require.InDelta(t, old+1, shadowCodeCounter(counter), 0)
	require.Equal(t, []int64{1, 2}, opts.RepoIDs)
	opts.RepoIDs = []int64{2}
	old = shadowCodeCounter(counter)
	_, _, _, err = PerformSearch(t.Context(), opts)
	require.NoError(t, err)
	require.Equal(t, 1, idx.candidateCalls)
	require.InDelta(t, old, shadowCodeCounter(counter), 0)
}

func shadowCodeCounter(counter prometheus.Counter) float64 {
	var metric dto.Metric
	if err := counter.Write(&metric); err != nil {
		panic(err)
	}
	return metric.GetCounter().GetValue()
}
