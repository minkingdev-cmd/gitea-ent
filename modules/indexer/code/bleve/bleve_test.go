// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package bleve

import (
	"strconv"
	"testing"
	"time"

	"gitea.dev/models/db"
	"gitea.dev/modules/indexer/code/internal"
	inner_bleve "gitea.dev/modules/indexer/internal/bleve"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBleveIndexerTokenFilter(t *testing.T) {
	dir := t.TempDir()
	indexer := NewIndexer(dir)
	defer indexer.Close()

	_, err := indexer.Init(t.Context())
	require.NoError(t, err)

	batch := inner_bleve.NewFlushingBatch(indexer.inner.Indexer, maxBatchSize)
	batch.Index("2", &RepoIndexerData{RepoID: 2, Content: "mDNS.port2=12345", UpdatedAt: time.Now()})
	batch.Flush()

	testCases := []struct {
		keyword     string
		expectedIDs []int64
	}{
		{keyword: "12345", expectedIDs: []int64{2}},
		{keyword: "DNS", expectedIDs: []int64{}},
		{keyword: "mdns", expectedIDs: []int64{2}},
		{keyword: "port", expectedIDs: []int64{2}},
		{keyword: "port2", expectedIDs: []int64{2}},
	}

	for _, testCase := range testCases {
		t.Run(testCase.keyword, func(t *testing.T) {
			_, results, _, err := indexer.Search(t.Context(), &internal.SearchOptions{
				Paginator: &db.ListOptions{Page: 1, PageSize: 1},
				Keyword:   testCase.keyword,
			})
			require.NoError(t, err)
			assert.ElementsMatch(t, testCase.expectedIDs, searchResultIDs(results))
		})
	}
}

func searchResultIDs(result []*internal.SearchResult) []int64 {
	ids := make([]int64, 0, len(result))
	for _, hit := range result {
		ids = append(ids, hit.RepoID)
	}
	return ids
}

func TestExcludedRepositoriesBeforePaginationAndFacets(t *testing.T) {
	idx := NewIndexer(t.TempDir())
	_, err := idx.Init(t.Context())
	require.NoError(t, err)
	t.Cleanup(idx.Close)
	batch := inner_bleve.NewFlushingBatch(idx.inner.Indexer, maxBatchSize)
	for id, language := range map[int64]string{1: "Rust", 2: "Go", 3: "Python"} {
		batch.Index(strconv.FormatInt(id, 10)+"_file.txt", &RepoIndexerData{RepoID: id, Content: "needle", Language: language, CommitID: "commit", UpdatedAt: time.Now()})
	}
	require.NoError(t, batch.Flush())
	for _, language := range []string{"", "Go"} {
		for _, page := range []int{1, 2} {
			opts := &internal.SearchOptions{Keyword: "needle", Language: language, Paginator: &db.ListOptions{Page: page, PageSize: 1}}
			opts.ExcludedRepoIDs = []int64{1, 3}
			total, hits, languages, err := idx.Search(t.Context(), opts)
			require.NoError(t, err)
			assert.EqualValues(t, 1, total)
			if page == 1 {
				assert.Equal(t, []int64{2}, searchResultIDs(hits))
			} else {
				assert.Empty(t, hits)
			}
			require.Len(t, languages, 1)
			assert.Equal(t, "Go", languages[0].Language)
			assert.Equal(t, 1, languages[0].Count)
		}
	}
}
