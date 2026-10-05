// Copyright 2020 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package elasticsearch

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitea.dev/models/db"
	"gitea.dev/modules/indexer/code/internal"
	"gitea.dev/modules/json"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIndexPos(t *testing.T) {
	startIdx, endIdx := contentMatchIndexPos("test index start and end", "start", "end")
	assert.Equal(t, 11, startIdx)
	assert.Equal(t, 15, endIdx)
}

func TestExcludedRepositoriesInSearchAndFacetQueries(t *testing.T) {
	requests := make(chan map[string]any, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode search request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		requests <- body
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"hits":{"total":{"value":0},"hits":[]},"aggregations":{"language":{"buckets":[]}}}`)
	}))
	t.Cleanup(server.Close)
	idx := NewIndexer(server.URL, "test_excluded")
	_, err := idx.Init(t.Context())
	require.NoError(t, err)
	t.Cleanup(idx.Close)
	for _, language := range []string{"", "Go"} {
		opts := &internal.SearchOptions{Keyword: "needle", Language: language, Paginator: &db.ListOptions{Page: 2, PageSize: 1}}
		opts.ExcludedRepoIDs = []int64{1, 3}
		_, _, _, err := idx.Search(t.Context(), opts)
		require.NoError(t, err)
	}
	require.Len(t, requests, 3)
	for range 3 {
		body := <-requests
		encoded, err := json.Marshal(body["query"])
		require.NoError(t, err)
		var query map[string]map[string]json.Value
		require.NoError(t, json.Unmarshal(encoded, &query))
		assert.JSONEq(t, `[{"terms":{"repo_id":[1,3]}}]`, string(query["bool"]["must_not"]))
	}
}
