// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package issue

import (
	"testing"

	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	"gitea.dev/models/unittest"

	"github.com/stretchr/testify/require"
)

func TestMergeGateNativeCodeownerReadFailure(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pb := &git_model.ProtectedBranch{BlockOnCodeownerReviews: true}
	pr := &issues_model.PullRequest{ID: 5000, BaseRepoID: 999999}
	allowed, err := HasAllRequiredCodeownerReviewsWithError(t.Context(), pb, pr)
	require.Error(t, err)
	require.False(t, allowed)
	require.False(t, HasAllRequiredCodeownerReviews(t.Context(), pb, pr))
	pb.BlockOnCodeownerReviews = false
	allowed, err = HasAllRequiredCodeownerReviewsWithError(t.Context(), pb, pr)
	require.NoError(t, err)
	require.True(t, allowed)
}
