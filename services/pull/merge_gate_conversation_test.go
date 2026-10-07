// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"errors"
	"testing"

	"gitea.dev/models/db"
	issues_model "gitea.dev/models/issues"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/automergequeue"

	"github.com/stretchr/testify/require"
)

func TestMergeGateConversationWakeWaitsForCommit(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	review := &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 4, Type: issues_model.ReviewTypeComment}
	require.NoError(t, db.Insert(t.Context(), review))
	root := &issues_model.Comment{IssueID: pr.IssueID, ReviewID: review.ID, Type: issues_model.CommentTypeCode, TreePath: "file.go", Line: 1}
	require.NoError(t, db.Insert(t.Context(), root))
	var items []automergequeue.AutoMergeItem
	t.Cleanup(test.MockVariableValue(&automergequeue.AddToQueue, func(item automergequeue.AutoMergeItem) { items = append(items, item) }))
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		require.NoError(t, ResolveReviewConversation(ctx, root, actor, true))
		require.Empty(t, items)
		return nil
	}))
	require.Len(t, items, 1)
	root = unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{ID: root.ID})
	rollback := errors.New("rollback conversation")
	require.ErrorIs(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		require.NoError(t, ResolveReviewConversation(ctx, root, actor, false))
		return rollback
	}), rollback)
	require.Len(t, items, 1)
	require.NotZero(t, unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{ID: root.ID}).ResolveDoerID)
}
