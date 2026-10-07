// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package issues_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gitea.dev/models/db"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

func TestMergeGateReviewReadsPreserveErrors(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pr := &issues_model.PullRequest{IssueID: 5000}
	pb := &git_model.ProtectedBranch{RequiredApprovals: 1, BlockOnRejectedReviews: true, BlockOnOfficialReviewRequests: true}
	review := &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 2, Type: issues_model.ReviewTypeApprove, Official: true, Stale: true}
	require.NoError(t, db.Insert(t.Context(), review))
	allowed, err := issues_model.HasEnoughApprovalsWithError(t.Context(), pb, pr)
	require.NoError(t, err)
	require.True(t, allowed)
	pb.IgnoreStaleApprovals = true
	allowed, err = issues_model.HasEnoughApprovalsWithError(t.Context(), pb, pr)
	require.NoError(t, err)
	require.False(t, allowed)
	hook := &mergeGateReviewFault{enabled: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	defer func() { hook.enabled = false }()
	_, err = issues_model.HasEnoughApprovalsWithError(t.Context(), pb, pr)
	require.ErrorIs(t, err, errMergeGateReviewRead)
	_, err = issues_model.MergeBlockedByRejectedReviewWithError(t.Context(), pb, pr)
	require.ErrorIs(t, err, errMergeGateReviewRead)
	_, err = issues_model.MergeBlockedByOfficialReviewRequestsWithError(t.Context(), pb, pr)
	require.ErrorIs(t, err, errMergeGateReviewRead)
	require.False(t, issues_model.HasEnoughApprovals(t.Context(), pb, pr))
	require.True(t, issues_model.MergeBlockedByRejectedReview(t.Context(), pb, pr))
	require.True(t, issues_model.MergeBlockedByOfficialReviewRequests(t.Context(), pb, pr))
}

func TestMergeGateCodeOwnersReadsPreserveErrors(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	rules, warnings, err := issues_model.GetCodeOwnersFromContentWithError(t.Context(), ".* @user2\n")
	require.NoError(t, err)
	require.Empty(t, warnings)
	require.Len(t, rules, 1)
	rules, warnings, err = issues_model.GetCodeOwnersFromContentWithError(t.Context(), ".* @missing-code-owner\n")
	require.NoError(t, err)
	require.NotEmpty(t, warnings)
	require.Empty(t, rules)
	hook := &mergeGateCodeOwnerFault{enabled: true, table: "user"}
	db.GetXORMEngineForTesting().AddHook(hook)
	defer func() { hook.enabled = false }()
	for _, data := range []string{".* @user2\n", ".* @user3/Owners\n"} {
		rules, _, err = issues_model.GetCodeOwnersFromContentWithError(t.Context(), data)
		require.ErrorIs(t, err, errMergeGateReviewRead)
		require.Empty(t, rules)
	}
	rules, warnings = issues_model.GetCodeOwnersFromContent(t.Context(), ".* @user2\n")
	require.Empty(t, rules)
	require.NotEmpty(t, warnings)
	hook.table = "team"
	rules, _, err = issues_model.GetCodeOwnersFromContentWithError(t.Context(), ".* @user3/Owners\n")
	require.ErrorIs(t, err, errMergeGateReviewRead)
	require.Empty(t, rules)
}

func TestMergeGateSensitiveCodeownersDoNotDropUnownedRules(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	for _, content := range []string{"[ @user2\n", "file\n", ".* @org/team/extra\n", ".* @/Owners\n", ".* @user3/\n", ".* @/\n", ".* @\n"} {
		rules, err := issues_model.GetCodeOwnersForSensitivePaths(t.Context(), content)
		require.Error(t, err, content)
		require.Empty(t, rules)
		_, warnings, err := issues_model.GetCodeOwnersFromContentWithError(t.Context(), content)
		require.NoError(t, err, "native checked parser preserves best-effort syntax")
		require.NotEmpty(t, warnings)
	}
	content := ".* @user2\nsensitive/.* @missing-code-owner\n"
	rules, err := issues_model.GetCodeOwnersForSensitivePaths(t.Context(), content)
	require.NoError(t, err)
	require.Len(t, rules, 2)
	require.Empty(t, rules[1].Users)
	require.Empty(t, rules[1].Teams)
	native, _, err := issues_model.GetCodeOwnersFromContentWithError(t.Context(), content)
	require.NoError(t, err)
	require.Len(t, native, 1)
}

type mergeGateCodeOwnerFault struct {
	enabled bool
	table   string
}

func (h *mergeGateCodeOwnerFault) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.enabled && strings.HasPrefix(c.SQL, "SELECT") && strings.Contains(c.SQL, h.table) {
		return c.Ctx, errMergeGateReviewRead
	}
	return c.Ctx, nil
}

func (*mergeGateCodeOwnerFault) AfterProcess(*contexts.ContextHook) error { return nil }

func TestMergeGateUnresolvedReviewConversation(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	issueID := int64(5000)
	published := &issues_model.Review{IssueID: issueID, ReviewerID: 2, Type: issues_model.ReviewTypeComment}
	pending := &issues_model.Review{IssueID: issueID, ReviewerID: 4, Type: issues_model.ReviewTypePending}
	require.NoError(t, db.Insert(t.Context(), published, pending))
	for _, comment := range []*issues_model.Comment{
		{IssueID: issueID, Type: issues_model.CommentTypeComment},
		{IssueID: issueID, Type: issues_model.CommentTypeCode, ReviewID: pending.ID},
		{IssueID: issueID, Type: issues_model.CommentTypeCode, ReviewID: published.ID, TreePath: "resolved.go", ResolveDoerID: 2},
	} {
		require.NoError(t, db.Insert(t.Context(), comment))
	}
	unresolved, err := issues_model.HasUnresolvedReviewConversation(t.Context(), issueID)
	require.NoError(t, err)
	require.False(t, unresolved)
	thread := &issues_model.Comment{IssueID: issueID, Type: issues_model.CommentTypeCode, ReviewID: published.ID, TreePath: "thread.go", Line: 10}
	require.NoError(t, db.Insert(t.Context(), thread))
	reply := &issues_model.Comment{IssueID: issueID, Type: issues_model.CommentTypeCode, ReviewID: published.ID, TreePath: thread.TreePath, Line: thread.Line}
	require.NoError(t, db.Insert(t.Context(), reply))
	unresolved, err = issues_model.HasUnresolvedReviewConversation(t.Context(), issueID)
	require.NoError(t, err)
	require.True(t, unresolved)
	require.NoError(t, issues_model.MarkConversation(t.Context(), thread, &user_model.User{ID: 2}, true))
	unresolved, err = issues_model.HasUnresolvedReviewConversation(t.Context(), issueID)
	require.NoError(t, err)
	require.False(t, unresolved)
	otherReview := &issues_model.Review{IssueID: issueID, ReviewerID: 4, Type: issues_model.ReviewTypeComment}
	require.NoError(t, db.Insert(t.Context(), otherReview))
	otherThread := &issues_model.Comment{IssueID: issueID, Type: issues_model.CommentTypeCode, ReviewID: otherReview.ID, TreePath: thread.TreePath, Line: thread.Line}
	require.NoError(t, db.Insert(t.Context(), otherThread))
	unresolved, err = issues_model.HasUnresolvedReviewConversation(t.Context(), issueID)
	require.NoError(t, err)
	require.True(t, unresolved, "a later review owns an independent conversation on the same line")
	hook := &mergeGateReviewFault{enabled: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	defer func() { hook.enabled = false }()
	_, err = issues_model.HasUnresolvedReviewConversation(t.Context(), issueID)
	require.ErrorIs(t, err, errMergeGateReviewRead)
}

var errMergeGateReviewRead = errors.New("injected_review_read_failure")

type mergeGateReviewFault struct{ enabled bool }

func (h *mergeGateReviewFault) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.enabled && strings.HasPrefix(c.SQL, "SELECT") && strings.Contains(c.SQL, "review") {
		return c.Ctx, errMergeGateReviewRead
	}
	return c.Ctx, nil
}
func (*mergeGateReviewFault) AfterProcess(*contexts.ContextHook) error { return nil }
