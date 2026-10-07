// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitea.dev/models/db"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/git/gitrepo"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestMergeGateNativeFactsAggregateCurrentGuards(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	t.Cleanup(test.MockVariableValue(&setting.Repository.PullRequest.WorkInProgressPrefixes, []string{"WIP:"}))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	_, err := db.GetEngine(t.Context()).ID(pr.IssueID).Cols("name").Update(&issues_model.Issue{Title: "WIP: gate"})
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).ID(pr.ID).Cols("status").Update(&issues_model.PullRequest{Status: issues_model.PullRequestStatusChecking})
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: pr.BaseRepoID, RuleName: pr.BaseBranch, RequiredApprovals: 99, BlockOnRejectedReviews: true, BlockOnOfficialReviewRequests: true}))
	reject := &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 4, Type: issues_model.ReviewTypeReject, Official: true}
	require.NoError(t, db.Insert(t.Context(), reject))
	require.NoError(t, db.Insert(t.Context(), &issues_model.Comment{IssueID: pr.IssueID, ReviewID: reject.ID, Type: issues_model.CommentTypeCode, TreePath: "thread", Line: 1}))
	facts, err := collectMergeGateNativeFacts(t.Context(), pr, actor, repo_model.MergeStyleMerge, "preview", nil)
	require.NoError(t, err)
	for _, code := range []string{"draft", "checking", "required_approvals", "rejected_review", "unresolved_conversation"} {
		found := false
		for _, fact := range facts {
			if fact.Code == code && fact.State == "failed" {
				found = true
			}
		}
		require.True(t, found, code)
	}
	result := authz.EvaluateMergeGate(authz.MergeGateInput{Mode: "enforce", Phase: "admission", Facts: facts, Bypass: authz.MergeGateBypass{Requested: true, Authorized: true, NativeAllowed: true, Reason: "rollback", Categories: []string{"required_approvals", "rejected_review"}}})
	require.Equal(t, "deny", result.AdmissionDecision)
	require.Len(t, result.BypassedReasons, 2)
	setting.EnterpriseMergeGate.Enabled = false
	facts, err = collectMergeGateNativeFacts(t.Context(), nil, nil, "", "", nil)
	require.NoError(t, err)
	require.Empty(t, facts)
}

func TestMergeGateInvalidNativeFilePatternIsNotEmptyPolicy(t *testing.T) {
	_, _, err := mergeGateCurrentGitGuards(t.Context(), &git_model.ProtectedBranch{ProtectedFilePatterns: "["}, nil)
	require.Error(t, err)
	_, _, err = mergeGateCurrentGitGuards(t.Context(), &git_model.ProtectedBranch{}, nil)
	require.NoError(t, err)
}

func TestMergeGateMandatoryFactsWithoutBranchProtection(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	state := func(code string) string {
		t.Helper()
		facts, err := collectMergeGateNativeFacts(t.Context(), pr, actor, repo_model.MergeStyleMerge, "preview", nil)
		require.NoError(t, err)
		for _, fact := range facts {
			if fact.Code == code {
				return fact.State
			}
		}
		t.Fatalf("missing mandatory fact %s", code)
		return ""
	}
	require.Equal(t, "passed", state("unresolved_conversation"))
	review := &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 4, Type: issues_model.ReviewTypeComment}
	require.NoError(t, db.Insert(t.Context(), review))
	require.NoError(t, db.Insert(t.Context(), &issues_model.Comment{IssueID: pr.IssueID, Type: issues_model.CommentTypeComment, ReviewID: review.ID}))
	require.Equal(t, "passed", state("unresolved_conversation"), "ordinary comments are not review conversations")
	thread := &issues_model.Comment{IssueID: pr.IssueID, Type: issues_model.CommentTypeCode, ReviewID: review.ID, TreePath: "file.go", Line: 1}
	require.NoError(t, db.Insert(t.Context(), thread))
	require.Equal(t, "failed", state("unresolved_conversation"))
	require.NoError(t, issues_model.MarkConversation(t.Context(), thread, actor, true))
	require.Equal(t, "passed", state("unresolved_conversation"))
	for _, status := range []struct {
		value issues_model.PullRequestStatus
		code  string
	}{
		{issues_model.PullRequestStatusConflict, "conflict"},
		{issues_model.PullRequestStatusChecking, "checking"},
	} {
		_, err := db.GetEngine(t.Context()).ID(pr.ID).Cols("status").Update(&issues_model.PullRequest{Status: status.value})
		require.NoError(t, err)
		require.Equal(t, "failed", state(status.code))
	}
	_, err := db.GetEngine(t.Context()).ID(pr.ID).Cols("has_merged").Update(&issues_model.PullRequest{HasMerged: true})
	require.NoError(t, err)
	require.Equal(t, "failed", state("merged"))
	_, err = db.GetEngine(t.Context()).ID(pr.IssueID).Cols("is_closed").Update(&issues_model.Issue{IsClosed: true})
	require.NoError(t, err)
	require.Equal(t, "failed", state("closed"))
	dependency := &issues_model.Issue{RepoID: pr.BaseRepoID, PosterID: actor.ID, Title: "open gate dependency"}
	require.NoError(t, db.Insert(t.Context(), dependency))
	require.NoError(t, db.Insert(t.Context(), &issues_model.IssueDependency{IssueID: pr.IssueID, DependencyID: dependency.ID, UserID: actor.ID}))
	require.Equal(t, "failed", state("dependency"))
	_, err = db.GetEngine(t.Context()).ID(dependency.ID).Cols("is_closed").Update(&issues_model.Issue{IsClosed: true})
	require.NoError(t, err)
	require.Equal(t, "passed", state("dependency"))
}

func TestMergeGateNativeUsesPinnedCodeownersAndSigning(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(t.Context()))
	require.NoError(t, pr.LoadIssue(t.Context()))
	_, err := db.GetEngine(t.Context()).ID(pr.IssueID).Cols("poster_id").Update(&issues_model.Issue{PosterID: actor.ID})
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Where("issue_id = ? AND reviewer_id = ?", pr.IssueID, 4).Delete(new(issues_model.Review))
	require.NoError(t, err)
	pb := &git_model.ProtectedBranch{RepoID: pr.BaseRepoID, RuleName: pr.BaseBranch, BlockOnCodeownerReviews: true, RequireSignedCommits: true}
	require.NoError(t, db.Insert(t.Context(), pb))
	dir := t.TempDir()
	require.NoError(t, git.InitRepositoryLocal(t.Context(), dir, false, "sha1"))
	repo := gitrepo.RepositoryUnmanaged(dir)
	commit := func(policy, content string) string {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "CODEOWNERS"), []byte(policy), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "file"), []byte(content), 0o600))
		require.NoError(t, gitcmd.NewCommand("add", "--all").WithRepo(repo).Run(t.Context()))
		require.NoError(t, gitcmd.NewCommand("-c", "user.name=Gate", "-c", "user.email=gate@example.invalid", "-c", "commit.gpgsign=false", "commit", "-m", "test").WithRepo(repo).Run(t.Context()))
		sha, _, err := gitcmd.NewCommand("rev-parse", "HEAD").WithRepo(repo).RunStdString(t.Context())
		require.NoError(t, err)
		return strings.TrimSpace(sha)
	}
	base := commit("file @user4\n", "base")
	head := commit("file @user2\n", "head")
	pinned := &mergeGateGitContext{Repo: repo, BaseSHA: base, HeadSHA: head, Paths: []string{"file"}}
	state := func(ctx context.Context, code string, style repo_model.MergeStyle) string {
		t.Helper()
		facts, err := collectMergeGateNativeFacts(ctx, pr, actor, style, "preview", pinned)
		require.NoError(t, err)
		for _, fact := range facts {
			if fact.Code == code {
				return fact.State
			}
		}
		t.Fatalf("missing fact %s", code)
		return ""
	}
	require.Equal(t, "failed", state(t.Context(), "codeowners_review", repo_model.MergeStyleFastForwardOnly), "the live branch and PR-modified policy cannot replace the pinned base policy")
	review := &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 4, Type: issues_model.ReviewTypeApprove, CommitID: base, Stale: true}
	require.NoError(t, db.Insert(t.Context(), review))
	require.Equal(t, "passed", state(t.Context(), "codeowners_review", repo_model.MergeStyleFastForwardOnly), "native stale behavior remains configuration dependent")
	pb.IgnoreStaleApprovals = true
	_, err = db.GetEngine(t.Context()).ID(pb.ID).Cols("ignore_stale_approvals").Update(pb)
	require.NoError(t, err)
	require.Equal(t, "failed", state(t.Context(), "codeowners_review", repo_model.MergeStyleFastForwardOnly))
	pinned.Paths = []string{"unowned"}
	require.Equal(t, "passed", state(t.Context(), "codeowners_review", repo_model.MergeStyleFastForwardOnly))
	pinned.Paths = nil
	require.Equal(t, "error", state(t.Context(), "codeowners_review", repo_model.MergeStyleFastForwardOnly))
	pinned.Paths = []string{"file"}
	require.Equal(t, "failed", state(t.Context(), "signing_required", repo_model.MergeStyleFastForwardOnly), "unsigned introduced commits remain blocked")
	pinned.HeadSHA = base
	require.Equal(t, "passed", state(t.Context(), "signing_required", repo_model.MergeStyleFastForwardOnly), "signing must verify the pinned range, not the live PR refs")
	pinned.HeadSHA = strings.Repeat("a", 40)
	require.Equal(t, "error", state(t.Context(), "signing_required", repo_model.MergeStyleFastForwardOnly), "missing pinned objects are errors rather than unsigned commits")
}
