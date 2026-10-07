// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	issues_model "gitea.dev/models/issues"
	organization_model "gitea.dev/models/organization"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/git/gitrepo"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func TestMergeGateSensitiveUsesBaseAndCurrentIndependentApproval(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	require.NoError(t, pr.LoadIssue(t.Context()))
	pr.Issue.PosterID = owner.ID
	_, err := db.GetEngine(t.Context()).ID(pr.IssueID).Cols("poster_id").Update(pr.Issue)
	require.NoError(t, err)
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: pr.BaseRepoID}
	role, err := authz_service.CreateRole(t.Context(), owner, scope, authz_service.CreateRoleInput{Name: "Sensitive role"})
	require.NoError(t, err)
	_, err = authz_service.PutProtectedPathRule(t.Context(), owner, scope, 0, authz_service.ProtectedPathRuleInput{Config: []byte(fmt.Sprintf(`{"path_pattern":"sensitive/**","required_role_id":%d,"check_contexts":["security/check"]}`, role.Definition.ID))})
	require.NoError(t, err)
	dir := t.TempDir()
	require.NoError(t, git.InitRepositoryLocal(t.Context(), dir, false, "sha1"))
	facade := gitrepo.RepositoryUnmanaged(dir)
	require.NoError(t, os.Mkdir(filepath.Join(dir, "sensitive"), 0o755))
	commit := func(policy, content string) string {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "CODEOWNERS"), []byte(policy), 0o600))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "sensitive/file"), []byte(content), 0o600))
		require.NoError(t, gitcmd.NewCommand("add", "--all").WithRepo(facade).Run(t.Context()))
		require.NoError(t, gitcmd.NewCommand("-c", "user.name=Gate", "-c", "user.email=gate@example.invalid", "-c", "commit.gpgsign=false", "commit", "-m", "test").WithRepo(facade).Run(t.Context()))
		sha, _, err := gitcmd.NewCommand("rev-parse", "HEAD").WithRepo(facade).RunStdString(t.Context())
		require.NoError(t, err)
		return strings.TrimSpace(sha)
	}
	base := commit("sensitive/.* @user4\n", "base")
	head := commit("sensitive/.* @user2\n", "head")
	repo, err := git.OpenRepositoryLocal(t.Context(), dir)
	require.NoError(t, err)
	defer repo.Close()
	collect := func() mergeGateSensitiveFacts {
		t.Helper()
		result, err := collectMergeGateSensitivePaths(t.Context(), pr, repo, base, head, base)
		require.NoError(t, err)
		require.Len(t, result.Facts, 1)
		require.Len(t, result.Contexts, 1)
		require.Equal(t, "security/check", result.Contexts[0].Context)
		return result
	}
	require.Equal(t, "failed", collect().Facts[0].State)
	review := &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 4, Type: issues_model.ReviewTypeApprove, CommitID: base}
	require.NoError(t, db.Insert(t.Context(), review))
	require.Equal(t, "failed", collect().Facts[0].State)
	review.ID = 0
	review.CommitID = head
	require.NoError(t, db.Insert(t.Context(), review))
	require.Equal(t, "passed", collect().Facts[0].State, "base CODEOWNERS, not the PR author's replacement")
	for _, column := range []string{"stale", "dismissed"} {
		_, err := db.GetEngine(t.Context()).Table(new(issues_model.Review)).ID(review.ID).Update(map[string]any{column: true})
		require.NoError(t, err)
		require.Equal(t, "failed", collect().Facts[0].State, "old approval must not revive")
		_, err = db.GetEngine(t.Context()).Table(new(issues_model.Review)).ID(review.ID).Update(map[string]any{column: false})
		require.NoError(t, err)
	}
	review.ID = 0
	review.ReviewerID = owner.ID
	require.NoError(t, db.Insert(t.Context(), review))
	review.ID = 0
	review.ReviewerID = 4
	review.Type = issues_model.ReviewTypeReject
	require.NoError(t, db.Insert(t.Context(), review))
	require.Equal(t, "failed", collect().Facts[0].State, "author approval cannot replace an independent owner")
	_, err = db.GetEngine(t.Context()).ID(review.ID).Cols("type").Update(&issues_model.Review{Type: issues_model.ReviewTypeApprove})
	require.NoError(t, err)
	require.Equal(t, "passed", collect().Facts[0].State)
	for _, column := range []string{"is_active", "prohibit_login"} {
		invalid := column == "prohibit_login"
		_, err = db.GetEngine(t.Context()).Table(new(user_model.User)).ID(4).Update(map[string]any{column: invalid})
		require.NoError(t, err)
		require.Equal(t, "failed", collect().Facts[0].State, column)
		_, err = db.GetEngine(t.Context()).Table(new(user_model.User)).ID(4).Update(map[string]any{column: !invalid})
		require.NoError(t, err)
	}
	_, err = db.GetEngine(t.Context()).ID(pr.BaseRepoID).Cols("is_private").Update(&repo_model.Repository{IsPrivate: true})
	require.NoError(t, err)
	require.Equal(t, "failed", collect().Facts[0].State, "reviewer must still have current visibility")
	_, err = db.GetEngine(t.Context()).ID(4).Cols("is_admin").Update(&user_model.User{IsAdmin: true})
	require.NoError(t, err)
	setting.EnterpriseWeCom.Enabled = true
	require.Equal(t, "failed", collect().Facts[0].State, "revoked enterprise administrator must not bypass current visibility")
	_, err = collectMergeGateSensitivePaths(t.Context(), pr, repo, strings.Repeat("f", 40), head, base)
	require.Error(t, err)
	invalidBase := commit("sensitive/.* @user4\n[ @user4\n", "trusted invalid policy")
	invalidHead := commit("sensitive/.* @user4\n", "updated content")
	_, err = collectMergeGateSensitivePaths(t.Context(), pr, repo, invalidBase, invalidHead, invalidBase)
	require.Error(t, err, "invalid trusted patterns cannot be silently dropped")
}

func TestMergeGateCodeownerCoverageIsBoundedAndCancellable(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := mergeGateCodeownerCoverage(ctx, []string{"sensitive/file"}, nil, nil)
	require.ErrorIs(t, err, context.Canceled)
	_, err = mergeGateCodeownerCoverage(t.Context(), []string{"sensitive/file"}, make([]*issues_model.CodeOwnerRule, 1025), nil)
	require.Error(t, err)
	result, err := mergeGateCodeownerCoverage(t.Context(), []string{"sensitive/file", "sensitive/file"}, nil, nil)
	require.NoError(t, err)
	require.Equal(t, map[string]bool{"sensitive/file": false}, result)
	owners, err := issues_model.GetCodeOwnersForSensitivePaths(t.Context(), "a @user4\nb @user5\n")
	require.NoError(t, err)
	result, err = mergeGateCodeownerCoverage(t.Context(), []string{"a", "b", "unowned"}, owners, map[int64]bool{4: true})
	require.NoError(t, err)
	require.Equal(t, map[string]bool{"a": true, "b": false, "unowned": false}, result)
	owners, err = issues_model.GetCodeOwnersForSensitivePaths(t.Context(), ".* @user4\na @missing-code-owner\n")
	require.NoError(t, err)
	result, err = mergeGateCodeownerCoverage(t.Context(), []string{"a", "b"}, owners, map[int64]bool{4: true})
	require.NoError(t, err)
	require.Equal(t, map[string]bool{"a": false, "b": true}, result, "a matching unowned rule cannot disappear behind another approved owner")
	owners, err = issues_model.GetCodeOwnersForSensitivePaths(t.Context(), ".* @org3/team1\n")
	require.NoError(t, err)
	require.Len(t, owners, 1)
	require.Len(t, owners[0].Teams, 1)
	result, err = mergeGateCodeownerCoverage(t.Context(), []string{"a"}, owners, map[int64]bool{4: true})
	require.NoError(t, err)
	require.True(t, result["a"])
	_, err = db.GetEngine(t.Context()).Where("uid=? AND team_id=?", 4, 2).Delete(new(organization_model.TeamUser))
	require.NoError(t, err)
	result, err = mergeGateCodeownerCoverage(t.Context(), []string{"a"}, owners, map[int64]bool{4: true})
	require.NoError(t, err)
	require.False(t, result["a"], "cached CODEOWNERS team objects must not keep revoked members eligible")
}

func TestMergeGateSensitiveRoleApprovalsRemainPerRule(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	_, err := db.GetEngine(t.Context()).ID(pr.IssueID).Cols("poster_id").Update(&issues_model.Issue{PosterID: owner.ID})
	require.NoError(t, err)
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: pr.BaseRepoID}
	var roleIDs []int64
	for i := range 2 {
		role, err := authz_service.CreateRole(t.Context(), owner, scope, authz_service.CreateRoleInput{Name: fmt.Sprintf("Gate role %d", i)})
		require.NoError(t, err)
		roleIDs = append(roleIDs, role.Definition.ID)
		_, err = authz_service.PutProtectedPathRule(t.Context(), owner, scope, 0, authz_service.ProtectedPathRuleInput{Config: []byte(fmt.Sprintf(`{"path_pattern":"sensitive/**","required_role_id":%d,"check_contexts":["security/check%d"]}`, role.Definition.ID, i))})
		require.NoError(t, err)
	}
	dir := t.TempDir()
	require.NoError(t, git.InitRepositoryLocal(t.Context(), dir, false, "sha1"))
	facade := gitrepo.RepositoryUnmanaged(dir)
	require.NoError(t, os.Mkdir(filepath.Join(dir, "sensitive"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "CODEOWNERS"), []byte("sensitive/.* @user2\n"), 0o600))
	commit := func(content string) string {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, "sensitive/file"), []byte(content), 0o600))
		require.NoError(t, gitcmd.NewCommand("add", "--all").WithRepo(facade).Run(t.Context()))
		require.NoError(t, gitcmd.NewCommand("-c", "user.name=Gate", "-c", "user.email=gate@example.invalid", "-c", "commit.gpgsign=false", "commit", "-m", "test").WithRepo(facade).Run(t.Context()))
		sha, _, err := gitcmd.NewCommand("rev-parse", "HEAD").WithRepo(facade).RunStdString(t.Context())
		require.NoError(t, err)
		return strings.TrimSpace(sha)
	}
	base, head := commit("base"), commit("head")
	repo, err := git.OpenRepositoryLocal(t.Context(), dir)
	require.NoError(t, err)
	defer repo.Close()
	require.NoError(t, db.Insert(t.Context(), &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 2, Type: issues_model.ReviewTypeApprove, CommitID: head}, &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 4, Type: issues_model.ReviewTypeApprove, CommitID: head}))
	collect := func() mergeGateSensitiveFacts {
		t.Helper()
		result, err := collectMergeGateSensitivePaths(t.Context(), pr, repo, base, head, base)
		require.NoError(t, err)
		require.Len(t, result.Facts, 2)
		require.Len(t, result.Contexts, 2)
		return result
	}
	result := collect()
	require.Equal(t, "failed", result.Facts[0].State, "author-only CODEOWNERS is not an exemption")
	require.Equal(t, "failed", result.Facts[1].State)
	bind := func(roleID int64) *authz_model.SubjectRoleBinding {
		t.Helper()
		binding, _, err := authz_service.PutBinding(t.Context(), owner, scope, authz_service.BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: roleID})
		require.NoError(t, err)
		return binding
	}
	first := bind(roleIDs[0])
	result = collect()
	require.Equal(t, "passed", result.Facts[0].State)
	require.Equal(t, "failed", result.Facts[1].State, "one role cannot satisfy another rule")
	bind(roleIDs[1])
	result = collect()
	require.Equal(t, "passed", result.Facts[1].State)
	head = commit("new current head")
	result = collect()
	for _, fact := range result.Facts {
		require.Equal(t, "failed", fact.State, "new head invalidates both old role approvals")
	}
	_, err = db.GetEngine(t.Context()).Where("issue_id=?", pr.IssueID).Cols("commit_id").Update(&issues_model.Review{CommitID: head})
	require.NoError(t, err)
	result = collect()
	for _, fact := range result.Facts {
		require.Equal(t, "passed", fact.State)
	}
	checks := authz.EvaluateMergeGateContexts(pr.BaseRepoID, head, result.Contexts, nil)
	decision := authz.EvaluateMergeGate(authz.MergeGateInput{Mode: "enforce", Phase: "preview", Facts: append(result.Facts, checks...)})
	require.Equal(t, "deny", decision.CandidateDecision, "role approvals do not waive rule checks")
	require.NoError(t, authz_service.DeleteBinding(t.Context(), owner, scope, first.ID))
	require.Equal(t, "failed", collect().Facts[0].State, "revoking the binding invalidates the approval")
	bind(roleIDs[0])
	require.NoError(t, os.WriteFile(filepath.Join(dir, "CODEOWNERS"), []byte("sensitive/.* @/Owners\n"), 0o600))
	badBase, badHead := commit("bad base policy"), commit("bad head")
	_, err = db.GetEngine(t.Context()).Where("issue_id=?", pr.IssueID).Cols("commit_id").Update(&issues_model.Review{CommitID: badHead})
	require.NoError(t, err)
	_, err = collectMergeGateSensitivePaths(t.Context(), pr, repo, badBase, badHead, badBase)
	require.Error(t, err, "valid role approvals cannot conceal malformed trusted CODEOWNERS")
}
