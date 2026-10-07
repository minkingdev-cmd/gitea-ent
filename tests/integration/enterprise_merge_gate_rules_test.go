// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
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
	authz_service "gitea.dev/services/enterpriseauthz"
	repo_service "gitea.dev/services/repository"
	files_service "gitea.dev/services/repository/files"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseMergeGateConversationRoots(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	review := &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 2, Type: issues_model.ReviewTypeComment}
	require.NoError(t, db.Insert(t.Context(), review))
	root := &issues_model.Comment{IssueID: pr.IssueID, ReviewID: review.ID, Type: issues_model.CommentTypeCode, TreePath: "gate-thread.go", Line: 1}
	require.NoError(t, db.Insert(t.Context(), root))
	require.NoError(t, db.Insert(t.Context(), &issues_model.Comment{IssueID: pr.IssueID, ReviewID: review.ID, Type: issues_model.CommentTypeCode, TreePath: root.TreePath, Line: root.Line}))
	unresolved, err := issues_model.HasUnresolvedReviewConversation(t.Context(), pr.IssueID)
	require.NoError(t, err)
	require.True(t, unresolved)
	require.NoError(t, issues_model.MarkConversation(t.Context(), root, &user_model.User{ID: 2}, true))
	unresolved, err = issues_model.HasUnresolvedReviewConversation(t.Context(), pr.IssueID)
	require.NoError(t, err)
	require.False(t, unresolved)
	otherReview := &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 4, Type: issues_model.ReviewTypeComment}
	require.NoError(t, db.Insert(t.Context(), otherReview))
	require.NoError(t, db.Insert(t.Context(), &issues_model.Comment{IssueID: pr.IssueID, ReviewID: otherReview.ID, Type: issues_model.CommentTypeCode, TreePath: root.TreePath, Line: root.Line}))
	unresolved, err = issues_model.HasUnresolvedReviewConversation(t.Context(), pr.IssueID)
	require.NoError(t, err)
	require.True(t, unresolved)
}

func TestEnterpriseMergeGateRulesAPI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	role, err := authz_service.CreateRole(t.Context(), owner, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}, authz_service.CreateRoleInput{Name: "API gate reviewer"})
	require.NoError(t, err)
	session := loginUser(t, "user2")
	write := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	read := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadRepository)
	reader := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth_model.AccessTokenScopeWriteRepository)
	publicOnly := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeWriteRepository)
	wrongScope := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadOrganization)
	root := "/api/v1/repos/user2/repo1/enterprise/authz/protected-path-rules"
	input := map[string]any{"config": map[string]any{"path_pattern": "k8s/**", "required_role_id": role.Definition.ID}, "expected_revision": 0}
	var rule struct{ ID, Revision int64 }
	DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", root, input).AddTokenAuth(write), http.StatusCreated), &rule)
	require.Positive(t, rule.ID)
	require.EqualValues(t, 1, rule.Revision)
	path := fmt.Sprintf("%s/%d", root, rule.ID)
	MakeRequest(t, NewRequest(t, "GET", root), http.StatusUnauthorized)
	MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(reader), http.StatusForbidden)
	MakeRequest(t, NewRequestWithJSON(t, "POST", root, input).AddTokenAuth(read), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "GET", root).AddTokenAuth(publicOnly), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "GET", root).AddTokenAuth(wrongScope), http.StatusForbidden)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", path, input).AddTokenAuth(write), http.StatusConflict)
	input["expected_revision"] = 1
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", path, input).AddTokenAuth(write), http.StatusOK)
	response := MakeRequest(t, NewRequest(t, "GET", root).AddTokenAuth(read), http.StatusOK)
	require.Equal(t, "1", response.Header().Get("X-Total-Count"))
	MakeRequest(t, NewRequest(t, "GET", root+"?limit=101").AddTokenAuth(read), http.StatusUnprocessableEntity)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo2/enterprise/authz/protected-path-rules/"+strconv.FormatInt(rule.ID, 10)).AddTokenAuth(write), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "DELETE", path).AddTokenAuth(write), http.StatusUnprocessableEntity)
	MakeRequest(t, NewRequest(t, "DELETE", path+"?expected_revision=1").AddTokenAuth(write), http.StatusNoContent)
	MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(read), http.StatusNotFound)
	setting.Audit.RecordOutput = setting.AuditRecordOutputDisabled
	input["expected_revision"] = 0
	MakeRequest(t, NewRequestWithJSON(t, "POST", root, input).AddTokenAuth(write), http.StatusServiceUnavailable)
	setting.Audit.RecordOutput = setting.AuditRecordOutputDatabase
	setting.EnterpriseMergeGate.Enabled = false
	MakeRequest(t, NewRequest(t, "GET", root).AddTokenAuth(read), http.StatusNotFound)
}

func TestEnterpriseMergeGateScopeRulesAPI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	role, err := authz_service.CreateRole(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeSystem}, authz_service.CreateRoleInput{Name: "Scope gate reviewer"})
	require.NoError(t, err)
	adminSession := loginUser(t, "user1")
	adminWrite := getTokenForLoggedInUser(t, adminSession, auth_model.AccessTokenScopeWriteAdmin)
	adminRead := getTokenForLoggedInUser(t, adminSession, auth_model.AccessTokenScopeReadAdmin)
	ownerSession := loginUser(t, "user2")
	orgWrite := getTokenForLoggedInUser(t, ownerSession, auth_model.AccessTokenScopeWriteOrganization)
	orgRead := getTokenForLoggedInUser(t, ownerSession, auth_model.AccessTokenScopeReadOrganization)
	for _, target := range []struct{ root, write, read string }{
		{"/api/v1/admin/enterprise/authz/protected-path-rules", adminWrite, adminRead},
		{"/api/v1/orgs/org3/enterprise/authz/protected-path-rules", orgWrite, orgRead},
	} {
		input := map[string]any{"config": map[string]any{"path_pattern": ".gitea/**", "required_role_id": role.Definition.ID}, "expected_revision": 0}
		var rule struct{ ID, Revision int64 }
		DecodeJSON(t, MakeRequest(t, NewRequestWithJSON(t, "POST", target.root, input).AddTokenAuth(target.write), http.StatusCreated), &rule)
		MakeRequest(t, NewRequest(t, "GET", target.root).AddTokenAuth(target.read), http.StatusOK)
		MakeRequest(t, NewRequestWithJSON(t, "POST", target.root, input).AddTokenAuth(target.read), http.StatusForbidden)
		MakeRequest(t, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d?expected_revision=1", target.root, rule.ID)).AddTokenAuth(target.write), http.StatusNoContent)
	}
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/enterprise/authz/protected-path-rules").AddTokenAuth(orgWrite), http.StatusForbidden)
	adminSession.MakeRequest(t, NewRequest(t, "GET", "/-/admin/enterprise/authz/scopes/system/roles"), http.StatusOK)
	_, err = db.GetEngine(t.Context()).ID(1).Cols("is_admin").Update(&user_model.User{IsAdmin: false})
	require.NoError(t, err)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/admin/enterprise/authz/protected-path-rules").AddTokenAuth(adminRead), http.StatusForbidden)
	adminSession.MakeRequest(t, NewRequest(t, "GET", "/-/admin/enterprise/authz/scopes/system/roles"), http.StatusForbidden)
	_, err = db.GetEngine(t.Context()).ID(2).Cols("prohibit_login").Update(&user_model.User{ProhibitLogin: true})
	require.NoError(t, err)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/enterprise/authz/protected-path-rules").AddTokenAuth(orgRead), http.StatusForbidden)
}

func TestEnterpriseMergeGateHistoryAPI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	snapshot := `{"snapshot_version":1}`
	record := &authz_model.MergeGateEvaluation{OperationID: "history-api", Attempt: 1, Phase: "admission", RepoID: pr.BaseRepoID, PullID: pr.ID, IssueID: pr.IssueID, ActorID: 2, Source: "web", Mode: "enforce", HeadSHA: strings.Repeat("a", 40), BaseSHA: strings.Repeat("b", 40), CandidateDecision: "deny", AdmissionDecision: "deny", ExecutionState: "not_started", SnapshotVersion: 1, SnapshotJSON: snapshot, SnapshotHash: fmt.Sprintf("%x", sha256.Sum256([]byte(snapshot))), ReasonsJSON: `[{"code":"required_check","source":"feature","state":"missing"}]`}
	_, err := authz_model.InsertMergeGateEvaluation(t.Context(), record)
	require.NoError(t, err)
	token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeReadRepository)
	reader := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth_model.AccessTokenScopeReadRepository)
	root := "/api/v1/repos/user2/repo1/enterprise/merge-gate/3/evaluations"
	response := MakeRequest(t, NewRequest(t, "GET", root).AddTokenAuth(token), http.StatusOK)
	require.Equal(t, "1", response.Header().Get("X-Total-Count"))
	var rows []struct {
		ID                int64
		Phase             string
		AdmissionDecision string `json:"admission_decision"`
	}
	DecodeJSON(t, response, &rows)
	require.Len(t, rows, 1)
	require.Equal(t, record.ID, rows[0].ID)
	require.Equal(t, "deny", rows[0].AdmissionDecision)
	path := root + "/" + strconv.FormatInt(record.ID, 10)
	MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), http.StatusOK)
	MakeRequest(t, NewRequest(t, "GET", root), http.StatusUnauthorized)
	MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(reader), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "GET", strings.Replace(path, "/3/", "/2/", 1)).AddTokenAuth(token), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "GET", root+"?limit=101").AddTokenAuth(token), http.StatusUnprocessableEntity)
	public := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeReadRepository)
	MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(public), http.StatusForbidden)
	setting.EnterpriseMergeGate.Enabled = false
	MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), http.StatusNotFound)
}

func TestEnterpriseMergeGatePreviewIsSafeAndNotAdmission(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{ScopeType: authz_model.ScopeSystem, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["private/security/context"]}`}))
	token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeReadRepository)
	root := "/api/v1/repos/user2/repo1/enterprise/merge-gate/3"
	_, err := db.GetEngine(t.Context()).ID(1).Cols("internal_usage").Update(&repo_model.Repository{InternalUsage: repo_model.InternalUsageCargoIndex})
	require.NoError(t, err)
	auditBefore, err := db.GetEngine(t.Context()).Count(new(audit_model.Event))
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: 1, RuleName: "master", ProtectedFilePatterns: "README.md"}))
	before, err := db.GetEngine(t.Context()).Count(new(authz_model.MergeGateEvaluation))
	require.NoError(t, err)
	response := MakeRequest(t, NewRequest(t, "GET", root).AddTokenAuth(token), http.StatusOK)
	body := response.Body.String()
	var preview struct {
		PreviewOnly       bool   `json:"preview_only"`
		CandidateDecision string `json:"candidate_decision"`
		AdmissionDecision string `json:"admission_decision"`
		HeadSHA           string `json:"head_sha"`
		Reasons           []struct {
			Code   string
			Source string
			State  string
		}
	}
	DecodeJSON(t, response, &preview)
	require.True(t, preview.PreviewOnly)
	require.Equal(t, "deny", preview.CandidateDecision)
	require.Equal(t, "not_admitted", preview.AdmissionDecision)
	require.Len(t, preview.HeadSHA, 40)
	require.Contains(t, body, "required_check")
	require.Contains(t, body, "protected_files")
	for _, sensitive := range []string{"private/security/context", "reference_id", "snapshot_hash", "bypass_reason", "required_role_id", "creator_id"} {
		require.NotContains(t, body, sensitive)
	}
	after, err := db.GetEngine(t.Context()).Count(new(authz_model.MergeGateEvaluation))
	require.NoError(t, err)
	require.Equal(t, before, after)
	auditAfter, err := db.GetEngine(t.Context()).Count(new(audit_model.Event))
	require.NoError(t, err)
	require.Equal(t, auditBefore, auditAfter, "preview must not write feature or merge admission audits")
	MakeRequest(t, NewRequest(t, "GET", root), http.StatusUnauthorized)
	MakeRequest(t, NewRequest(t, "GET", root+"?style=arbitrary").AddTokenAuth(token), http.StatusUnprocessableEntity)
	outsider := getUserToken(t, "user5", auth_model.AccessTokenScopeReadRepository)
	_, err = db.GetEngine(t.Context()).ID(1).Cols("is_private").Update(&repo_model.Repository{IsPrivate: true})
	require.NoError(t, err)
	MakeRequest(t, NewRequest(t, "GET", root).AddTokenAuth(outsider), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "GET", root).AddTokenAuth(token), http.StatusOK)
	setting.EnterpriseMergeGate.Enabled = false
	MakeRequest(t, NewRequest(t, "GET", root).AddTokenAuth(token), http.StatusNotFound)
}

func TestEnterpriseMergeGatePreviewForkAndAGit(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	base := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: pr.BaseRepoID})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	forkOwner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	fork, err := repo_service.ForkRepository(t.Context(), actor, forkOwner, repo_service.ForkRepoOptions{BaseRepo: base, Name: "gate-preview-fork"})
	require.NoError(t, err)
	token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeReadRepository)
	root := "/api/v1/repos/user2/repo1/enterprise/merge-gate/3"
	preview := func() struct {
		HeadSHA           string `json:"head_sha"`
		BaseSHA           string `json:"base_sha"`
		CandidateDecision string `json:"candidate_decision"`
	} {
		t.Helper()
		var result struct {
			HeadSHA           string `json:"head_sha"`
			BaseSHA           string `json:"base_sha"`
			CandidateDecision string `json:"candidate_decision"`
		}
		DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", root).AddTokenAuth(token), http.StatusOK), &result)
		return result
	}
	original := preview()
	require.NotEqual(t, "error", original.CandidateDecision)
	require.Len(t, original.HeadSHA, 40)
	_, err = db.GetEngine(t.Context()).ID(pr.ID).Cols("head_repo_id").Update(&issues_model.PullRequest{HeadRepoID: fork.ID})
	require.NoError(t, err)
	forked := preview()
	require.Equal(t, original, forked, "fork fetch must use the same trusted base/head objects")
	facade := gitrepo.RepositoryUnmanaged(gitrepo.RepoLocalPath(base.CodeStorageRepo()))
	require.NoError(t, gitcmd.NewCommand("update-ref").AddDynamicArguments(pr.GetGitHeadRefName(), original.HeadSHA).WithRepo(facade).Run(t.Context()))
	_, err = db.GetEngine(t.Context()).ID(pr.ID).Cols("head_repo_id", "flow", "head_branch").Update(&issues_model.PullRequest{HeadRepoID: base.ID, Flow: issues_model.PullRequestFlowAGit, HeadBranch: "user2/nonexistent-head-branch"})
	require.NoError(t, err)
	agit := preview()
	require.Equal(t, original, agit, "AGit fetch must use the hidden pull ref, not a nonexistent branch")
	require.NoError(t, gitcmd.NewCommand("update-ref", "-d").AddDynamicArguments(pr.GetGitHeadRefName()).WithRepo(facade).Run(t.Context()))
	require.Equal(t, "error", preview().CandidateDecision, "missing AGit objects are not an empty successful diff")
	require.False(t, pr.HasMerged)
	require.False(t, git.IsEmptyCommitID(original.HeadSHA))
}

func TestEnterpriseMergeGateRoleApprovalDoesNotWaiveNativeCodeowners(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		featureTestMode(t)
		t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
		base := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: pr.BaseRepoID})
		actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		_, err := files_service.ChangeRepoFiles(t.Context(), base, actor, &files_service.ChangeRepoFilesOptions{OldBranch: pr.BaseBranch, Files: []*files_service.ChangeRepoFile{{Operation: "create", TreePath: "CODEOWNERS", ContentReader: strings.NewReader("README.md @user5\n")}}})
		require.NoError(t, err)
		_, err = db.GetEngine(t.Context()).ID(pr.ID).Cols("status").Update(&issues_model.PullRequest{Status: issues_model.PullRequestStatusMergeable})
		require.NoError(t, err)
		scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: base.ID}
		role, err := authz_service.CreateRole(t.Context(), actor, scope, authz_service.CreateRoleInput{Name: "Independent path approver"})
		require.NoError(t, err)
		_, _, err = authz_service.PutBinding(t.Context(), actor, scope, authz_service.BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: role.Definition.ID})
		require.NoError(t, err)
		_, err = authz_service.PutProtectedPathRule(t.Context(), actor, scope, 0, authz_service.ProtectedPathRuleInput{Config: []byte(fmt.Sprintf(`{"path_pattern":"README.md","required_role_id":%d}`, role.Definition.ID))})
		require.NoError(t, err)
		require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: base.ID, RuleName: pr.BaseBranch, BlockOnCodeownerReviews: true}))
		facade := gitrepo.RepositoryUnmanaged(gitrepo.RepoLocalPath(base.CodeStorageRepo()))
		head, _, err := gitcmd.NewCommand("rev-parse").AddDynamicArguments(git.BranchPrefix + pr.HeadBranch).WithRepo(facade).RunStdString(t.Context())
		require.NoError(t, err)
		require.NoError(t, db.Insert(t.Context(), &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 4, Type: issues_model.ReviewTypeApprove, CommitID: strings.TrimSpace(head)}))
		token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteRepository)
		root := "/api/v1/repos/user2/repo1/enterprise/merge-gate/3"
		response := MakeRequest(t, NewRequest(t, "GET", root).AddTokenAuth(token), http.StatusOK)
		require.Contains(t, response.Body.String(), `"code":"codeowners_review"`)
		require.NotContains(t, response.Body.String(), `"code":"sensitive_path_approval"`, "the designated current role satisfies only the path rule")
		require.NoError(t, db.Insert(t.Context(), &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 5, Type: issues_model.ReviewTypeApprove, CommitID: strings.TrimSpace(head)}))
		response = MakeRequest(t, NewRequest(t, "GET", root).AddTokenAuth(token), http.StatusOK)
		require.NotContains(t, response.Body.String(), `"code":"codeowners_review"`)
		require.NotContains(t, response.Body.String(), `"code":"sensitive_path_approval"`)
	})
}
