// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

const shadowPullPrivate = "secret-token-OAuth-code-private@example.com/private/path"

type shadowPullCheck func(string, *RequestWrapper, *TestSession, int, authz.Action, string, int64, int64) *httptest.ResponseRecorder

func shadowPullResponse(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	if strings.Contains(response.Header().Get("Content-Type"), "text/html") {
		doc := NewHTMLParser(t, strings.NewReader(shadowReadHTML(t, response.Body.String())))
		doc.Find("relative-time").SetAttr("datetime", "").SetText("")
		output, err := doc.doc.Html()
		require.NoError(t, err)
		return output
	}
	if !strings.Contains(response.Header().Get("Content-Type"), "application/json") {
		return response.Body.String()
	}
	var value any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &value))
	var normalize func(any)
	normalize = func(v any) {
		switch v := v.(type) {
		case map[string]any:
			for k, item := range v {
				switch k {
				case "created_at", "updated_at", "submitted_at", "last_login":
					v[k] = ""
				default:
					normalize(item)
				}
			}
		case []any:
			for _, item := range v {
				normalize(item)
			}
		}
	}
	normalize(value)
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return string(encoded)
}

func prepareShadowPullEnv(t *testing.T) func() {
	t.Helper()
	cleanup := tests.PrepareTestEnv(t)
	if setting.Database.Type.IsSQLite3() { // fixture DELETE 不重置自增序列。
		for _, table := range []string{"comment", "issue", "pull_request", "review"} {
			_, err := db.Exec(context.WithValue(t.Context(), db.ContextKeyTestFixtures, true), "UPDATE sqlite_sequence SET seq = (SELECT COALESCE(MAX(id),0) FROM `"+table+"`) WHERE name = ?", table)
			require.NoError(t, err)
		}
	}
	return cleanup
}

func testShadowPullModes(t *testing.T, run func(*testing.T, shadowPullCheck)) {
	t.Helper()
	baseline := map[string]string{}
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("shadow=%t", enabled), func(t *testing.T) {
			defer prepareShadowPullEnv(t)()
			defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, enabled)()
			defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
			defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
			defer test.MockVariableValue(&setting.Other.ShowFooterTemplateLoadTime, false)()
			check := func(name string, req *RequestWrapper, session *TestSession, status int, action authz.Action, outcome string, actorID, repoID int64) *httptest.ResponseRecorder {
				t.Helper()
				if !strings.HasPrefix(req.URL.Path, "/api/") && req.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
					require.NoError(t, req.ParseForm())
				}
				before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: action})
				response := session.MakeRequest(t, req, status)
				body := shadowPullResponse(t, response)
				if !enabled {
					baseline[name] = body
					require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: action}))
					return response
				}
				if strings.Contains(response.Header().Get("Content-Type"), "application/json") {
					require.JSONEq(t, baseline[name], body, name)
				} else {
					require.Equal(t, baseline[name], body, name)
				}
				require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{Action: action}), name)
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: action}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
				require.Equal(t, actorID, record.ActorID)
				require.Equal(t, repoID, record.RepoID)
				require.Equal(t, outcome, record.NativeOutcome, name)
				if outcome == "denied" {
					require.Contains(t, []string{"operation", "authorization"}, record.NativeStage)
				} else {
					require.Equal(t, "operation", record.NativeStage)
				}
				source := "web"
				if strings.HasPrefix(req.URL.Path, "/api/") {
					source = "api"
				}
				require.Equal(t, source, record.RequestSource)
				require.NotContains(t, record.SnapshotJSON, shadowPullPrivate)
				event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, unittest.Cond("metadata LIKE ?", "%"+record.ObservationID+"%"))
				require.NotContains(t, event.Metadata, shadowPullPrivate)
				return response
			}
			run(t, check)
		})
	}
}

func TestEnterpriseAuthzShadowPullReviewAPIMutations(t *testing.T) {
	testShadowPullModes(t, func(t *testing.T, check shadowPullCheck) {
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		const base = "/api/v1/repos/user2/repo1/pulls/3"
		review := DecodeJSON(t, check("create", NewRequestWithJSON(t, "POST", base+"/reviews", api.CreatePullReviewOptions{Body: shadowPullPrivate, Comments: []api.CreatePullReviewComment{{Path: "README.md", Body: shadowPullPrivate, NewLineNum: 1}, {Path: "README.md", Body: "second", NewLineNum: 2}}}).AddTokenAuth(token), session, 200, authz.ReviewPullRequest, "success", 2, 1), &api.PullReview{})
		require.Equal(t, api.ReviewStatePending, review.State)
		require.Equal(t, 2, review.CodeCommentsCount)
		path := fmt.Sprintf("%s/reviews/%d", base, review.ID)
		check("submit", NewRequestWithJSON(t, "POST", path, api.SubmitPullReviewOptions{Event: api.ReviewStateApproved}).AddTokenAuth(token), session, 200, authz.ReviewPullRequest, "success", 2, 1)
		check("dismiss", NewRequestWithJSON(t, "POST", path+"/dismissals", api.DismissPullReviewOptions{Message: shadowPullPrivate}).AddTokenAuth(token), session, 200, authz.ReviewPullRequest, "success", 2, 1)
		check("undismiss", NewRequest(t, "POST", path+"/undismissals").AddTokenAuth(token), session, 200, authz.ReviewPullRequest, "success", 2, 1)
		comment := unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{ReviewID: review.ID, Line: 1, Type: issues_model.CommentTypeCode})
		check("reply", NewRequestWithJSON(t, "POST", fmt.Sprintf("%s/comments/%d/replies", base, comment.ID), api.CreatePullReviewCommentReplyOptions{Body: shadowPullPrivate}).AddTokenAuth(token), session, 201, authz.ReviewPullRequest, "success", 2, 1)
		commentPath := fmt.Sprintf("/api/v1/repos/user2/repo1/pulls/comments/%d", comment.ID)
		check("resolve", NewRequest(t, "POST", commentPath+"/resolve").AddTokenAuth(token), session, 204, authz.ReviewPullRequest, "success", 2, 1)
		check("unresolve", NewRequest(t, "POST", commentPath+"/unresolve").AddTokenAuth(token), session, 204, authz.ReviewPullRequest, "success", 2, 1)
		before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ReviewPullRequest})
		session.MakeRequest(t, NewRequest(t, "GET", base+"/reviews").AddTokenAuth(token), 200)
		session.MakeRequest(t, NewRequest(t, "GET", path+"/comments").AddTokenAuth(token), 200)
		require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ReviewPullRequest}))
		check("delete", NewRequest(t, "DELETE", path).AddTokenAuth(token), session, 204, authz.ReviewPullRequest, "success", 2, 1)
		unittest.AssertNotExistsBean(t, &issues_model.Review{ID: review.ID})
	})
}

func TestEnterpriseAuthzShadowPullCreation(t *testing.T) {
	for _, web := range []bool{false, true} {
		t.Run(fmt.Sprintf("web=%t", web), func(t *testing.T) {
			testShadowPullModes(t, func(t *testing.T, check shadowPullCheck) {
				session := loginUser(t, "user13")
				token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
				before := unittest.GetCount(t, &issues_model.PullRequest{BaseRepoID: 10})
				req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user12/repo10/pulls", api.CreatePullRequestOption{Head: "user13:master", Base: "master", Title: shadowPullPrivate}).AddTokenAuth(token)
				status := 201
				if web {
					req = NewRequestWithValues(t, "POST", "/user12/repo10/compare/master...user13:master", map[string]string{"title": shadowPullPrivate})
					status = 200
				}
				check("create", req, session, status, authz.CreatePullRequest, "success", 13, 10)
				require.Equal(t, before+1, unittest.GetCount(t, &issues_model.PullRequest{BaseRepoID: 10}))
				pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: 10, HeadRepoID: 11, HeadBranch: "master", BaseBranch: "master"})
				issue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: pr.IssueID})
				require.Equal(t, int64(13), issue.PosterID)
				require.Equal(t, shadowPullPrivate, issue.Title)
			})
		})
	}
}

func TestEnterpriseAuthzShadowReviewerCannotOverrideNativeGuards(t *testing.T) {
	testShadowPullModes(t, func(t *testing.T, check shadowPullCheck) {
		owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
		enabled := setting.EnterpriseAuthz.Enabled
		setting.EnterpriseAuthz.Enabled = true
		role, err := authz_service.CreateRole(t.Context(), owner, scope, authz_service.CreateRoleInput{Name: "Reviewer", Permissions: &[]authz_service.PermissionInput{{Action: authz.ReviewPullRequest, Effect: "allow"}}})
		require.NoError(t, err)
		for _, id := range []int64{1, 4} {
			_, _, err := authz_service.PutBinding(t.Context(), owner, scope, authz_service.BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: id, RoleID: role.Definition.ID})
			require.NoError(t, err)
		}
		setting.EnterpriseAuthz.Enabled = enabled
		session := loginUser(t, "user1")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		reviews := unittest.GetCount(t, &issues_model.Review{})
		check("api-self", NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/reviews", api.CreatePullReviewOptions{Event: api.ReviewStateApproved}).AddTokenAuth(token), session, 422, authz.ReviewPullRequest, "denied", 1, 1)
		check("web-self", NewRequestWithValues(t, "POST", "/user2/repo1/pulls/3/files/reviews/submit", map[string]string{"type": "approve"}), session, 200, authz.ReviewPullRequest, "denied", 1, 1)
		reader := loginUser(t, "user4")
		token = getTokenForLoggedInUser(t, reader, auth_model.AccessTokenScopeWriteRepository)
		check("dismiss-no-admin", NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/reviews/8/dismissals", api.DismissPullReviewOptions{Message: shadowPullPrivate}).AddTokenAuth(token), reader, 403, authz.ReviewPullRequest, "denied", 4, 1)
		check("web-dismiss-no-admin", NewRequestWithValues(t, "POST", "/user2/repo1/issues/dismiss_review", map[string]string{"review_id": "8", "message": shadowPullPrivate}), reader, 404, authz.ReviewPullRequest, "denied", 4, 1)
		check("delete-not-author", NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/pulls/3/reviews/5").AddTokenAuth(token), reader, 403, authz.ReviewPullRequest, "denied", 4, 1)
		require.Equal(t, reviews, unittest.GetCount(t, &issues_model.Review{}))
		if setting.EnterpriseAuthz.Enabled {
			var records []authz_model.DecisionRecord
			require.NoError(t, db.GetEngine(t.Context()).Where("action = ?", authz.ReviewPullRequest).Find(&records))
			require.Len(t, records, 5)
			for _, record := range records {
				require.Equal(t, "allow", record.CandidateDecision)
			}
		}
	})
}

func TestEnterpriseAuthzShadowPullReviewWebMutations(t *testing.T) {
	testShadowPullModes(t, func(t *testing.T, check shadowPullCheck) {
		session := loginUser(t, "user2")
		const base = "/user2/repo1/pulls/3/files/reviews"
		values := map[string]string{"origin": "diff", "content": shadowPullPrivate, "side": "proposed", "line": "1", "path": "README.md", "latest_commit_id": "985f0301dba5e7b34be866819cd15ad3d8f508ee"}
		check("comment", NewRequestWithValues(t, "POST", base+"/comments", values), session, 200, authz.ReviewPullRequest, "success", 2, 1)
		comment := unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{IssueID: 3, PosterID: 2, Line: 1, Content: shadowPullPrivate})
		check("submit", NewRequestWithValues(t, "POST", base+"/submit", map[string]string{"type": "approve", "commit_id": "985f0301dba5e7b34be866819cd15ad3d8f508ee"}), session, 200, authz.ReviewPullRequest, "success", 2, 1)
		review := unittest.AssertExistsAndLoadBean(t, &issues_model.Review{ID: comment.ReviewID})
		require.Equal(t, issues_model.ReviewTypeApprove, review.Type)
		for _, action := range []string{"Resolve", "UnResolve"} {
			check(action, NewRequestWithValues(t, "POST", "/user2/repo1/issues/resolve_conversation", map[string]string{"origin": "diff", "action": action, "comment_id": strconv.FormatInt(comment.ID, 10)}), session, 200, authz.ReviewPullRequest, "success", 2, 1)
		}
		check("dismiss", NewRequestWithValues(t, "POST", "/user2/repo1/issues/dismiss_review", map[string]string{"review_id": strconv.FormatInt(review.ID, 10), "message": shadowPullPrivate}), session, 303, authz.ReviewPullRequest, "success", 2, 1)
		review = unittest.AssertExistsAndLoadBean(t, &issues_model.Review{ID: review.ID})
		require.True(t, review.Dismissed)
		values["single_review"] = "true"
		values["line"] = "2"
		check("single-comment", NewRequestWithValues(t, "POST", base+"/comments", values), session, 200, authz.ReviewPullRequest, "success", 2, 1)
	})
}

func TestEnterpriseAuthzShadowPullReviewValidation(t *testing.T) {
	testShadowPullModes(t, func(t *testing.T, check shadowPullCheck) {
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		check("empty-api", NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/reviews", api.CreatePullReviewOptions{Event: api.ReviewStateComment}).AddTokenAuth(token), session, 422, authz.ReviewPullRequest, "failed", 2, 1)
		check("empty-web", NewRequestWithValues(t, "POST", "/user2/repo1/pulls/3/files/reviews/submit", map[string]string{"type": "comment"}), session, 200, authz.ReviewPullRequest, "failed", 2, 1)
		check("cross-pr-review", NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/pulls/5/reviews/8").AddTokenAuth(token), session, 404, authz.ReviewPullRequest, "failed", 2, 1)
		before := unittest.GetCount(t, &issues_model.Review{})
		_, err := db.Exec(t.Context(), "UPDATE issue SET is_closed=? WHERE id=3", true)
		require.NoError(t, err)
		check("closed-api", NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/reviews", api.CreatePullReviewOptions{Event: api.ReviewStateApproved}).AddTokenAuth(token), session, 422, authz.ReviewPullRequest, "denied", 2, 1)
		check("closed-web", NewRequestWithValues(t, "POST", "/user2/repo1/pulls/3/files/reviews/submit", map[string]string{"type": "approve"}), session, 422, authz.ReviewPullRequest, "denied", 2, 1)
		require.Equal(t, before, unittest.GetCount(t, &issues_model.Review{}))
	})
}

func TestEnterpriseAuthzShadowPullMutationStorageFailures(t *testing.T) {
	for _, web := range []bool{false, true} {
		for _, table := range []string{"enterprise_subject_role_binding", "enterprise_authz_decision", "audit_event"} {
			t.Run(fmt.Sprintf("web=%t/%s", web, table), func(t *testing.T) {
				defer prepareShadowPullEnv(t)()
				defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, false)()
				defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
				session := loginUser(t, "user1")
				token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
				request := func() *RequestWrapper {
					if web {
						return NewRequestWithValues(t, "POST", "/user2/repo1/pulls/3/files/reviews/submit", map[string]string{"type": "approve"})
					}
					return NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/reviews", api.CreatePullReviewOptions{Event: api.ReviewStateApproved}).AddTokenAuth(token)
				}
				status := 422
				if web {
					status = 200
				}
				baseline := session.MakeRequest(t, request(), status)
				before := unittest.GetCount(t, &authz_model.DecisionRecord{})
				auditBefore := unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
				renamed := false
				restore := func() {
					if !renamed {
						return
					}
					_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE authz_pull_fault RENAME TO "+table)
					require.NoError(t, err)
					renamed = false
				}
				t.Cleanup(restore)
				_, err := db.Exec(t.Context(), "ALTER TABLE "+table+" RENAME TO authz_pull_fault")
				require.NoError(t, err)
				renamed = true
				setting.EnterpriseAuthz.Enabled = true
				response := session.MakeRequest(t, request(), status)
				require.JSONEq(t, baseline.Body.String(), response.Body.String())
				restore()
				added := 0
				if table == "enterprise_subject_role_binding" {
					added = 1
				}
				require.Equal(t, before+added, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				require.Equal(t, auditBefore+added, unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}))
				if added == 1 {
					record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.ReviewPullRequest})
					require.Equal(t, "error", record.CandidateDecision)
					require.Equal(t, "policy_read_failed", record.Reason)
					require.Equal(t, "denied", record.NativeOutcome)
				}
			})
		}
	}
}

func TestEnterpriseAuthzShadowPullMutationCredentialAndVisibilityGuards(t *testing.T) {
	defer prepareShadowPullEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user4")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadRepository)
	before := unittest.GetCount(t, &authz_model.DecisionRecord{})
	session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/reviews", api.CreatePullReviewOptions{Event: api.ReviewStateApproved}).AddTokenAuth(token), 403)
	token = getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo2/pulls/1/reviews", api.CreatePullReviewOptions{Event: api.ReviewStateApproved}).AddTokenAuth(token), 404)
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
}

func TestEnterpriseAuthzShadowPullReviewPartialFailure(t *testing.T) {
	testShadowPullModes(t, func(t *testing.T, check shadowPullCheck) {
		if setting.Database.Type.IsSQLite3() {
			_, err := db.Exec(t.Context(), `CREATE TRIGGER authz_pull_comment_failure BEFORE INSERT ON comment WHEN NEW.tree_path = 'private/missing-file' BEGIN SELECT RAISE(ABORT, 'comment_write_failed'); END`)
			require.NoError(t, err)
			defer func() {
				_, err := db.Exec(context.WithoutCancel(t.Context()), "DROP TRIGGER authz_pull_comment_failure")
				require.NoError(t, err)
			}()
		} else {
			_, err := db.Exec(t.Context(), `CREATE FUNCTION authz_pull_comment_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tree_path = 'private/missing-file' THEN RAISE EXCEPTION 'comment_write_failed'; END IF; RETURN NEW; END $$`)
			require.NoError(t, err)
			_, err = db.Exec(t.Context(), `CREATE TRIGGER authz_pull_comment_failure BEFORE INSERT ON comment FOR EACH ROW EXECUTE FUNCTION authz_pull_comment_failure()`)
			require.NoError(t, err)
			defer func() {
				_, err := db.Exec(context.WithoutCancel(t.Context()), "DROP TRIGGER authz_pull_comment_failure ON comment")
				require.NoError(t, err)
				_, err = db.Exec(context.WithoutCancel(t.Context()), "DROP FUNCTION authz_pull_comment_failure()")
				require.NoError(t, err)
			}()
		}
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		before := unittest.GetCount(t, &issues_model.Comment{Type: issues_model.CommentTypeCode})
		check("partial", NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/reviews?request_source=ssh&actor_id=1", api.CreatePullReviewOptions{Body: shadowPullPrivate, Comments: []api.CreatePullReviewComment{{Path: "README.md", Body: shadowPullPrivate, NewLineNum: 1}, {Path: "private/missing-file", Body: shadowPullPrivate, NewLineNum: 2}}}).AddTokenAuth(token), session, 500, authz.ReviewPullRequest, "failed", 2, 1)
		require.Equal(t, before+1, unittest.GetCount(t, &issues_model.Comment{Type: issues_model.CommentTypeCode}))
		unittest.AssertExistsAndLoadBean(t, &issues_model.Review{ID: 6, Type: issues_model.ReviewTypePending})
	})
}

func TestEnterpriseAuthzShadowPullCreationBlocked(t *testing.T) {
	testShadowPullModes(t, func(t *testing.T, check shadowPullCheck) {
		enabled := setting.EnterpriseAuthz.Enabled
		setting.EnterpriseAuthz.Enabled = true
		admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
		scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 10}
		role, err := authz_service.CreateRole(t.Context(), admin, scope, authz_service.CreateRoleInput{Name: "PR Creator", Permissions: &[]authz_service.PermissionInput{{Action: authz.CreatePullRequest, Effect: "allow"}}})
		require.NoError(t, err)
		_, _, err = authz_service.PutBinding(t.Context(), admin, scope, authz_service.BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 13, RoleID: role.Definition.ID})
		require.NoError(t, err)
		setting.EnterpriseAuthz.Enabled = enabled
		require.NoError(t, db.Insert(t.Context(), &user_model.Blocking{BlockerID: 12, BlockeeID: 13}))
		session := loginUser(t, "user13")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		before := unittest.GetCount(t, &issues_model.PullRequest{})
		check("api", NewRequestWithJSON(t, "POST", "/api/v1/repos/user12/repo10/pulls", api.CreatePullRequestOption{Head: "user13:master", Base: "master", Title: shadowPullPrivate}).AddTokenAuth(token), session, 403, authz.CreatePullRequest, "denied", 13, 10)
		check("web", NewRequestWithValues(t, "POST", "/user12/repo10/compare/master...user13:master", map[string]string{"title": shadowPullPrivate}), session, 400, authz.CreatePullRequest, "denied", 13, 10)
		require.Equal(t, before, unittest.GetCount(t, &issues_model.PullRequest{}))
		if enabled {
			var records []authz_model.DecisionRecord
			require.NoError(t, db.GetEngine(t.Context()).Where("action = ?", authz.CreatePullRequest).Find(&records))
			require.Len(t, records, 2)
			for _, record := range records {
				require.Equal(t, "allow", record.CandidateDecision)
			}
		}
	})
}

func TestEnterpriseAuthzDisabledPullMutationsNeedNoPolicyTables(t *testing.T) {
	defer prepareShadowPullEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, false)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	before := unittest.GetCount(t, &authz_model.DecisionRecord{})
	for _, table := range []string{"enterprise_role_definition", "enterprise_role_permission", "enterprise_subject_role_binding", "enterprise_authz_decision"} {
		_, err := db.Exec(t.Context(), "ALTER TABLE "+table+" RENAME TO "+table+"_pull_disabled")
		require.NoError(t, err)
		t.Cleanup(func() {
			exists, err := db.GetEngine(context.WithoutCancel(t.Context())).IsTableExist(table + "_pull_disabled")
			require.NoError(t, err)
			if !exists {
				return
			}
			_, err = db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE "+table+"_pull_disabled RENAME TO "+table)
			require.NoError(t, err)
		})
	}
	response := session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/reviews", api.CreatePullReviewOptions{Event: api.ReviewStateApproved}).AddTokenAuth(token), 200)
	review := DecodeJSON(t, response, &api.PullReview{})
	require.Equal(t, api.ReviewStateApproved, review.State)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/pulls/3/files/reviews/submit", map[string]string{"type": "comment", "content": shadowPullPrivate}), 200)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, 0)
	for _, table := range []string{"enterprise_role_definition", "enterprise_role_permission", "enterprise_subject_role_binding", "enterprise_authz_decision"} {
		_, err := db.Exec(t.Context(), "ALTER TABLE "+table+"_pull_disabled RENAME TO "+table)
		require.NoError(t, err)
	}
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
}

func TestEnterpriseAuthzShadowPullReviewInvalidTargets(t *testing.T) {
	defer prepareShadowPullEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ReviewPullRequest})
	session.MakeRequest(t, NewRequest(t, "POST", "/api/v1/repos/user2/repo1/pulls/comments/2/resolve").AddTokenAuth(token), 400)
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ReviewPullRequest}))
	session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/comments/2/replies", api.CreatePullReviewCommentReplyOptions{Body: "reply"}).AddTokenAuth(token), 400)
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ReviewPullRequest}))
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/issues/resolve_conversation", map[string]string{"comment_id": "2", "action": "Resolve", "origin": "timeline"}), 400)
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ReviewPullRequest}))
}

func TestEnterpriseAuthzShadowPullReviewRenderingFailure(t *testing.T) {
	testShadowPullModes(t, func(t *testing.T, check shadowPullCheck) {
		session := loginUser(t, "user2")
		before := unittest.GetCount(t, &issues_model.Comment{Type: issues_model.CommentTypeCode})
		check("create", NewRequestWithValues(t, "POST", "/user2/repo1/pulls/3/files/reviews/comments", map[string]string{"line": "1", "side": "proposed", "content": shadowPullPrivate, "path": "README.md", "origin": "diff", "latest_commit_id": "985f0301dba5e7b34be866819cd15ad3d8f508ee"}), session, 200, authz.ReviewPullRequest, "success", 2, 1)
		require.Equal(t, before+1, unittest.GetCount(t, &issues_model.Comment{Type: issues_model.CommentTypeCode}))
		comment := unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{Type: issues_model.CommentTypeCode}, unittest.Cond("id = (SELECT MAX(id) FROM comment WHERE type = ?)", issues_model.CommentTypeCode))
		check("resolve", NewRequestWithValues(t, "POST", "/user2/repo1/issues/resolve_conversation", map[string]string{"comment_id": strconv.FormatInt(comment.ID, 10), "action": "Resolve", "origin": "invalid"}), session, 400, authz.ReviewPullRequest, "failed", 2, 1)
		unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{ID: comment.ID, ResolveDoerID: 2})
	})
}

func TestEnterpriseAuthzShadowPullMutationArchivedGuards(t *testing.T) {
	testShadowPullModes(t, func(t *testing.T, check shadowPullCheck) {
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		reviews := unittest.GetCount(t, &issues_model.Review{})
		comments := unittest.GetCount(t, &issues_model.Comment{})
		_, err := db.Exec(t.Context(), "UPDATE repository SET is_archived = ? WHERE id IN (1,10)", true)
		require.NoError(t, err)
		check("api-resolve", NewRequest(t, "POST", "/api/v1/repos/user2/repo1/pulls/comments/7/resolve").AddTokenAuth(token), session, 404, authz.ReviewPullRequest, "denied", 2, 1)
		check("api-unresolve", NewRequest(t, "POST", "/api/v1/repos/user2/repo1/pulls/comments/7/unresolve").AddTokenAuth(token), session, 404, authz.ReviewPullRequest, "denied", 2, 1)
		check("api-reply", NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/comments/7/replies", api.CreatePullReviewCommentReplyOptions{Body: shadowPullPrivate}).AddTokenAuth(token), session, 404, authz.ReviewPullRequest, "denied", 2, 1)
		check("web-resolve", NewRequestWithValues(t, "POST", "/user2/repo1/issues/resolve_conversation", map[string]string{"comment_id": "7", "action": "Resolve", "origin": "diff"}), session, 404, authz.ReviewPullRequest, "denied", 2, 1)
		check("web-dismiss", NewRequestWithValues(t, "POST", "/user2/repo1/issues/dismiss_review", map[string]string{"review_id": "8", "message": shadowPullPrivate}), session, 404, authz.ReviewPullRequest, "denied", 2, 1)
		check("web-submit", NewRequestWithValues(t, "POST", "/user2/repo1/pulls/3/files/reviews/submit", map[string]string{"type": "approve"}), session, 404, authz.ReviewPullRequest, "denied", 2, 1)
		check("web-comment", NewRequestWithValues(t, "POST", "/user2/repo1/pulls/3/files/reviews/comments", map[string]string{"content": shadowPullPrivate, "path": "README.md", "side": "proposed", "origin": "diff"}), session, 404, authz.ReviewPullRequest, "denied", 2, 1)
		before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ReviewPullRequest})
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/issues/resolve_conversation", map[string]string{"comment_id": "2", "action": "Resolve", "origin": "diff"}), 404)
		session.MakeRequest(t, NewRequest(t, "POST", "/api/v1/repos/user2/repo1/pulls/comments/2/resolve").AddTokenAuth(token), 404)
		session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/pulls/3/files/reviews/new_comment"), 404)
		require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ReviewPullRequest}))
		require.Equal(t, reviews, unittest.GetCount(t, &issues_model.Review{}))
		require.Equal(t, comments, unittest.GetCount(t, &issues_model.Comment{}))
		creator := loginUser(t, "user13")
		token = getTokenForLoggedInUser(t, creator, auth_model.AccessTokenScopeWriteRepository)
		pulls := unittest.GetCount(t, &issues_model.PullRequest{})
		check("api-create", NewRequestWithJSON(t, "POST", "/api/v1/repos/user12/repo10/pulls", api.CreatePullRequestOption{Head: "user13:master", Base: "master", Title: shadowPullPrivate}).AddTokenAuth(token), creator, 404, authz.CreatePullRequest, "denied", 13, 10)
		check("web-create", NewRequestWithValues(t, "POST", "/user12/repo10/compare/master...user13:master", map[string]string{"title": shadowPullPrivate}), creator, 404, authz.CreatePullRequest, "denied", 13, 10)
		require.Equal(t, pulls, unittest.GetCount(t, &issues_model.PullRequest{}))
		if setting.EnterpriseAuthz.Enabled {
			var records []authz_model.DecisionRecord
			require.NoError(t, db.GetEngine(t.Context()).Where("action IN (?,?)", authz.CreatePullRequest, authz.ReviewPullRequest).Find(&records))
			require.Len(t, records, 9)
			for _, record := range records {
				require.Equal(t, "authorization", record.NativeStage)
			}
		}
	})
}

func TestEnterpriseAuthzShadowPullMutationSuccessStorageFailures(t *testing.T) {
	for _, create := range []bool{false, true} {
		for _, web := range []bool{false, true} {
			for _, table := range []string{"enterprise_subject_role_binding", "enterprise_authz_decision", "audit_event"} {
				t.Run(fmt.Sprintf("create=%t/web=%t/%s", create, web, table), func(t *testing.T) {
					var baseline string
					for _, enabled := range []bool{false, true} {
						t.Run(fmt.Sprintf("shadow=%t", enabled), func(t *testing.T) {
							defer prepareShadowPullEnv(t)()
							defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, enabled)()
							defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
							defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
							name, action := "user2", authz.ReviewPullRequest
							if create {
								name, action = "user13", authz.CreatePullRequest
							}
							session := loginUser(t, name)
							token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
							req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/reviews", api.CreatePullReviewOptions{Event: api.ReviewStateApproved}).AddTokenAuth(token)
							status := 200
							if web {
								req = NewRequestWithValues(t, "POST", "/user2/repo1/pulls/3/files/reviews/submit", map[string]string{"type": "approve", "commit_id": "985f0301dba5e7b34be866819cd15ad3d8f508ee"})
							}
							if create {
								req = NewRequestWithJSON(t, "POST", "/api/v1/repos/user12/repo10/pulls", api.CreatePullRequestOption{Head: "user13:master", Base: "master", Title: shadowPullPrivate}).AddTokenAuth(token)
								status = 201
								if web {
									status = 200
									req = NewRequestWithValues(t, "POST", "/user12/repo10/compare/master...user13:master", map[string]string{"title": shadowPullPrivate})
								}
							}
							before := unittest.GetCount(t, &authz_model.DecisionRecord{})
							auditBefore := unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
							reviews := unittest.GetCount(t, &issues_model.Review{})
							pulls := unittest.GetCount(t, &issues_model.PullRequest{})
							renamed := false
							restore := func() {
								if !renamed {
									return
								}
								_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE authz_pull_success_fault RENAME TO "+table)
								require.NoError(t, err)
								renamed = false
							}
							defer restore()
							if enabled {
								_, err := db.Exec(t.Context(), "ALTER TABLE "+table+" RENAME TO authz_pull_success_fault")
								require.NoError(t, err)
								renamed = true
							}
							response := session.MakeRequest(t, req, status)
							body := shadowPullResponse(t, response)
							if !enabled {
								baseline = body
							} else {
								require.JSONEq(t, baseline, body)
							}
							restore()
							added := 0
							if enabled && table == "enterprise_subject_role_binding" {
								added = 1
							}
							require.Equal(t, before+added, unittest.GetCount(t, &authz_model.DecisionRecord{}))
							require.Equal(t, auditBefore+added, unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}))
							if create {
								require.Equal(t, pulls+1, unittest.GetCount(t, &issues_model.PullRequest{}))
								unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{BaseRepoID: 10, HeadRepoID: 11, HeadBranch: "master", BaseBranch: "master"})
							} else {
								require.Equal(t, reviews, unittest.GetCount(t, &issues_model.Review{}))
								unittest.AssertExistsAndLoadBean(t, &issues_model.Review{ReviewerID: 2, IssueID: 3, Type: issues_model.ReviewTypeApprove})
							}
							if added > 0 {
								record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: action})
								require.Equal(t, "error", record.CandidateDecision)
								require.Equal(t, "policy_read_failed", record.Reason)
								require.Equal(t, "success", record.NativeOutcome)
							}
						})
					}
				})
			}
		}
	}
}

func TestEnterpriseAuthzShadowPullReviewCommentContentMutations(t *testing.T) {
	testShadowPullModes(t, func(t *testing.T, check shadowPullCheck) {
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteIssue)
		check("api-edit", NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/issues/comments/7", api.EditIssueCommentOption{Body: shadowPullPrivate}).AddTokenAuth(token), session, 200, authz.ReviewPullRequest, "success", 2, 1)
		if setting.EnterpriseAuthz.Enabled {
			record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.ReviewPullRequest}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
			var snapshot struct {
				NativeActions []authz.Action `json:"native_actions"`
			}
			require.NoError(t, json.Unmarshal([]byte(record.SnapshotJSON), &snapshot))
			require.Equal(t, []authz.Action{authz.ReviewPullRequest}, snapshot.NativeActions)
		}
		comment := unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{ID: 7, Content: shadowPullPrivate})
		check("web-edit", NewRequestWithValues(t, "POST", "/user2/repo1/comments/7", map[string]string{"content": "changed", "content_version": strconv.Itoa(comment.ContentVersion), "ignore_attachments": "true"}), session, 200, authz.ReviewPullRequest, "success", 2, 1)
		unittest.AssertExistsAndLoadBean(t, &issues_model.Comment{ID: 7, Content: "changed"})
		check("api-deprecated-edit", NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/issues/3/comments/7", api.EditIssueCommentOption{Body: shadowPullPrivate}).AddTokenAuth(token), session, 200, authz.ReviewPullRequest, "success", 2, 1)
		reader := loginUser(t, "user4")
		readToken := getTokenForLoggedInUser(t, reader, auth_model.AccessTokenScopeWriteIssue)
		check("api-edit-denied", NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/issues/comments/7", api.EditIssueCommentOption{Body: "not-author"}).AddTokenAuth(readToken), reader, 403, authz.ReviewPullRequest, "denied", 4, 1)
		check("web-delete-denied", NewRequest(t, "POST", "/user2/repo1/comments/7/delete"), reader, 403, authz.ReviewPullRequest, "denied", 4, 1)
		check("api-delete", NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/issues/comments/7").AddTokenAuth(token), session, 204, authz.ReviewPullRequest, "success", 2, 1)
		unittest.AssertNotExistsBean(t, &issues_model.Comment{ID: 7})
		check("web-delete", NewRequest(t, "POST", "/user2/repo1/comments/4/delete"), session, 200, authz.ReviewPullRequest, "success", 2, 1)
		unittest.AssertNotExistsBean(t, &issues_model.Comment{ID: 4})
		check("api-deprecated-delete", NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/issues/2/comments/5").AddTokenAuth(token), session, 204, authz.ReviewPullRequest, "success", 2, 1)
		unittest.AssertNotExistsBean(t, &issues_model.Comment{ID: 5})
		_, err := db.Exec(t.Context(), "UPDATE repository SET is_archived = ? WHERE id=1", true)
		require.NoError(t, err)
		check("api-edit-archived", NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/issues/comments/6", api.EditIssueCommentOption{Body: shadowPullPrivate}).AddTokenAuth(token), session, 423, authz.ReviewPullRequest, "denied", 2, 1)
		_, err = db.Exec(t.Context(), "UPDATE repository SET is_archived = ? WHERE id=1", false)
		require.NoError(t, err)
		check("api-review-content", NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/issues/comments/9", api.EditIssueCommentOption{Body: shadowPullPrivate}).AddTokenAuth(token), session, 200, authz.ReviewPullRequest, "success", 2, 1)
		check("web-review-delete", NewRequest(t, "POST", "/user2/repo1/comments/9/delete"), session, 200, authz.ReviewPullRequest, "success", 2, 1)
		before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ReviewPullRequest})
		session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/issues/comments/2", api.EditIssueCommentOption{Body: "ordinary issue"}).AddTokenAuth(token), 200)
		session.MakeRequest(t, NewRequest(t, "POST", "/user2/repo1/comments/2/delete"), 200)
		require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ReviewPullRequest}))
	})
}

type shadowPullTargetReadHook struct {
	active   atomic.Bool
	scoped   atomic.Int32
	unscoped atomic.Int32
}

func (h *shadowPullTargetReadHook) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.active.Load() {
		sql := strings.ToUpper(strings.NewReplacer("\"", "", "`", "").Replace(c.SQL))
		if strings.HasPrefix(sql, "SELECT ") && (strings.Contains(sql, "FROM COMMENT ") || strings.Contains(sql, "FROM REVIEW ")) {
			if strings.Contains(sql, "ISSUE.REPO_ID") {
				h.scoped.Add(1)
			} else {
				h.unscoped.Add(1)
			}
		}
	}
	return c.Ctx, nil
}

func (h *shadowPullTargetReadHook) AfterProcess(*contexts.ContextHook) error { return nil }

func TestEnterpriseAuthzShadowPullGuardLookupNeverLoadsForeignPayloads(t *testing.T) {
	defer prepareShadowPullEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	_, err := db.Exec(t.Context(), "UPDATE repository SET is_archived = ? WHERE id=1", true)
	require.NoError(t, err)
	hook := &shadowPullTargetReadHook{}
	unittest.GetXORMEngine().AddHook(hook)
	hook.active.Store(true)
	defer hook.active.Store(false)
	session.MakeRequest(t, NewRequest(t, "POST", "/api/v1/repos/user2/repo1/pulls/comments/8/resolve").AddTokenAuth(token), 404)
	session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/reviews/13/dismissals", api.DismissPullReviewOptions{Message: shadowPullPrivate}).AddTokenAuth(token), 404)
	hook.active.Store(false)
	require.Zero(t, hook.unscoped.Load())
	require.EqualValues(t, 2, hook.scoped.Load())
	unittest.AssertCount(t, &authz_model.DecisionRecord{Action: authz.ReviewPullRequest}, 0)
}

func TestEnterpriseAuthzShadowPullBindingFailures(t *testing.T) {
	testShadowPullModes(t, func(t *testing.T, check shadowPullCheck) {
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		issueToken := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteIssue)
		for _, item := range []struct {
			name, method, path string
			issue              bool
		}{
			{"create-review", "POST", "/pulls/3/reviews", false},
			{"submit-review", "POST", "/pulls/3/reviews/8", false},
			{"dismiss-review", "POST", "/pulls/3/reviews/8/dismissals", false},
			{"reply", "POST", "/pulls/3/comments/7/replies", false},
			{"edit-content", "PATCH", "/issues/comments/7", true},
			{"deprecated-content", "PATCH", "/issues/3/comments/7", true},
		} {
			credential := token
			if item.issue {
				credential = issueToken
			}
			req := NewRequestWithBody(t, item.method, "/api/v1/repos/user2/repo1"+item.path, strings.NewReader("{"))
			req.Header.Set("Content-Type", "application/json")
			check(item.name, req.AddTokenAuth(credential), session, 422, authz.ReviewPullRequest, "failed", 2, 1)
		}
		before := unittest.GetCount(t, &authz_model.DecisionRecord{})
		for _, path := range []string{"/pulls/3/comments/8/replies", "/issues/comments/2", "/issues/comments/8"} {
			method, credential := "POST", token
			if strings.HasPrefix(path, "/issues/") {
				method, credential = "PATCH", issueToken
			}
			req := NewRequestWithBody(t, method, "/api/v1/repos/user2/repo1"+path, strings.NewReader("{"))
			req.Header.Set("Content-Type", "application/json")
			session.MakeRequest(t, req.AddTokenAuth(credential), 422)
		}
		require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
		creator := loginUser(t, "user13")
		token = getTokenForLoggedInUser(t, creator, auth_model.AccessTokenScopeWriteRepository)
		for i, payload := range []string{"{", `{"head":"user13:master","base":"master"}`, `{"head":"user13:master","base":"master","title":[]}`} {
			req := NewRequestWithBody(t, "POST", "/api/v1/repos/user12/repo10/pulls", strings.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			check(fmt.Sprintf("create-pull-%d", i), req.AddTokenAuth(token), creator, 422, authz.CreatePullRequest, "failed", 13, 10)
		}
	})
}

func TestEnterpriseAuthzShadowPullPrivacyDenials(t *testing.T) {
	testShadowPullModes(t, func(t *testing.T, check shadowPullCheck) {
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		restricted := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopePublicOnly)
		pulls, reviews, comments := unittest.GetCount(t, &issues_model.PullRequest{}), unittest.GetCount(t, &issues_model.Review{}), unittest.GetCount(t, &issues_model.Comment{})
		req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls", api.CreatePullRequestOption{Head: "user2/repo2:master", Base: "master", Title: shadowPullPrivate}).AddTokenAuth(restricted)
		check("head-credential", req, session, 404, authz.CreatePullRequest, "denied", 2, 1)
		_, err := db.GetEngine(t.Context()).Where("repo_id = ? AND type = ?", 2, unit.TypeCode).Delete(&repo_model.RepoUnit{})
		require.NoError(t, err)
		req = NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls", api.CreatePullRequestOption{Head: "user2/repo2:master", Base: "master", Title: shadowPullPrivate}).AddTokenAuth(token)
		check("head-code-api", req, session, 404, authz.CreatePullRequest, "denied", 2, 1)
		check("head-code-web", NewRequestWithValues(t, "POST", "/user2/repo1/compare/master...user2/repo2:master", map[string]string{"title": shadowPullPrivate}), session, 500, authz.CreatePullRequest, "denied", 2, 1)
		check("missing-branch", NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls", api.CreatePullRequestOption{Head: "shadow-no-such-branch", Base: "master", Title: shadowPullPrivate}).AddTokenAuth(token), session, 404, authz.CreatePullRequest, "failed", 2, 1)
		for _, item := range []struct {
			name, method, path string
			body               any
		}{
			{"pending-delete", "DELETE", "/pulls/2/reviews/4", nil},
			{"pending-submit", "POST", "/pulls/2/reviews/4", api.SubmitPullReviewOptions{Event: api.ReviewStateApproved}},
			{"pending-dismiss", "POST", "/pulls/2/reviews/4/dismissals", api.DismissPullReviewOptions{Message: shadowPullPrivate}},
		} {
			req := NewRequest(t, item.method, "/api/v1/repos/user2/repo1"+item.path)
			if item.body != nil {
				req = NewRequestWithJSON(t, item.method, "/api/v1/repos/user2/repo1"+item.path, item.body)
			}
			check(item.name, req.AddTokenAuth(token), session, 404, authz.ReviewPullRequest, "denied", 2, 1)
		}
		before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.CreatePullRequest})
		session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/compare/master...user2/repo2:master"), 404)
		require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.CreatePullRequest}))
		before = unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ReviewPullRequest})
		session.MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1/pulls/2/reviews/4").AddTokenAuth(token), 404)
		require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ReviewPullRequest}))
		require.Equal(t, pulls, unittest.GetCount(t, &issues_model.PullRequest{}))
		require.Equal(t, reviews, unittest.GetCount(t, &issues_model.Review{}))
		require.Equal(t, comments, unittest.GetCount(t, &issues_model.Comment{}))
		if setting.EnterpriseAuthz.Enabled {
			var records []authz_model.DecisionRecord
			require.NoError(t, db.GetEngine(t.Context()).Where("native_outcome = ?", "denied").In("action", authz.CreatePullRequest, authz.ReviewPullRequest).Find(&records))
			require.Len(t, records, 6)
			for _, record := range records {
				require.Equal(t, "allow", record.CandidateDecision)
				require.NotContains(t, record.SnapshotJSON, "repo2")
				require.NotContains(t, record.SnapshotJSON, "Pending Review")
				event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, unittest.Cond("metadata LIKE ?", "%"+record.ObservationID+"%"))
				require.Equal(t, true, audit_model.DecodeMetadata(event.Metadata)["mismatch"])
			}
		}
	})
}
