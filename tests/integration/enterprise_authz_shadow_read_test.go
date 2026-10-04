// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	repo_router "gitea.dev/routers/web/repo"
	authz_service "gitea.dev/services/enterpriseauthz"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

type shadowReadEndpoint struct {
	path    string
	status  int
	action  authz.Action
	outcome string
	repoID  int64
	method  string
	values  map[string]string
}

func shadowReadJSON(t *testing.T, body []byte, path string) string {
	t.Helper()
	if !strings.Contains(path, "/teams") {
		return string(body)
	}
	var value any
	require.NoError(t, json.Unmarshal(body, &value))
	teams, ok := value.([]any)
	if !ok {
		teams = []any{value}
	}
	for _, item := range teams {
		team, ok := item.(map[string]any)
		require.True(t, ok)
		rawUnits, ok := team["units"].([]any)
		require.True(t, ok)
		units := make([]string, len(rawUnits))
		for i, raw := range rawUnits {
			name, ok := raw.(string)
			require.True(t, ok)
			units[i] = name
		}
		slices.Sort(units)
		team["units"] = units
	}
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	return string(encoded)
}

func shadowReadHTML(t *testing.T, body string) string {
	t.Helper()
	doc := NewHTMLParser(t, strings.NewReader(body))
	doc.Find("[nonce]").SetAttr("nonce", "")
	doc.Find(".active-stopwatch[data-seconds]").SetAttr("data-seconds", "0")
	period := doc.Find(".activity-header relative-time[datetime]")
	for i := range period.Length() {
		item := period.Eq(i)
		value, _ := item.Attr("datetime")
		date, _, _ := strings.Cut(value, "T")
		item.SetAttr("datetime", date)
	}
	configs := doc.Find("[data-code-editor-config]")
	for i := range configs.Length() {
		item := configs.Eq(i)
		raw, _ := item.Attr("data-code-editor-config")
		var config repo_router.CodeEditorConfig
		require.NoError(t, json.Unmarshal([]byte(raw), &config))
		slices.Sort(config.PreviewableExtensions)
		encoded, err := json.Marshal(config)
		require.NoError(t, err)
		item.SetAttr("data-code-editor-config", string(encoded))
	}
	output, err := doc.doc.Html()
	require.NoError(t, err)
	return regexp.MustCompile(`nonce-[a-f0-9]{32}`).ReplaceAllString(output, "nonce-")
}

func shadowReadFeed(body string) string {
	boundary := strings.Index(body, "<item>")
	if boundary < 0 {
		boundary = strings.Index(body, "<entry>")
	}
	if boundary < 0 {
		boundary = len(body)
	}
	header := regexp.MustCompile(`<(pubDate|lastBuildDate|updated)>[^<]*</(pubDate|lastBuildDate|updated)>`).ReplaceAllString(body[:boundary], "<${1}></${2}>")
	return header + body[boundary:]
}

func testShadowReadEndpoints(t *testing.T, web bool, endpoints []shadowReadEndpoint) {
	t.Helper()
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.Other.EnableFeed, true)()
	defer test.MockVariableValue(&setting.Other.ShowFooterTemplateLoadTime, false)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadRepository)
	if web {
		repository := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		gitRepo, err := git.OpenRepository(t.Context(), repository)
		require.NoError(t, err)
		defer gitRepo.Close()
		commit, err := gitRepo.GetBranchCommit(t.Context(), "master")
		require.NoError(t, err)
		blob, err := commit.GetBlobByPath(t.Context(), gitRepo, "README.md")
		require.NoError(t, err)
		for i := range endpoints {
			endpoints[i].path = strings.ReplaceAll(endpoints[i].path, "{blob}", blob.ID.String())
		}
	}
	for _, endpoint := range endpoints {
		t.Run(endpoint.path, func(t *testing.T) {
			status := endpoint.status
			if status == 0 {
				status = http.StatusOK
			}
			action := endpoint.action
			if action == "" {
				action = authz.ReadCode
			}
			request := func() *RequestWrapper {
				method := endpoint.method
				if method == "" {
					method = "GET"
				}
				r := NewRequest(t, method, endpoint.path)
				if endpoint.values != nil {
					r = NewRequestWithValues(t, method, endpoint.path, endpoint.values)
				}
				if !web {
					r.AddTokenAuth(token)
				}
				return r
			}
			setting.EnterpriseAuthz.Enabled = false
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			baseline := session.MakeRequest(t, request(), status)
			require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			setting.EnterpriseAuthz.Enabled = true
			response := session.MakeRequest(t, request(), status)
			require.Equal(t, baseline.Header().Get("Content-Type"), response.Header().Get("Content-Type"))
			if strings.Contains(response.Header().Get("Content-Type"), "application/json") {
				require.JSONEq(t, shadowReadJSON(t, baseline.Body.Bytes(), endpoint.path), shadowReadJSON(t, response.Body.Bytes(), endpoint.path))
			} else if strings.Contains(response.Header().Get("Content-Type"), "text/html") {
				require.Equal(t, shadowReadHTML(t, baseline.Body.String()), shadowReadHTML(t, response.Body.String()))
			} else if strings.Contains(response.Header().Get("Content-Type"), "+xml") {
				require.Equal(t, shadowReadFeed(baseline.Body.String()), shadowReadFeed(response.Body.String()))
			} else {
				require.Equal(t, baseline.Body.Bytes(), response.Body.Bytes())
			}
			require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			repoID := endpoint.repoID
			if repoID == 0 {
				repoID = 1
			}
			record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repoID, Action: action}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
			require.Equal(t, "allow", record.CandidateDecision)
			outcome := "success"
			if status >= 400 {
				outcome = "failed"
			}
			if endpoint.outcome != "" {
				outcome = endpoint.outcome
			}
			require.Equal(t, outcome, record.NativeOutcome)
			source := "api"
			if web {
				source = "web"
			} else {
				require.Contains(t, record.SnapshotJSON, `"write":false`)
			}
			require.Equal(t, source, record.RequestSource)
			require.NotContains(t, record.SnapshotJSON, "README.md")
			unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, unittest.Cond("metadata LIKE ?", "%"+record.ObservationID+"%"))
		})
	}
}

func shadowWebCodeReadEndpoints() []shadowReadEndpoint {
	const commit = "65f1bf27bc3bf70f64657658635e66094edbcb4d"
	return []shadowReadEndpoint{
		{path: "/user2/repo1/raw/branch/master/README.md"},
		{path: "/user2/repo1/media/branch/master/README.md"},
		{path: "/user2/repo1/raw/blob/{blob}"},
		{path: "/user2/repo1/media/blob/{blob}"},
		{path: "/user2/repo1/render/branch/master/README.md", status: http.StatusBadRequest},
		{path: "/user2/repo1/blame/branch/master/README.md"},
		{path: "/user2/repo1/commits/branch/master"},
		{path: "/user2/repo1/commits/branch/master/search?q=Initial"},
		{path: "/user2/repo1/commits/branch/master/README.md"},
		{path: "/user2/repo1/graph"},
		{path: "/user2/repo1/commit/" + commit},
		{path: "/user2/repo1/commit/" + commit + ".diff"},
		{path: "/user2/repo1/commit/" + commit + ".patch"},
		{path: "/user2/repo1/lastcommit/" + commit + "/"},
		{path: "/user2/repo1/tree-list/branch/master"},
		{path: "/user2/repo1/tree-view/branch/master"},
		{path: "/user2/repo1/compare/master...master"},
		{path: "/user2/repo1/compare/master...985f0301dba5e7b34be866819cd15ad3d8f508ee.diff"},
		{path: "/user2/repo1/compare/master...985f0301dba5e7b34be866819cd15ad3d8f508ee.patch"},
		{path: "/user2/repo1/archive/master.zip"},
		{path: "/user2/repo1/search?q=repo1"},
		{path: "/user2/repo1/rss/branch/master"},
		{path: "/user2/repo1/atom/branch/master/README.md"},
		{path: "/user2/repo1/branches"},
		{path: "/user2/repo1/branches/list", action: authz.ViewMetadata},
		{path: "/user2/repo1/tags", action: authz.ViewMetadata},
		{path: "/user2/repo1/tags/list", action: authz.ViewMetadata},
		{path: "/user2/repo1/tags.rss", action: authz.ViewMetadata},
		{path: "/user2/repo1/commit/" + commit + "/load-branches-and-tags"},
		{path: "/user2/repo1/blob_excerpt/985f0301dba5e7b34be866819cd15ad3d8f508ee?last_left=0&last_right=0&left=2&right=2&left_hunk_size=2&right_hunk_size=2&path=README.md&style=split&direction=up"},
	}
}

func TestEnterpriseAuthzShadowWebFileReadEndpoints(t *testing.T) {
	testShadowReadEndpoints(t, true, shadowWebCodeReadEndpoints()[:10])
}

func TestEnterpriseAuthzShadowWebDiffReadEndpoints(t *testing.T) {
	testShadowReadEndpoints(t, true, shadowWebCodeReadEndpoints()[10:21])
}

func TestEnterpriseAuthzShadowWebNavigationReadEndpoints(t *testing.T) {
	testShadowReadEndpoints(t, true, shadowWebCodeReadEndpoints()[21:])
}

func shadowAPICodeReadEndpoints() []shadowReadEndpoint {
	const commit = "65f1bf27bc3bf70f64657658635e66094edbcb4d"
	return []shadowReadEndpoint{
		{path: "/api/v1/repos/user2/repo1/git/blobs/" + commit},
		{path: "/api/v1/repos/user2/repo1/git/trees/" + commit},
		{path: "/api/v1/repos/user2/repo1/git/refs"},
		{path: "/api/v1/repos/user2/repo1/git/refs/heads/master"},
		{path: "/api/v1/repos/user2/repo1/git/notes/" + commit},
		{path: "/api/v1/repos/user2/repo1/git/tags/" + commit, status: http.StatusBadRequest},
		{path: "/api/v1/repos/user2/repo1/commits"},
		{path: "/api/v1/repos/user2/repo1/commits/" + commit},
		{path: "/api/v1/repos/user2/repo1/git/commits/" + commit},
		{path: "/api/v1/repos/user2/repo1/commits/" + commit + ".diff"},
		{path: "/api/v1/repos/user2/repo1/compare/master...master"},
		{path: "/api/v1/repos/user2/repo1/compare/master...985f0301dba5e7b34be866819cd15ad3d8f508ee?output=diff"},
		{path: "/api/v1/repos/user2/repo1/archive/master.zip"},
		{path: "/api/v1/repos/user2/repo1/zipball/master"},
		{path: "/api/v1/repos/user2/repo1/branches"},
		{path: "/api/v1/repos/user2/repo1/branches/master"},
		{path: "/api/v1/repos/user2/repo1/tags"},
		{path: "/api/v1/repos/user2/repo1/tags/v1.1"},
		{path: "/api/v1/repos/user2/repo1/issue_templates"},
		{path: "/api/v1/repos/user2/repo1/issue_config"},
		{path: "/api/v1/repos/user2/repo1/issue_config/validate"},
		{path: "/api/v1/repos/user2/repo1/editorconfig/README.md", status: http.StatusNotFound},
		{path: "/api/v1/repos/user2/repo1/languages", action: authz.ViewMetadata},
		{path: "/api/v1/repos/user2/repo1/licenses", action: authz.ViewMetadata},
		{path: "/api/v1/repos/user2/repo1/topics", action: authz.ViewMetadata},
	}
}

func TestEnterpriseAuthzShadowAPIGitObjectReadEndpoints(t *testing.T) {
	testShadowReadEndpoints(t, false, shadowAPICodeReadEndpoints()[:6])
}

func TestEnterpriseAuthzShadowAPICommitReadEndpoints(t *testing.T) {
	testShadowReadEndpoints(t, false, shadowAPICodeReadEndpoints()[6:14])
}

func TestEnterpriseAuthzShadowAPIRepositoryReadEndpoints(t *testing.T) {
	testShadowReadEndpoints(t, false, shadowAPICodeReadEndpoints()[14:])
}

func shadowPullReadEndpoints(web bool) []shadowReadEndpoint {
	base := "/api/v1/repos/user2/repo1/pulls/3"
	paths := []string{".diff", ".patch", "/commits", "/files"}
	if web {
		base = "/user2/repo1/pulls/3"
		paths = append(paths, "/commits/list", "/commits/985f0301dba5e7b34be866819cd15ad3d8f508ee", "/files/985f0301dba5e7b34be866819cd15ad3d8f508ee..5c050d3b6d2db231ab1f64e324f1b6b9a0b181c2")
	}
	endpoints := make([]shadowReadEndpoint, 0, len(paths))
	for _, path := range paths {
		endpoints = append(endpoints, shadowReadEndpoint{path: base + path})
	}
	return endpoints
}

func TestEnterpriseAuthzShadowPullAPIReadEndpoints(t *testing.T) {
	testShadowReadEndpoints(t, false, shadowPullReadEndpoints(false))
}

func TestEnterpriseAuthzShadowPullWebReadEndpoints(t *testing.T) {
	testShadowReadEndpoints(t, true, shadowPullReadEndpoints(true)[:4])
}

func TestEnterpriseAuthzShadowPullWebCommitRangeReadEndpoints(t *testing.T) {
	testShadowReadEndpoints(t, true, shadowPullReadEndpoints(true)[4:])
}

func TestEnterpriseAuthzShadowEmptyDiffOutcome(t *testing.T) {
	testShadowReadEndpoints(t, true, []shadowReadEndpoint{{path: "/user2/repo1/compare/master...master.diff", outcome: "unknown"}, {path: "/user2/repo1/compare/master...master.patch", outcome: "unknown"}})
}

func TestEnterpriseAuthzShadowEditorReadEndpoints(t *testing.T) {
	testShadowReadEndpoints(t, true, []shadowReadEndpoint{
		{path: "/user2/repo1/_edit/master/README.md"},
		{path: "/user2/repo1/_new/master/"},
		{path: "/user2/repo1/_cherrypick/65f1bf27bc3bf70f64657658635e66094edbcb4d/master"},
		{path: "/user2/repo1/cherry-pick/65f1bf27bc3bf70f64657658635e66094edbcb4d"},
		{path: "/user2/repo1/_preview/master/README.md", method: "POST", values: map[string]string{"content": "# repo1 (Edited)"}},
	})
}

func TestEnterpriseAuthzShadowWebMetadataReadEndpoints(t *testing.T) {
	testShadowReadEndpoints(t, true, []shadowReadEndpoint{
		{path: "/user2/repo1.rss", action: authz.ViewMetadata},
		{path: "/user2/repo1/activity", action: authz.ViewMetadata},
		{path: "/user2/repo1/activity_author_data", action: authz.ViewMetadata},
		{path: "/user2/repo1/activity/contributors", action: authz.ViewMetadata},
		{path: "/user2/repo1/activity/contributors/data", action: authz.ViewMetadata},
		{path: "/user2/repo1/activity/code-frequency", action: authz.ViewMetadata},
		{path: "/user2/repo1/activity/code-frequency/data", action: authz.ViewMetadata},
		{path: "/user2/repo1/activity/recent-commits", action: authz.ViewMetadata},
		{path: "/user2/repo1/activity/recent-commits/data", action: authz.ViewMetadata},
		{path: "/user2/repo1/stars", action: authz.ViewMetadata},
		{path: "/user2/repo1/watchers", action: authz.ViewMetadata},
		{path: "/user2/repo1/forks", action: authz.ViewMetadata},
	})
}

func TestEnterpriseAuthzShadowArchiveInitiation(t *testing.T) {
	testShadowReadEndpoints(t, true, []shadowReadEndpoint{{path: "/user2/repo1/archive/master.zip", method: "POST"}})
}

func TestEnterpriseAuthzShadowAPIMetadataReadEndpoints(t *testing.T) {
	testShadowReadEndpoints(t, false, []shadowReadEndpoint{
		{path: "/api/v1/repos/user2/repo1/forks", action: authz.ViewMetadata},
		{path: "/api/v1/repos/user2/repo1/stargazers", action: authz.ViewMetadata},
		{path: "/api/v1/repos/user2/repo1/subscribers", action: authz.ViewMetadata},
		{path: "/api/v1/repos/user2/repo1/collaborators", action: authz.ViewMetadata},
		{path: "/api/v1/repos/user2/repo1/collaborators/user4/permission", action: authz.ViewMetadata},
		{path: "/api/v1/repos/org3/repo3/collaborators/user2", action: authz.ViewMetadata, status: http.StatusNoContent, repoID: 3},
		{path: "/api/v1/repos/org3/repo3/teams", action: authz.ViewMetadata, repoID: 3},
		{path: "/api/v1/repos/org3/repo3/teams/Owners", action: authz.ViewMetadata, repoID: 3},
		{path: "/api/v1/repos/user2/repo1/activities/feeds", action: authz.ViewMetadata},
	})
}

func TestEnterpriseAuthzShadowAPISearchReadEndpoints(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	owner := loginUser(t, "user2")
	for i, scopes := range [][]auth_model.AccessTokenScope{
		{auth_model.AccessTokenScopeReadRepository},
		{auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopePublicOnly},
	} {
		t.Run([]string{"unrestricted", "public-only"}[i], func(t *testing.T) {
			token := getTokenForLoggedInUser(t, owner, scopes...)
			path := "/api/v1/repos/search?q=repo&uid=2&limit=2&sort=id&order=asc"
			setting.EnterpriseAuthz.Enabled = false
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			var lastID int64
			if before > 0 {
				lastID = unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)")).ID
			}
			baseline := MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), http.StatusOK)
			require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			var result api.SearchResults
			require.NoError(t, json.Unmarshal(baseline.Body.Bytes(), &result))
			require.Len(t, result.Data, 2)
			setting.EnterpriseAuthz.Enabled = true
			response := MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), http.StatusOK)
			require.JSONEq(t, baseline.Body.String(), response.Body.String())
			require.Equal(t, baseline.Header().Get("X-Total-Count"), response.Header().Get("X-Total-Count"))
			require.Equal(t, baseline.Header().Get("Link"), response.Header().Get("Link"))
			require.Equal(t, before+len(result.Data), unittest.GetCount(t, &authz_model.DecisionRecord{}))
			var operationID string
			for _, repo := range result.Data {
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repo.ID, ActorID: 2, Action: authz.ViewMetadata}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision WHERE repo_id = ?)", repo.ID))
				require.Greater(t, record.ID, lastID)
				unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, unittest.Cond("metadata LIKE ?", "%"+record.ObservationID+"%"))
				require.Equal(t, "allow", record.CandidateDecision)
				require.Equal(t, "success", record.NativeOutcome)
				require.Equal(t, "api", record.RequestSource)
				if operationID == "" {
					operationID = record.OperationID
				}
				require.Equal(t, operationID, record.OperationID)
				if len(scopes) > 1 {
					require.False(t, repo.Private)
				}
			}
		})
	}
}

func TestEnterpriseAuthzShadowReadGuardsPreserved(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.Other.EnableFeed, true)()
	owner := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth_model.AccessTokenScopeReadRepository)
	limited := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeReadUser)
	publicOnly := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopePublicOnly)
	paths := []string{
		"/api/v1/repos/user2/repo1/git/blobs/65f1bf27bc3bf70f64657658635e66094edbcb4d",
		"/api/v1/repos/user2/repo1/commits",
		"/api/v1/repos/user2/repo1/archive/master.zip",
		"/user2/repo1/raw/branch/master/README.md",
		"/user2/repo1/rss/branch/master",
	}
	before := unittest.GetCount(t, &authz_model.DecisionRecord{})
	require.NoError(t, repo_model.UpdateRepositoryColsNoAutoTime(t.Context(), &repo_model.Repository{ID: 1, IsPrivate: true}, "is_private"))
	for _, path := range paths {
		MakeRequest(t, NewRequest(t, "GET", path), http.StatusNotFound)
		limitedRequest := NewRequest(t, "GET", path).AddTokenAuth(limited)
		publicRequest := NewRequest(t, "GET", path).AddTokenAuth(publicOnly)
		if strings.Contains(path, "/rss/") {
			limitedRequest.AddBasicAuth("user2", limited)
			publicRequest.AddBasicAuth("user2", publicOnly)
		}
		owner.MakeRequest(t, limitedRequest, http.StatusForbidden)
		publicStatus := http.StatusForbidden
		if strings.HasPrefix(path, "/api/") {
			publicStatus = http.StatusNotFound
		}
		owner.MakeRequest(t, publicRequest, publicStatus)
	}
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
	require.NoError(t, repo_model.UpdateRepositoryColsNoAutoTime(t.Context(), &repo_model.Repository{ID: 1, IsPrivate: false}, "is_private"))
	_, err := db.GetEngine(t.Context()).Where("repo_id = ? AND type = ?", 1, unit.TypeCode).Delete(&repo_model.RepoUnit{})
	require.NoError(t, err)
	for _, path := range paths {
		status := http.StatusNotFound
		if strings.HasPrefix(path, "/api/") {
			status = http.StatusForbidden
		}
		MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), status)
	}
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
	baseline := owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/pulls/3.diff"), http.StatusOK)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.ReadCode}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
	require.Equal(t, "deny", record.CandidateDecision)
	require.Equal(t, "native_visibility_denied", record.Reason)
	require.Equal(t, "success", record.NativeOutcome)
	setting.EnterpriseAuthz.Enabled = false
	disabled := owner.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/pulls/3.diff"), http.StatusOK)
	require.Equal(t, baseline.Body.Bytes(), disabled.Body.Bytes())
}

func TestEnterpriseAuthzShadowVisibleNativeDenied(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	token := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth_model.AccessTokenScopeReadRepository)
	path := "/api/v1/repos/user2/repo1/collaborators/user2/permission"
	baseline := MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), http.StatusForbidden)
	setting.EnterpriseAuthz.Enabled = true
	response := MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), http.StatusForbidden)
	require.JSONEq(t, baseline.Body.String(), response.Body.String())
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, ActorID: 4, Action: authz.ViewMetadata})
	require.Equal(t, "allow", record.CandidateDecision)
	require.Equal(t, "denied", record.NativeOutcome)
}

func TestEnterpriseAuthzShadowCodeReadStorageFailures(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadRepository)
	paths := []string{"/api/v1/repos/user2/repo1/git/blobs/65f1bf27bc3bf70f64657658635e66094edbcb4d", "/user2/repo1/raw/branch/master/README.md", "/user2/repo1/pulls/3.diff"}
	baseline := make([][]byte, len(paths))
	for i, path := range paths {
		response := session.MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), http.StatusOK)
		baseline[i] = slices.Clone(response.Body.Bytes())
	}
	setting.EnterpriseAuthz.Enabled = true
	for _, table := range []string{"enterprise_subject_role_binding", "enterprise_authz_decision", "audit_event"} {
		before := unittest.GetCount(t, &authz_model.DecisionRecord{})
		auditBefore := unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
		_, err := db.Exec(t.Context(), "ALTER TABLE "+table+" RENAME TO authz_read_fault_table")
		require.NoError(t, err)
		for i, path := range paths {
			response := session.MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), http.StatusOK)
			require.Equal(t, baseline[i], response.Body.Bytes())
		}
		_, err = db.Exec(t.Context(), "ALTER TABLE authz_read_fault_table RENAME TO "+table)
		require.NoError(t, err)
		added := 0
		if table == "enterprise_subject_role_binding" {
			added = len(paths)
		}
		require.Equal(t, before+added, unittest.GetCount(t, &authz_model.DecisionRecord{}))
		require.Equal(t, auditBefore+added, unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}))
	}
	setting.EnterpriseAuthz.Enabled = false
	for _, table := range []string{"enterprise_role_definition", "enterprise_role_permission", "enterprise_subject_role_binding", "enterprise_authz_decision"} {
		_, err := db.Exec(t.Context(), "ALTER TABLE "+table+" RENAME TO "+table+"_read_disabled")
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE "+table+"_read_disabled RENAME TO "+table)
			require.NoError(t, err)
		})
	}
	for i, path := range paths {
		response := session.MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), http.StatusOK)
		require.Equal(t, baseline[i], response.Body.Bytes())
	}
}

func TestEnterpriseAuthzShadowRepositoryReads(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadRepository)
	for _, scenario := range []struct {
		path   string
		action authz.Action
		web    bool
	}{
		{"/api/v1/repos/user2/repo1", authz.ViewMetadata, false},
		{"/api/v1/repositories/1", authz.ViewMetadata, false},
		{"/api/v1/repos/user2/repo1/contents/README.md", authz.ReadCode, false},
		{"/api/v1/repos/user2/repo1/contents-ext/README.md", authz.ReadCode, false},
		{"/user2/repo1", authz.ReadCode, true},
	} {
		t.Run(scenario.path, func(t *testing.T) {
			setting.EnterpriseAuthz.Enabled = false
			request := NewRequest(t, "GET", scenario.path)
			if !scenario.web {
				request.AddTokenAuth(token)
			}
			disabled := session.MakeRequest(t, request, http.StatusOK)
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			setting.EnterpriseAuthz.Enabled = true
			request = NewRequest(t, "GET", scenario.path)
			if !scenario.web {
				request.AddTokenAuth(token)
			}
			shadow := session.MakeRequest(t, request, http.StatusOK)
			if !scenario.web {
				require.JSONEq(t, disabled.Body.String(), shadow.Body.String())
			}
			added := 1
			if scenario.web {
				added = 2
			}
			require.Equal(t, before+added, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, Action: scenario.action}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision WHERE action = ?)", scenario.action))
			require.Equal(t, "allow", record.CandidateDecision)
			require.Equal(t, "success", record.NativeOutcome)
			source := "api"
			if scenario.web {
				source = "web"
				unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.ViewMetadata, RequestSource: "web"})
			}
			require.Equal(t, source, record.RequestSource)
			event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, unittest.Cond("metadata LIKE ?", "%"+record.ObservationID+"%"))
			if !scenario.web {
				require.Contains(t, event.ActorCredential, "access-token:")
				require.Contains(t, record.SnapshotJSON, `"write":false`)
			}
			require.NotContains(t, record.SnapshotJSON, "README.md")
		})
	}
	before := unittest.GetCount(t, &authz_model.DecisionRecord{})
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo2"), http.StatusNotFound)
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
	repository := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	_, err := db.GetEngine(t.Context()).Where("repo_id = ? AND type = ?", repository.ID, unit.TypeCode).Delete(&repo_model.RepoUnit{})
	require.NoError(t, err)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1/contents/README.md"), http.StatusForbidden)
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
}

func TestEnterpriseAuthzShadowReadStorageFailuresKeepNativeResponse(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeReadRepository)
	path := "/api/v1/repos/user2/repo1"
	baseline := MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), http.StatusOK)
	for _, table := range []string{"enterprise_subject_role_binding", "enterprise_authz_decision", "audit_event"} {
		t.Run(table, func(t *testing.T) {
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			auditBefore := unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
			_, err := db.GetEngine(t.Context()).Exec("ALTER TABLE " + table + " RENAME TO authz_fault_table")
			require.NoError(t, err)
			setting.EnterpriseAuthz.Enabled = true
			response := MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), http.StatusOK)
			_, err = db.GetEngine(t.Context()).Exec("ALTER TABLE authz_fault_table RENAME TO " + table)
			require.NoError(t, err)
			require.JSONEq(t, baseline.Body.String(), response.Body.String())
			if table == "enterprise_subject_role_binding" {
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
				require.Equal(t, "error", record.CandidateDecision)
				require.Equal(t, "policy_read_failed", record.Reason)
				require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			} else {
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				require.Equal(t, auditBefore, unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}))
			}
		})
	}
	setting.EnterpriseAuthz.Enabled = false
	for _, table := range []string{"enterprise_role_definition", "enterprise_role_permission", "enterprise_subject_role_binding", "enterprise_authz_decision"} {
		_, err := db.GetEngine(t.Context()).Exec("ALTER TABLE " + table + " RENAME TO " + table + "_disabled")
		require.NoError(t, err)
	}
	response := MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), http.StatusOK)
	require.JSONEq(t, baseline.Body.String(), response.Body.String())
	for _, table := range []string{"enterprise_role_definition", "enterprise_role_permission", "enterprise_subject_role_binding", "enterprise_authz_decision"} {
		_, err := db.GetEngine(t.Context()).Exec("ALTER TABLE " + table + "_disabled RENAME TO " + table)
		require.NoError(t, err)
	}
}

func TestEnterpriseAuthzObservationSurvivesNativeRollback(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	setting.EnterpriseAuthz.Enabled = true
	repository := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	permission, err := access_model.GetDoerRepoPermission(t.Context(), repository, actor)
	require.NoError(t, err)
	ctx, observation := authz_service.BeginObservation(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: repository, Permission: &permission, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, Action: authz.Transfer, ConditionContext: authz.ConditionContext{Source: "system"}})
	nativeFailure := errors.New("native test rollback")
	require.ErrorIs(t, db.WithTx(ctx, func(tx context.Context) error {
		_, err := db.GetEngine(tx).ID(repository.ID).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 3})
		require.NoError(t, err)
		return nativeFailure
	}), nativeFailure)
	observation.Finish(ctx, authz_service.NativeFailed, authz_service.StageOperation)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1})
	require.Equal(t, "failed", record.NativeOutcome)
	require.EqualValues(t, 2, record.OwnerID)
	require.Contains(t, record.SnapshotJSON, `"owner_id":2`)
	unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1, OwnerID: 2})
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, 1)
}
