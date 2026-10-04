// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	code_indexer "gitea.dev/modules/indexer/code"
	"gitea.dev/modules/json"
	"gitea.dev/modules/queue"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	shared_user "gitea.dev/routers/web/shared/user"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzShadowRepositoryCollections(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	for _, userID := range []int64{1, 2} {
		doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: userID})
		require.NoError(t, repo_model.StarRepo(t.Context(), doer, repo, true))
		require.NoError(t, repo_model.WatchRepoAuto(t.Context(), doer, repo, true))
	}
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopeReadUser, auth_model.AccessTokenScopeReadOrganization)
	for _, endpoint := range []string{"/api/v1/user/repos?limit=2", "/api/v1/users/user2/repos?limit=2", "/api/v1/orgs/org3/repos?limit=2", "/api/v1/user/starred?limit=2", "/api/v1/user/subscriptions?limit=2", "/api/v1/users/user1/starred?limit=2", "/api/v1/users/user1/subscriptions?limit=2", "/api/v1/teams/1/repos?limit=2"} {
		t.Run(endpoint, func(t *testing.T) {
			setting.EnterpriseAuthz.Enabled = false
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			var latest authz_model.DecisionRecord
			_, err := db.GetEngine(t.Context()).OrderBy("id DESC").Get(&latest)
			require.NoError(t, err)
			baseline := session.MakeRequest(t, NewRequest(t, "GET", endpoint).AddTokenAuth(token), http.StatusOK)
			require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			setting.EnterpriseAuthz.Enabled = true
			response := session.MakeRequest(t, NewRequest(t, "GET", endpoint).AddTokenAuth(token), http.StatusOK)
			require.JSONEq(t, baseline.Body.String(), response.Body.String())
			require.Equal(t, baseline.Header().Get("X-Total-Count"), response.Header().Get("X-Total-Count"))
			repos := DecodeJSON(t, response, []*api.Repository{})
			require.NotEmpty(t, repos)
			var records []*authz_model.DecisionRecord
			require.NoError(t, db.GetEngine(t.Context()).Where("id > ?", latest.ID).Find(&records))
			require.Len(t, records, len(repos))
			for _, repo := range repos {
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: repo.ID, Action: authz.ViewMetadata, RequestSource: "api", NativeOutcome: "success"}, unittest.Cond("id > ?", latest.ID))
				unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, unittest.Cond("metadata LIKE ?", "%"+record.ObservationID+"%"))
			}
		})
	}
}

func TestEnterpriseAuthzShadowWebRepositoryCollections(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.Other.ShowFooterTemplateLoadTime, false)()
	session := loginUser(t, "user2")
	for _, endpoint := range []string{"/explore/repos?q=repo1", "/user2?tab=repositories&q=repo1", "/org3?tab=repositories&q=repo3", "/user2?tab=stars"} {
		t.Run(endpoint, func(t *testing.T) {
			setting.EnterpriseAuthz.Enabled = false
			var latest authz_model.DecisionRecord
			_, err := db.GetEngine(t.Context()).OrderBy("id DESC").Get(&latest)
			require.NoError(t, err)
			baseline := session.MakeRequest(t, NewRequest(t, "GET", endpoint), http.StatusOK)
			setting.EnterpriseAuthz.Enabled = true
			response := session.MakeRequest(t, NewRequest(t, "GET", endpoint), http.StatusOK)
			require.Equal(t, shadowReadHTML(t, baseline.Body.String()), shadowReadHTML(t, response.Body.String()))
			doc := NewHTMLParser(t, response.Body)
			links := doc.doc.Find(".flex-divided-list .item-title a.name")
			var repoIDs []int64
			for i := range links.Length() {
				href, ok := links.Eq(i).Attr("href")
				require.True(t, ok)
				owner, name, found := strings.Cut(strings.TrimPrefix(href, "/"), "/")
				if !found {
					continue
				}
				repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: owner, Name: name})
				repoIDs = append(repoIDs, repo.ID)
			}
			require.NotEmpty(t, repoIDs)
			var records []*authz_model.DecisionRecord
			require.NoError(t, db.GetEngine(t.Context()).Where("id > ?", latest.ID).Find(&records))
			require.Len(t, records, len(repoIDs))
			for _, repoID := range repoIDs {
				unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: repoID, Action: authz.ViewMetadata, RequestSource: "web", NativeOutcome: "success"}, unittest.Cond("id > ?", latest.ID))
			}
		})
	}
}

func TestEnterpriseAuthzShadowProfileReadme(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		defer test.MockVariableValue(&setting.Other.ShowFooterTemplateLoadTime, false)()
		setting.EnterpriseAuthz.Enabled = false
		createTestProfile(t, "org3", shared_user.RepoNameProfile, "public profile readme")
		createTestProfile(t, "org3", shared_user.RepoNameProfilePrivate, shadowPullPrivate)
		admin := loginUser(t, "user1")
		for _, row := range []struct {
			path, repoName string
			session        *TestSession
			actorID        int64
		}{
			{"/org3?view_as=public", shared_user.RepoNameProfile, admin, 1},
			{"/org3?view_as=member", shared_user.RepoNameProfilePrivate, admin, 1},
			{"/org3", shared_user.RepoNameProfile, nil, 0},
		} {
			t.Run(row.path, func(t *testing.T) {
				setting.EnterpriseAuthz.Enabled = false
				baseline := row.session.MakeRequest(t, NewRequest(t, "GET", row.path), 200)
				before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ReadCode})
				setting.EnterpriseAuthz.Enabled = true
				response := row.session.MakeRequest(t, NewRequest(t, "GET", row.path), 200)
				require.Equal(t, shadowReadHTML(t, baseline.Body.String()), shadowReadHTML(t, response.Body.String()))
				require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ReadCode}))
				repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: "org3", Name: row.repoName})
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repo.ID, ActorID: row.actorID, Action: authz.ReadCode, RequestSource: "web", NativeOutcome: "success"}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision WHERE action = ?)", authz.ReadCode))
				require.NotContains(t, record.SnapshotJSON, shadowPullPrivate)
			})
		}
	})
}

func TestEnterpriseAuthzShadowGlobalCodeSearch(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.Other.ShowFooterTemplateLoadTime, false)()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	code_indexer.UpdateRepoIndexer(repo)
	require.NoError(t, queue.GetManager().FlushAll(t.Context(), 0))
	setting.EnterpriseAuthz.Enabled = false
	baseline := MakeRequest(t, NewRequest(t, "GET", "/explore/code?q=Description"), 200)
	before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ReadCode})
	setting.EnterpriseAuthz.Enabled = true
	response := MakeRequest(t, NewRequest(t, "GET", "/explore/code?q=Description"), 200)
	require.Equal(t, shadowReadHTML(t, baseline.Body.String()), shadowReadHTML(t, response.Body.String()))
	doc := NewHTMLParser(t, response.Body)
	require.NotZero(t, doc.doc.Find(".repo-search-result").Length())
	require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ReadCode}))
	unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 0, RepoID: 1, Action: authz.ReadCode, RequestSource: "web", NativeOutcome: "success"})
}

func TestEnterpriseAuthzShadowCollectionEvidenceFaults(t *testing.T) {
	for _, web := range []bool{false, true} {
		for _, table := range []string{"enterprise_subject_role_binding", "enterprise_authz_decision", "audit_event"} {
			t.Run(fmt.Sprintf("web=%t/%s", web, table), func(t *testing.T) {
				defer tests.PrepareTestEnv(t)()
				defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
				defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
				defer test.MockVariableValue(&setting.Other.ShowFooterTemplateLoadTime, false)()
				session := loginUser(t, "user2")
				token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopeReadUser)
				request := func() *RequestWrapper {
					if web {
						return NewRequest(t, "GET", "/user2?tab=repositories&q=repo1")
					}
					return NewRequest(t, "GET", "/api/v1/user/repos?limit=2").AddTokenAuth(token)
				}
				setting.EnterpriseAuthz.Enabled = false
				baseline := session.MakeRequest(t, request(), 200)
				before := unittest.GetCount(t, &authz_model.DecisionRecord{})
				auditBefore := unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
				renamed := false
				restore := func() {
					if renamed {
						_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE authz_collection_fault RENAME TO "+table)
						require.NoError(t, err)
						renamed = false
					}
				}
				defer restore()
				_, err := db.Exec(t.Context(), "ALTER TABLE "+table+" RENAME TO authz_collection_fault")
				require.NoError(t, err)
				renamed = true
				setting.EnterpriseAuthz.Enabled = true
				response := session.MakeRequest(t, request(), 200)
				var added int
				if web {
					require.Equal(t, shadowReadHTML(t, baseline.Body.String()), shadowReadHTML(t, response.Body.String()))
					added = 3
				} else {
					require.JSONEq(t, baseline.Body.String(), response.Body.String())
					added = 2
				}
				restore()
				if table != "enterprise_subject_role_binding" {
					added = 0
				}
				require.Equal(t, before+added, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				require.Equal(t, auditBefore+added, unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}))
				if added > 0 {
					require.Equal(t, added, unittest.GetCount(t, &authz_model.DecisionRecord{ActorID: 2, Action: authz.ViewMetadata, CandidateDecision: "error", NativeOutcome: "success", Reason: "policy_read_failed"}))
				}
			})
		}
	}
}

func TestEnterpriseAuthzShadowCollectionOrganizationScopeDoesNotGrantCode(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadOrganization)
	response := session.MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/repos?limit=1").AddTokenAuth(token), 200)
	repos := DecodeJSON(t, response, []*api.Repository{})
	require.Len(t, repos, 1)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: repos[0].ID, Action: authz.ViewMetadata, NativeOutcome: "success"})
	var snapshot struct {
		NativeActions []string `json:"native_actions"`
		Credential    struct {
			Read    bool     `json:"read"`
			Write   bool     `json:"write"`
			Actions []string `json:"actions"`
		} `json:"credential"`
	}
	require.NoError(t, json.Unmarshal([]byte(record.SnapshotJSON), &snapshot))
	require.Equal(t, []string{"repo.view_metadata"}, snapshot.NativeActions)
	require.Equal(t, []string{"repo.view_metadata"}, snapshot.Credential.Actions)
	require.True(t, snapshot.Credential.Read)
	require.False(t, snapshot.Credential.Write)
}

func TestEnterpriseAuthzShadowTeamOrganizationScopeDoesNotGrantCode(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadOrganization)
	endpoint := "/api/v1/teams/1/repos/org3/repo3"
	setting.EnterpriseAuthz.Enabled = false
	before := unittest.GetCount(t, &authz_model.DecisionRecord{})
	baseline := session.MakeRequest(t, NewRequest(t, "GET", endpoint).AddTokenAuth(token), 200)
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
	setting.EnterpriseAuthz.Enabled = true
	response := session.MakeRequest(t, NewRequest(t, "GET", endpoint).AddTokenAuth(token), 200)
	require.JSONEq(t, baseline.Body.String(), response.Body.String())
	require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
	repo := DecodeJSON(t, response, api.Repository{})
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: repo.ID, Action: authz.ViewMetadata, NativeOutcome: "success"})
	var snapshot struct {
		NativeActions []string `json:"native_actions"`
		Credential    struct {
			Read    bool     `json:"read"`
			Write   bool     `json:"write"`
			Actions []string `json:"actions"`
		} `json:"credential"`
	}
	require.NoError(t, json.Unmarshal([]byte(record.SnapshotJSON), &snapshot))
	require.Equal(t, []string{"repo.view_metadata"}, snapshot.NativeActions)
	require.Equal(t, []string{"repo.view_metadata"}, snapshot.Credential.Actions)
	require.True(t, snapshot.Credential.Read)
	require.False(t, snapshot.Credential.Write)
}
