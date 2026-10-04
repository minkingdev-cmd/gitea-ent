// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzUIDiagnosticCandidateAndConditions(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	admin := loginUser(t, "user1")
	base := "/-/admin/enterprise/authz/scopes/repo/1"
	page := admin.MakeRequest(t, NewRequest(t, "GET", base+"/effective-permissions?user_id=4"), http.StatusOK)
	require.Contains(t, page.Body.String(), "repo.read_code")
	require.Contains(t, page.Body.String(), "candidate-only")
	csrf := NewHTMLParser(t, page.Body).GetInputValueByName("authz_csrf")
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	permissions := []authz_service.PermissionInput{{Action: authz.PushBranch, Effect: "allow", Condition: []byte(`{"branch_pattern":["release/**"],"path_pattern":["docs/**"],"request_sources":["diagnostic"]}`)}}
	role, err := authz_service.CreateRole(t.Context(), actor, scope, authz_service.CreateRoleInput{Name: "Diagnostic conditional", Permissions: &permissions})
	require.NoError(t, err)
	_, _, err = authz_service.PutBinding(t.Context(), actor, scope, authz_service.BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: role.Definition.ID})
	require.NoError(t, err)
	before := unittest.GetCount(t, &authz_model.DecisionRecord{})
	for _, tc := range []struct{ paths, result, decision string }{
		{"", "unresolved", "deny"}, {"docs/public.md\nprivate/token-secret.txt", "not_matched", "deny"}, {"docs/public.md", "matched", "allow"},
	} {
		response := admin.MakeRequest(t, NewRequestWithValues(t, "POST", base+"/evaluate", map[string]string{"authz_csrf": csrf, "user_id": "4", "action": "repo.push_branch", "branch": "release/v1", "paths": tc.paths}), http.StatusOK)
		require.Contains(t, response.Body.String(), `data-condition-result="`+tc.result+`"`)
		require.Contains(t, response.Body.String(), `data-candidate-decision="`+tc.decision+`"`)
		require.Contains(t, response.Body.String(), "candidate-only")
		require.NotContains(t, response.Body.String(), "private/token-secret.txt")
	}
	inactive := admin.MakeRequest(t, NewRequestWithValues(t, "POST", base+"/evaluate", map[string]string{"authz_csrf": csrf, "user_id": "9", "action": "repo.read_code"}), http.StatusOK)
	require.Contains(t, inactive.Body.String(), `data-candidate-decision="deny" data-reason="actor_inactive"`)
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
	for _, fields := range []map[string]string{
		{"user_id": "-1", "action": "repo.push_branch"}, {"action": "repo.unknown"}, {"action": "repo.clone", "paths": "../secret"}, {"action": "repo.clone", "caller_id": "2"}, {"action": "repo.clone", "request_source": "ssh"}, {"action": "repo.clone", "scope_id": "2"}, {"action": "repo.clone", "paths": strings.Repeat("p", authz.MaxBodyBytes+1)},
	} {
		fields["authz_csrf"] = csrf
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", base+"/evaluate", fields), http.StatusUnprocessableEntity)
	}
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", base+"/evaluate", map[string]string{"action": "repo.clone"}), http.StatusForbidden)
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", base+"/evaluate", map[string]string{"authz_csrf": "forged", "action": "repo.clone"}), http.StatusForbidden)
	for _, path := range []string{"system", "org/3"} {
		response := admin.MakeRequest(t, NewRequest(t, "GET", "/-/admin/enterprise/authz/scopes/"+path+"/effective-permissions"), http.StatusOK)
		require.Contains(t, response.Body.String(), "Select a repository")
	}
	_, err = db.Exec(t.Context(), "ALTER TABLE audit_event RENAME TO audit_event_ui_diagnostic_fault")
	require.NoError(t, err)
	defer func() {
		_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE audit_event_ui_diagnostic_fault RENAME TO audit_event")
		require.NoError(t, err)
	}()
	failed := admin.MakeRequest(t, NewRequestWithValues(t, "POST", base+"/evaluate", map[string]string{"authz_csrf": csrf, "user_id": "4", "action": "repo.delete", "branch": "release/draft", "paths": "private/token-secret.txt"}), http.StatusInternalServerError)
	require.NotContains(t, failed.Body.String(), "private/token-secret.txt")
	failedPage := NewHTMLParser(t, failed.Body)
	require.Equal(t, "release/draft", failedPage.GetInputValueByName("branch"))
	selected, exists := failedPage.Find(`select[name="action"] option[selected]`).Attr("value")
	require.True(t, exists)
	require.Equal(t, "repo.delete", selected)
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
}

func TestEnterpriseAuthzUIDecisionHistoryPrivacyAndScope(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	repository := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	administrator := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	permissions := []authz_service.PermissionInput{{Action: authz.PushBranch, Effect: "allow", Condition: []byte(`{"branch_pattern":["release/**"]}`)}}
	role, err := authz_service.CreateRole(t.Context(), administrator, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}, authz_service.CreateRoleInput{Name: "Historical revision", Permissions: &permissions})
	require.NoError(t, err)
	_, _, err = authz_service.PutBinding(t.Context(), administrator, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}, authz_service.BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: role.Definition.ID})
	require.NoError(t, err)
	permission, err := access_model.GetDoerRepoPermission(t.Context(), repository, actor)
	require.NoError(t, err)
	ctx, observation := authz_service.BeginObservation(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: repository, Permission: &permission, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, Action: authz.PushBranch, ConditionContext: authz.ConditionContext{Source: "ssh", Paths: []string{"private/token-secret.txt"}, PathsComplete: true}})
	observation.Finish(ctx, authz_service.NativeUnknown, authz_service.StageTransport)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.PushBranch})
	_, err = authz_service.UpdateRole(t.Context(), administrator, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}, role.Definition.ID, authz_service.UpdateRoleInput{ExpectedRevision: 1, Permissions: &[]authz_service.PermissionInput{}})
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).ID(record.ID).Cols("observation_id").Update(&authz_model.DecisionRecord{ObservationID: strings.Repeat("a", 64)})
	require.NoError(t, err)
	admin := loginUser(t, "user1")
	base := "/-/admin/enterprise/authz/scopes/repo/1/decisions"
	response := admin.MakeRequest(t, NewRequest(t, "GET", base+"?actor_id=4&action=repo.push_branch&decision=deny&limit=1"), http.StatusOK)
	require.Contains(t, response.Body.String(), `data-total="1"`)
	id := strconv.FormatInt(record.ID, 10)
	response = admin.MakeRequest(t, NewRequest(t, "GET", base+"/"+id), http.StatusOK)
	require.Contains(t, response.Body.String(), strings.Repeat("a", 64))
	require.Contains(t, response.Body.String(), `data-native-outcome="unknown"`)
	require.Contains(t, response.Body.String(), `data-mismatch="unknown"`)
	require.NotContains(t, response.Body.String(), "private/token-secret.txt")
	require.Contains(t, response.Body.String(), `data-recorded-role="`+strconv.FormatInt(role.Definition.ID, 10)+`" data-recorded-revision="1"`)
	require.NotContains(t, response.Body.String(), `data-recorded-revision="2"`)
	for _, query := range []string{"limit=101", "page=x", "since=200&until=100", "action=repo.bad", "actor_id=bad"} {
		admin.MakeRequest(t, NewRequest(t, "GET", base+"?"+query), http.StatusUnprocessableEntity)
	}
	admin.MakeRequest(t, NewRequest(t, "GET", base+"?repo_id=2"), http.StatusNotFound)
	admin.MakeRequest(t, NewRequest(t, "GET", "/-/admin/enterprise/authz/scopes/repo/2/decisions/"+id), http.StatusNotFound)
	_, err = db.GetEngine(t.Context()).ID(record.ID).Cols("repo_id").Update(&authz_model.DecisionRecord{RepoID: 999999})
	require.NoError(t, err)
	response = admin.MakeRequest(t, NewRequest(t, "GET", "/-/admin/enterprise/authz/scopes/system/decisions/"+id), http.StatusOK)
	require.Contains(t, response.Body.String(), "Deleted repository")
	_, err = db.GetEngine(t.Context()).ID(record.ID).Cols("snapshot_json").Update(&authz_model.DecisionRecord{SnapshotJSON: `{"catalog_version":1,"secret":"private/token-secret.txt"`})
	require.NoError(t, err)
	response = admin.MakeRequest(t, NewRequest(t, "GET", "/-/admin/enterprise/authz/scopes/system/decisions/"+id), http.StatusInternalServerError)
	require.NotContains(t, response.Body.String(), "private/token-secret.txt")
}

func TestEnterpriseAuthzUIHistoryNamedSelectors(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	repository := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	permission, err := access_model.GetDoerRepoPermission(t.Context(), repository, actor)
	require.NoError(t, err)
	ctx, observation := authz_service.BeginObservation(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: repository, Permission: &permission, Credential: authz_service.CredentialCeiling{Read: true}, Action: authz.ViewMetadata, ConditionContext: authz.ConditionContext{Source: "web"}})
	observation.Finish(ctx, authz_service.NativeSuccess, authz_service.StageOperation)
	admin := loginUser(t, "user1")
	base := "/-/admin/enterprise/authz"
	for kind, label := range map[string]string{"history_repo": "user2/repo1", "history_actor": "user4"} {
		response := admin.MakeRequest(t, NewRequest(t, "GET", base+"/selectors/"+kind+"?scope_type=repo&scope_id=1&limit=1"), http.StatusOK)
		require.Contains(t, response.Body.String(), label)
		loginUser(t, "user2").MakeRequest(t, NewRequest(t, "GET", base+"/selectors/"+kind), http.StatusForbidden)
	}
	for kind, keyword := range map[string]string{"history_repo": "user2/repo1", "history_actor": "user4"} {
		response := admin.MakeRequest(t, NewRequest(t, "GET", base+"/selectors/"+kind+"?scope_type=repo&scope_id=1&q="+url.QueryEscape(keyword)), http.StatusOK)
		require.Contains(t, response.Body.String(), keyword)
	}
	for _, synthetic := range []*user_model.User{user_model.NewActionsUser(), user_model.NewDeployKeyUser()} {
		ctx, observation := authz_service.BeginObservation(t.Context(), authz_service.EvaluateInput{Actor: synthetic, Repo: repository, Permission: &permission, Credential: authz_service.CredentialCeiling{Read: true, NativeOnly: true}, Action: authz.ViewMetadata, ConditionContext: authz.ConditionContext{Source: "system"}})
		observation.Finish(ctx, authz_service.NativeSuccess, authz_service.StageOperation)
		for _, keyword := range []string{synthetic.Name, synthetic.FullName} {
			response := admin.MakeRequest(t, NewRequest(t, "GET", base+"/selectors/history_actor?scope_type=repo&scope_id=1&q="+url.QueryEscape(keyword)), http.StatusOK)
			require.Contains(t, response.Body.String(), synthetic.Name)
		}
	}
	_, err = db.GetEngine(t.Context()).Where("repo_id = ?", 1).Cols("repo_id").Update(&authz_model.DecisionRecord{RepoID: 999999})
	require.NoError(t, err)
	response := admin.MakeRequest(t, NewRequest(t, "GET", base+"/selectors/history_repo?scope_type=system&limit=1"), http.StatusOK)
	require.Contains(t, response.Body.String(), "Deleted repository")
	require.Contains(t, response.Body.String(), "999999")
	response = admin.MakeRequest(t, NewRequest(t, "GET", base+"/scopes/system/decisions?repo_id=999999"), http.StatusOK)
	doc := NewHTMLParser(t, response.Body)
	require.Contains(t, doc.Find(`#authz-history-repo-selected`).Text(), "Deleted repository")
	require.Zero(t, doc.Find(`input[name="repo_id"]:not([type="hidden"])`).Length())
}
