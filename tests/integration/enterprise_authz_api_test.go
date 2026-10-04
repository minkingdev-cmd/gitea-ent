// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"crypto/rand"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	"gitea.dev/modules/timeutil"
	audit_service "gitea.dev/services/audit"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzAPIManagement(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteRepository)
	base := "/api/v1/repos/user2/repo1/enterprise/authz"
	resp := MakeRequest(t, NewRequestWithJSON(t, http.MethodPost, base+"/roles", map[string]any{"name": "API Reviewer", "permissions": []any{map[string]any{"action": "repo.review_pull_request", "effect": "allow"}}}).AddTokenAuth(token), http.StatusCreated)
	var role api.EnterpriseAuthzRole
	DecodeJSON(t, resp, &role)
	require.Positive(t, role.ID)
	require.EqualValues(t, 1, role.Revision)
	rolePath := base + "/roles/" + strconv.FormatInt(role.ID, 10)
	MakeRequest(t, NewRequest(t, "GET", rolePath).AddTokenAuth(token), http.StatusOK)
	list := MakeRequest(t, NewRequest(t, "GET", base+"/roles?limit=1").AddTokenAuth(token), http.StatusOK)
	require.Equal(t, "1", list.Header().Get("X-Total-Count"))
	MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/roles", map[string]any{"name": "Copy", "copy_from_role_id": role.ID}).AddTokenAuth(token), http.StatusCreated)
	foreign := strings.Replace(rolePath, "repo1", "repo2", 1)
	MakeRequest(t, NewRequest(t, "GET", foreign).AddTokenAuth(token), http.StatusNotFound)
	binding := map[string]any{"subject_type": "user", "subject_id": 4, "role_id": role.ID}
	for range 2 {
		MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/bindings", binding).AddTokenAuth(token), http.StatusNoContent)
	}
	bindingsResp := MakeRequest(t, NewRequest(t, "GET", base+"/bindings").AddTokenAuth(token), http.StatusOK)
	var bindings []api.EnterpriseAuthzBinding
	DecodeJSON(t, bindingsResp, &bindings)
	require.Len(t, bindings, 1)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzBindingAdd}, 1)
	MakeRequest(t, NewRequest(t, "DELETE", rolePath+"?expected_revision=1").AddTokenAuth(token), http.StatusConflict)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", rolePath, map[string]any{"expected_revision": 1, "permissions": []any{}}).AddTokenAuth(token), http.StatusOK)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", rolePath, map[string]any{"expected_revision": 1, "name": "Stale"}).AddTokenAuth(token), http.StatusConflict)
	bindingPath := base + "/bindings/" + strconv.FormatInt(bindings[0].ID, 10)
	MakeRequest(t, NewRequest(t, "DELETE", strings.Replace(bindingPath, "repo1", "repo2", 1)).AddTokenAuth(token), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "DELETE", bindingPath).AddTokenAuth(token), http.StatusNoContent)
	MakeRequest(t, NewRequest(t, "DELETE", bindingPath).AddTokenAuth(token), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "DELETE", rolePath).AddTokenAuth(token), http.StatusConflict)
	for _, invalid := range []map[string]any{{"subject_type": "repo", "subject_id": 1, "role_id": role.ID}, {"subject_type": "team", "subject_id": 2, "role_id": role.ID}} {
		MakeRequest(t, NewRequestWithJSON(t, "PUT", base+"/bindings", invalid).AddTokenAuth(token), http.StatusUnprocessableEntity)
	}
	MakeRequest(t, NewRequest(t, "DELETE", rolePath+"?expected_revision=2").AddTokenAuth(token), http.StatusNoContent)
}

func TestEnterpriseAuthzAPIScopesAndDiagnostics(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	ownerSession := loginUser(t, "user2")
	ownerToken := getTokenForLoggedInUser(t, ownerSession, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
	readerWriterToken := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth_model.AccessTokenScopeWriteRepository)
	readerToken := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth_model.AccessTokenScopeReadRepository)
	adminToken := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeWriteAdmin)
	base := "/api/v1/repos/user2/repo1/enterprise/authz"
	for _, path := range []string{base + "/roles", base + "/effective-permissions", "/api/v1/enterprise/authz/actions", "/api/v1/orgs/org3/enterprise/authz/roles"} {
		MakeRequest(t, NewRequest(t, "GET", path), http.StatusUnauthorized)
	}
	MakeRequest(t, NewRequest(t, "GET", base+"/roles").AddTokenAuth(readerToken), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/enterprise/authz/actions").AddTokenAuth(ownerToken), http.StatusForbidden)
	catalog := MakeRequest(t, NewRequest(t, "GET", "/api/v1/enterprise/authz/actions").AddTokenAuth(adminToken), http.StatusOK)
	var directory api.EnterpriseAuthzActionCatalog
	DecodeJSON(t, catalog, &directory)
	require.Len(t, directory.Actions, 19)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/enterprise/authz/roles").AddTokenAuth(ownerToken), http.StatusOK)
	self := MakeRequest(t, NewRequest(t, "GET", base+"/effective-permissions").AddTokenAuth(readerToken), http.StatusOK)
	var effective api.EnterpriseAuthzEffectivePermissions
	DecodeJSON(t, self, &effective)
	require.True(t, effective.CandidateOnly)
	require.False(t, effective.SafetyGuardsEvaluated)
	require.Contains(t, effective.NativeActions, "repo.read_code")
	require.NotContains(t, effective.NativeActions, "repo.push_branch")
	MakeRequest(t, NewRequest(t, "GET", base+"/effective-permissions?user_id=2").AddTokenAuth(readerToken), http.StatusForbidden)
	MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/evaluate", map[string]any{"action": "repo.read_code"}).AddTokenAuth(readerToken), http.StatusForbidden)
	readBefore := unittest.GetCount(t, &authz_model.DecisionRecord{})
	evaluate := MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/evaluate", map[string]any{"action": "repo.push_branch", "user_id": 4, "paths": []string{"private/token-secret.txt"}}).AddTokenAuth(ownerToken), http.StatusOK)
	require.NotContains(t, evaluate.Body.String(), "private/token-secret.txt")
	require.NotContains(t, evaluate.Body.String(), "snapshot")
	require.NotContains(t, evaluate.Body.String(), "subject_id")
	require.Equal(t, readBefore, unittest.GetCount(t, &authz_model.DecisionRecord{}))
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDiagnostic}, 2)
	for _, invalid := range []string{
		`{"action":"repo.clone","actor_id":1}`, `{"action":"repo.clone","request_source":"ssh"}`, `{"action":"repo.clone","scope":{"type":"system"}}`,
		`{"action":"repo.clone","action":"repo.delete"}`, `{"action":null}`, `{"action":"repo.nonexistent"}`, `{"action":"repo.clone","paths":["../private"]}`,
	} {
		MakeRequest(t, NewRequestWithBody(t, "POST", base+"/evaluate", strings.NewReader(invalid)).SetHeader("Content-Type", "application/json").AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
	}
	MakeRequest(t, NewRequestWithBody(t, "POST", base+"/roles", strings.NewReader(strings.Repeat("x", (1<<20)+1))).SetHeader("Content-Type", "application/json").AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
	for _, invalid := range []string{`{"name":"Spoof","scope_id":2}`, `{"name":"Duplicate","name":"Changed"}`, `{"name":"Unknown","permissions":[{"action":"repo.clone","effect":"allow","condition":{"path_pattern":["docs/**"],"path_pattern":["**"]}}]}`} {
		MakeRequest(t, NewRequestWithBody(t, "POST", base+"/roles", strings.NewReader(invalid)).SetHeader("Content-Type", "application/json").AddTokenAuth(ownerToken), http.StatusUnprocessableEntity)
	}
	for _, query := range []string{"limit=101", "page=x", "limit=-1", "repo_id=2", "action=repo.bad", "since=200&until=100"} {
		want := http.StatusUnprocessableEntity
		if query == "repo_id=2" {
			want = http.StatusNotFound
		}
		MakeRequest(t, NewRequest(t, "GET", base+"/decisions?"+query).AddTokenAuth(ownerToken), want)
	}
	setting.EnterpriseAuthz.Enabled = false
	MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/evaluate", map[string]any{"action": "repo.clone", "user_id": 2}).AddTokenAuth(readerWriterToken), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "GET", base+"/effective-permissions?user_id=2").AddTokenAuth(readerToken), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "GET", base+"/roles").AddTokenAuth(readerToken), http.StatusForbidden)
	for _, path := range []string{base + "/roles", base + "/effective-permissions", "/api/v1/orgs/org3/enterprise/authz/roles"} {
		MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(ownerToken), http.StatusNotFound)
	}
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/enterprise/authz/actions").AddTokenAuth(adminToken), http.StatusNotFound)
	setting.EnterpriseAuthz.Enabled = true
	setting.EnterpriseWeCom.Enabled = true
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/enterprise/authz/actions").AddTokenAuth(adminToken), http.StatusForbidden)
}

func TestEnterpriseAuthzAPIDecisionSanitizationAndStorageFailure(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteRepository)
	base := "/api/v1/repos/user2/repo1/enterprise/authz"
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1").AddTokenAuth(token), http.StatusOK)
	resp := MakeRequest(t, NewRequest(t, "GET", base+"/decisions?actor_id=2&repo_id=1&action=repo.view_metadata&decision=allow&limit=1").AddTokenAuth(token), http.StatusOK)
	require.Equal(t, "1", resp.Header().Get("X-Total-Count"))
	var records []api.EnterpriseAuthzDecision
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &records))
	require.Len(t, records, 1)
	require.True(t, records[0].CandidateOnly)
	var evidence []map[string]any
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &evidence))
	snapshot, ok := evidence[0]["snapshot"].(map[string]any)
	require.True(t, ok)
	require.Contains(t, snapshot, "unit_modes")
	require.Contains(t, snapshot, "credential_ceiling")
	require.NotContains(t, resp.Body.String(), "access-token:")
	MakeRequest(t, NewRequest(t, "GET", base+"/decisions/"+strconv.FormatInt(records[0].ID, 10)).AddTokenAuth(token), http.StatusOK)
	secret := "secret-token-OAuth-code https://callback/private 13800138000 private@example.com private/secret.txt"
	fault := authz_model.DecisionRecord{ObservationID: rand.Text(), OperationID: rand.Text(), ActorID: 2, RepoID: 1, OwnerID: 2, Action: "repo.clone", RequestSource: "api", CandidateDecision: "error", Reason: "secret-token-OAuth-code", MissingActions: "[]", NativeOutcome: "failed", NativeStage: "operation", SnapshotJSON: `{"catalog_version":1}`, CreatedUnix: timeutil.TimeStampNow()}
	_, err := db.GetEngine(t.Context()).Insert(&fault)
	require.NoError(t, err)
	safe := MakeRequest(t, NewRequest(t, "GET", base+"/decisions/"+strconv.FormatInt(fault.ID, 10)).AddTokenAuth(token), http.StatusInternalServerError)
	require.NotContains(t, safe.Body.String(), secret)
	require.Contains(t, safe.Body.String(), "policy_storage_failed")
	badBinding := &authz_model.SubjectRoleBinding{SubjectType: "secret-token", SubjectID: 4, ScopeType: authz_model.ScopeRepo, ScopeID: 1, ScopeOwnerID: 2, RoleID: 1}
	require.NoError(t, db.Insert(t.Context(), badBinding))
	sanitizedBinding := MakeRequest(t, NewRequest(t, "GET", base+"/bindings").AddTokenAuth(token), http.StatusInternalServerError)
	require.NotContains(t, sanitizedBinding.Body.String(), "secret-token")
	_, err = db.Exec(t.Context(), "ALTER TABLE audit_event RENAME TO audit_event_authz_api_fault")
	require.NoError(t, err)
	defer func() {
		_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE audit_event_authz_api_fault RENAME TO audit_event")
		require.NoError(t, err)
	}()
	MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/roles", map[string]any{"name": "Storage fault", "description": secret}).AddTokenAuth(token), http.StatusInternalServerError)
	MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/evaluate", map[string]any{"action": "repo.clone"}).AddTokenAuth(token), http.StatusInternalServerError)
}

func TestEnterpriseAuthzAPIPublicOnlyEvidence(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	owner := loginUser(t, "user2")
	full := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeReadRepository)
	limited := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeReadOrganization)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3").AddTokenAuth(full), http.StatusOK)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 3})
	base := "/api/v1/orgs/org3/enterprise/authz/decisions"
	for _, path := range []string{base, base + "/" + strconv.FormatInt(record.ID, 10)} {
		MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(limited), http.StatusForbidden)
	}
	systemLimited := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopePublicOnly, auth_model.AccessTokenScopeReadAdmin)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/enterprise/authz/decisions").AddTokenAuth(systemLimited), http.StatusForbidden)
	setting.EnterpriseAuthz.Enabled = false
	MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(limited), http.StatusForbidden)
}

func TestEnterpriseAuthzAPIAllManagementScopes(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	adminToken := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeWriteAdmin, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
	ownerToken := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
	creatorToken := getTokenForLoggedInUser(t, loginUser(t, "user5"), auth_model.AccessTokenScopeWriteRepository)
	for _, scope := range []struct{ base, token string }{
		{"/api/v1/enterprise/authz", adminToken}, {"/api/v1/orgs/org3/enterprise/authz", ownerToken},
	} {
		response := MakeRequest(t, NewRequestWithJSON(t, "POST", scope.base+"/roles", map[string]any{"name": "Scoped role", "permissions": []any{}}).AddTokenAuth(scope.token), http.StatusCreated)
		var role api.EnterpriseAuthzRole
		DecodeJSON(t, response, &role)
		path := scope.base + "/roles/" + strconv.FormatInt(role.ID, 10)
		MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(scope.token), http.StatusOK)
		MakeRequest(t, NewRequestWithJSON(t, "PATCH", path, map[string]any{"expected_revision": 1, "name": "Revised"}).AddTokenAuth(scope.token), http.StatusOK)
		MakeRequest(t, NewRequest(t, "DELETE", path+"?expected_revision=2").AddTokenAuth(scope.token), http.StatusNoContent)
	}
	key := "platform-admin"
	builtin := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeSystem, Name: "Platform Admin", LowerName: "platform-admin", BuiltinKey: &key, Revision: 1}
	require.NoError(t, db.Insert(t.Context(), builtin))
	systemPath := "/api/v1/enterprise/authz/roles/" + strconv.FormatInt(builtin.ID, 10)
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", systemPath, map[string]any{"expected_revision": 1, "name": "Mutable"}).AddTokenAuth(adminToken), http.StatusConflict)
	MakeRequest(t, NewRequest(t, "DELETE", systemPath+"?expected_revision=1").AddTokenAuth(adminToken), http.StatusConflict)
	MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/orgs/org3/enterprise/authz/bindings", map[string]any{"subject_type": "user", "subject_id": 4, "role_id": builtin.ID}).AddTokenAuth(ownerToken), http.StatusForbidden)
	setting.EnterpriseWeCom = setting.EnterpriseWeComConfig{Enabled: true, CorpID: "api-corp", AgentID: "1000002"}
	for _, path := range []string{"/api/v1/enterprise/authz/roles", "/api/v1/orgs/org3/enterprise/authz/roles", "/api/v1/repos/org3/repo3/enterprise/authz/roles"} {
		MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(adminToken), http.StatusForbidden)
	}
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3/enterprise/authz/roles").AddTokenAuth(ownerToken), http.StatusOK)
	require.NoError(t, db.Insert(t.Context(), &wecom_model.RepositoryGovernance{RepoID: 3, CreatorID: 5}))
	require.NoError(t, db.Insert(t.Context(), &access_model.Access{UserID: 5, RepoID: 3, Mode: perm.AccessModeRead}))
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3/enterprise/authz/roles").AddTokenAuth(creatorToken), http.StatusOK)
	require.NoError(t, db.Insert(t.Context(), &wecom_model.AdminAuthority{CorpID: "api-corp", AgentID: "1000002", WeComUserID: "api.super", IsManagement: true, IsActive: true}))
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 1, CorpID: "api-corp", WeComUserID: "api.super", Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	for _, path := range []string{"/api/v1/enterprise/authz/roles", "/api/v1/orgs/org3/enterprise/authz/roles", "/api/v1/repos/org3/repo3/enterprise/authz/roles"} {
		MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(adminToken), http.StatusOK)
	}
}

func TestEnterpriseAuthzAPIHistoryUsesCurrentScopeAndPreservesDeletedRepository(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	owner := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeReadRepository, auth_model.AccessTokenScopeReadOrganization)
	next := getTokenForLoggedInUser(t, loginUser(t, "user5"), auth_model.AccessTokenScopeReadRepository)
	admin := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeReadAdmin)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo3").AddTokenAuth(owner), http.StatusOK)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 3})
	recordID := strconv.FormatInt(record.ID, 10)
	_, err := db.Exec(t.Context(), "UPDATE repository SET owner_id=5 WHERE id=3")
	require.NoError(t, err)
	orgBase := "/api/v1/orgs/org3/enterprise/authz/decisions"
	MakeRequest(t, NewRequest(t, "GET", orgBase+"/"+recordID).AddTokenAuth(owner), http.StatusNotFound)
	empty := MakeRequest(t, NewRequest(t, "GET", orgBase).AddTokenAuth(owner), http.StatusOK)
	require.Equal(t, "0", empty.Header().Get("X-Total-Count"))
	current := MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user5/repo3/enterprise/authz/decisions/"+recordID).AddTokenAuth(next), http.StatusOK)
	var dto api.EnterpriseAuthzDecision
	DecodeJSON(t, current, &dto)
	require.EqualValues(t, 3, dto.OwnerID)
	_, err = db.Exec(t.Context(), "DELETE FROM repository WHERE id=3")
	require.NoError(t, err)
	MakeRequest(t, NewRequest(t, "GET", orgBase+"/"+recordID).AddTokenAuth(owner), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/enterprise/authz/decisions/"+recordID).AddTokenAuth(admin), http.StatusOK)
	old := timeutil.TimeStamp(time.Now().Add(-48 * time.Hour).Unix())
	_, err = db.GetEngine(t.Context()).ID(record.ID).NoAutoTime().Cols("created_unix").Update(&authz_model.DecisionRecord{CreatedUnix: old})
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Where("action = ? AND metadata LIKE ?", audit_model.EnterpriseAuthzDecision, "%"+record.ObservationID+"%").Cols("timestamp_unix").Update(&audit_model.Event{TimestampUnix: old})
	require.NoError(t, err)
	require.NoError(t, audit_service.DeleteOldEvents(t.Context(), 0))
	unittest.AssertCount(t, &authz_model.DecisionRecord{ID: record.ID}, 1)
	require.NoError(t, audit_service.DeleteOldEvents(t.Context(), 24*time.Hour))
	unittest.AssertCount(t, &authz_model.DecisionRecord{ID: record.ID}, 0)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, 0)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/enterprise/authz/decisions/"+recordID).AddTokenAuth(admin), http.StatusNotFound)
}
