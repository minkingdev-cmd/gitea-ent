// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"testing"

	v1_28 "gitea.dev/modelmigration/v28"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzUIAuthority(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	paths := []string{"/-/admin/enterprise/authz/scopes/system/roles", "/-/admin/enterprise/authz/scopes/org/3/roles", "/-/admin/enterprise/authz/scopes/repo/1/roles", "/-/admin/enterprise/authz/scopes/repo/1/effective-permissions", "/-/admin/enterprise/authz/selectors/user"}
	for _, username := range []string{"user2", "user4"} {
		session := loginUser(t, username)
		for _, path := range paths {
			session.MakeRequest(t, NewRequest(t, "GET", path), http.StatusForbidden)
		}
	}
	admin := loginUser(t, "user1")
	for _, path := range paths {
		response := admin.MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK)
		if path != paths[len(paths)-1] {
			require.Contains(t, response.Body.String(), "enterprise-authz")
			require.NotContains(t, response.Body.String(), "admin.enterprise_authz.")
		}
	}
	setting.EnterpriseAuthz.Enabled = false
	admin.MakeRequest(t, NewRequest(t, "GET", paths[0]), http.StatusNotFound)
	setting.EnterpriseAuthz.Enabled = true
	protectEnterpriseWeComAdminForIntegration(t, "user2")
	admin.MakeRequest(t, NewRequest(t, "GET", paths[0]), http.StatusForbidden)
	protectEnterpriseWeComAdminForIntegration(t, "user1")
	admin.MakeRequest(t, NewRequest(t, "GET", paths[0]), http.StatusOK)
}

func TestEnterpriseAuthzUIRoleLifecycle(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	admin := loginUser(t, "user1")
	for _, scope := range []string{"system", "org/3", "repo/1"} {
		base := "/-/admin/enterprise/authz/scopes/" + scope
		page := admin.MakeRequest(t, NewRequest(t, "GET", base+"/roles/new"), http.StatusOK)
		token := NewHTMLParser(t, page.Body).GetInputValueByName("authz_csrf")
		values := map[string]string{"authz_csrf": token, "name": "UI role", "description": "<script>private-token</script>", "permissions_mode": "replace", "permission_count": "2", "permission_0_action": "repo.push_branch", "permission_0_branch": "release/*", "permission_0_paths": "docs/**", "permission_0_sources": "web\ndiagnostic", "permission_1_action": "repo.push_branch", "permission_1_branch": "main", "permission_1_paths": "", "permission_1_sources": ""}
		res := admin.MakeRequest(t, NewRequestWithValues(t, "POST", base+"/roles/new", values), http.StatusSeeOther)
		detail := res.Header().Get("Location")
		page = admin.MakeRequest(t, NewRequest(t, "GET", detail), http.StatusOK)
		doc := NewHTMLParser(t, page.Body)
		require.Contains(t, doc.Find(`textarea[data-authz-field="branch"]`).Text(), "release/*")
		require.Contains(t, doc.Find(`textarea[data-authz-field="branch"]`).Text(), "main")
		require.Equal(t, "2", doc.GetInputValueByName("permission_count"))
		require.NotContains(t, page.Body.String(), "<script>private-token</script>")
		revision := doc.GetInputValueByName("expected_revision")
		values["expected_revision"] = revision
		values["name"] = "UI role updated"
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", detail, values), http.StatusSeeOther)
		res = admin.MakeRequest(t, NewRequestWithValues(t, "POST", detail, values), http.StatusConflict)
		require.Contains(t, res.Body.String(), "UI role updated")
		require.Contains(t, res.Body.String(), `value="`+revision+`"`)
		values["expected_revision"] = "2"
		values["permission_1_branch"] = "release/*"
		values["permission_1_paths"] = "docs/**"
		values["permission_1_sources"] = "diagnostic\nweb"
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", detail, values), http.StatusUnprocessableEntity)
		deleteValues := map[string]string{"authz_csrf": token, "expected_revision": "2", "confirm": "yes"}
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", detail+"/delete", deleteValues), http.StatusSeeOther)
		admin.MakeRequest(t, NewRequest(t, "GET", detail), http.StatusNotFound)
	}
}

func TestEnterpriseAuthzUISessionAndCSRF(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	admin := loginUser(t, "user1")
	base := "/-/admin/enterprise/authz/scopes/system/roles/new"
	page := admin.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK)
	token := NewHTMLParser(t, page.Body).GetInputValueByName("authz_csrf")
	require.Len(t, token, 64)
	fields := map[string]string{"name": "CSRF role", "permissions_mode": "replace", "permission_count": "0"}
	for _, value := range []string{"", "wrong"} {
		fields["authz_csrf"] = value
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", base, fields), http.StatusForbidden)
	}
	other := loginUser(t, "user1")
	fields["authz_csrf"] = token
	other.MakeRequest(t, NewRequestWithValues(t, "POST", base, fields), http.StatusForbidden)
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", base, fields), http.StatusSeeOther)
	req := NewRequest(t, "GET", base)
	req.SetBasicAuth("user1", userPassword)
	MakeRequest(t, req, http.StatusSeeOther)
	pat := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	MakeRequest(t, NewRequest(t, "GET", base).AddTokenAuth(pat), http.StatusSeeOther)
	req = NewRequestWithValues(t, "POST", base, fields)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	admin.MakeRequest(t, req, http.StatusForbidden)
	admin.MakeRequest(t, NewRequest(t, "GET", base+"/delete"), http.StatusMethodNotAllowed)
}

func TestEnterpriseAuthzUIBodyBoundAndConditionRoundTrip(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	condition := authz.Condition{BranchPattern: []string{" leading ", "private\n*", "private\r\n*", `"literal`}, PathPattern: []string{`dir\*`}}
	raw, err := json.Marshal(condition)
	require.NoError(t, err)
	permissions := []authz_service.PermissionInput{{Action: authz.PushBranch, Effect: "allow", Condition: raw}}
	role, err := authz_service.CreateRole(t.Context(), actor, authz_model.Scope{Type: authz_model.ScopeSystem}, authz_service.CreateRoleInput{Name: "Roundtrip", Permissions: &permissions})
	require.NoError(t, err)
	admin := loginUser(t, "user1")
	base := fmt.Sprintf("/-/admin/enterprise/authz/scopes/system/roles/%d", role.Definition.ID)
	page := admin.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK)
	doc := NewHTMLParser(t, page.Body)
	fields := map[string]string{"authz_csrf": doc.GetInputValueByName("authz_csrf"), "expected_revision": "1", "copy_from_role_id": "0", "name": "Roundtrip", "description": "", "permission_count": "1", "permissions_mode": "replace", "permission_0_action": "repo.push_branch", "permission_0_branch": doc.Find(`[name="permission_0_branch"]`).Text(), "permission_0_paths": doc.Find(`[name="permission_0_paths"]`).Text(), "permission_0_sources": ""}
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", base, fields), http.StatusSeeOther)
	after, err := authz_service.GetRole(t.Context(), actor, authz_model.Scope{Type: authz_model.ScopeSystem}, role.Definition.ID)
	require.NoError(t, err)
	require.Equal(t, role.Permissions[0].ConditionHash, after.Permissions[0].ConditionHash)
}

func TestEnterpriseAuthzUIMultipartBodyBound(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	admin := loginUser(t, "user1")
	base := "/-/admin/enterprise/authz/scopes/system/roles/new"
	page := admin.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK)
	token := NewHTMLParser(t, page.Body).GetInputValueByName("authz_csrf")
	fields := map[string]string{"authz_csrf": token, "name": "Body bound", "permissions_mode": "replace", "permission_count": "0"}
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range fields {
		require.NoError(t, writer.WriteField(key, value))
	}
	file, err := writer.CreateFormFile("unused", "private-token.txt")
	require.NoError(t, err)
	_, err = file.Write(bytes.Repeat([]byte("x"), authz.MaxBodyBytes+1))
	require.NoError(t, err)
	require.NoError(t, writer.Close())
	req := NewRequestWithBody(t, "POST", base, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	admin.MakeRequest(t, req, http.StatusUnprocessableEntity)
}

func TestEnterpriseAuthzUIAllEntrypointsAndWeComAuthority(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	paths := []string{authzUIBase + "/scope?scope_type=system", authzUIBase + "/selectors/user", authzUIBase + "/selectors/team", authzUIBase + "/selectors/org", authzUIBase + "/selectors/repo", authzUIBase + "/selectors/role"}
	for _, scope := range []string{"system", "org/3", "repo/1"} {
		for _, suffix := range []string{"roles", "roles/new", "roles/999999", "bindings", "effective-permissions", "decisions", "decisions/999999"} {
			paths = append(paths, authzUIBase+"/scopes/"+scope+"/"+suffix)
		}
	}
	posts := []string{"roles/new", "roles/999999", "roles/999999/delete", "bindings", "bindings/999999/delete", "evaluate"}
	for _, username := range []string{"user2", "user4"} {
		client := loginUser(t, username)
		for _, path := range paths {
			client.MakeRequest(t, NewRequest(t, "GET", path), http.StatusForbidden)
		}
		for _, suffix := range posts {
			client.MakeRequest(t, NewRequestWithValues(t, "POST", authzUIBase+"/scopes/repo/1/"+suffix, map[string]string{}), http.StatusForbidden)
		}
	}
	admin := loginUser(t, "user1")
	page := admin.MakeRequest(t, NewRequest(t, "GET", authzUIBase+"/scopes/repo/1/roles/new"), http.StatusOK)
	token := NewHTMLParser(t, page.Body).GetInputValueByName("authz_csrf")
	protectEnterpriseWeComAdminForIntegration(t, "user1")
	authority := unittest.AssertExistsAndLoadBean(t, &wecom_model.AdminAuthority{WeComUserID: "protected-user1"})
	for _, change := range []wecom_model.AdminAuthority{{IsActive: false, IsManagement: true, AgentID: setting.EnterpriseWeCom.AgentID}, {IsActive: true, IsManagement: false, AgentID: setting.EnterpriseWeCom.AgentID}, {IsActive: true, IsManagement: true, AgentID: "other-app"}} {
		_, err := db.GetEngine(t.Context()).ID(authority.ID).Cols("is_active", "is_management", "agent_id").Update(&change)
		require.NoError(t, err)
		for _, path := range paths {
			admin.MakeRequest(t, NewRequest(t, "GET", path), http.StatusForbidden)
		}
		for _, suffix := range posts {
			admin.MakeRequest(t, NewRequestWithValues(t, "POST", authzUIBase+"/scopes/repo/1/"+suffix, map[string]string{"authz_csrf": token}), http.StatusForbidden)
		}
	}
	_, err := db.GetEngine(t.Context()).ID(authority.ID).Cols("is_active", "is_management", "agent_id").Update(&wecom_model.AdminAuthority{IsActive: true, IsManagement: true, AgentID: setting.EnterpriseWeCom.AgentID})
	require.NoError(t, err)
	admin.MakeRequest(t, NewRequest(t, "GET", authzUIBase+"/scopes/repo/1/roles"), http.StatusOK)
	setting.EnterpriseAuthz.Enabled = false
	page = admin.MakeRequest(t, NewRequest(t, "GET", "/-/admin"), http.StatusOK)
	require.NotContains(t, page.Body.String(), `href="`+authzUIBase+`"`)
	for _, path := range paths {
		admin.MakeRequest(t, NewRequest(t, "GET", path), http.StatusNotFound)
	}
	setting.EnterpriseAuthz.Enabled = true
	_, err = db.GetEngine(t.Context()).Where("user_id = ?", 1).Cols("status").Update(&wecom_model.Identity{Status: wecom_model.IdentityStatusInactive})
	require.NoError(t, err)
	admin.MakeRequest(t, NewRequest(t, "GET", paths[1]), http.StatusForbidden)
}

const authzUIBase = "/-/admin/enterprise/authz"

func TestEnterpriseAuthzUIReadonlyCopyAndSelectors(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	require.NoError(t, v1_28.AddEnterpriseAuthzFoundation(t.Context(), db.GetXORMEngineForTesting()))
	require.NoError(t, v1_28.AddEnterpriseAuthzEnforcement(t.Context(), db.GetXORMEngineForTesting()))
	admin := loginUser(t, "user1")
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	page := admin.MakeRequest(t, NewRequest(t, "GET", authzUIBase+"/scopes/repo/1/roles"), http.StatusOK)
	require.Contains(t, page.Body.String(), "platform-admin")
	page = admin.MakeRequest(t, NewRequest(t, "GET", authzUIBase+"/scopes/repo/1/roles/new"), http.StatusOK)
	token := NewHTMLParser(t, page.Body).GetInputValueByName("authz_csrf")
	for key := range authz.BuiltinRoles() {
		role := unittest.AssertExistsAndLoadBean(t, &authz_model.RoleDefinition{LowerName: key})
		path := fmt.Sprintf("%s/scopes/repo/1/roles/%d", authzUIBase, role.ID)
		page = admin.MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK)
		require.Contains(t, page.Body.String(), "read-only")
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", path, map[string]string{"authz_csrf": token, "name": key, "description": "", "permissions_mode": "unchanged", "permission_count": "0", "expected_revision": "1"}), http.StatusConflict)
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", path+"/delete", map[string]string{"authz_csrf": token, "confirm": "yes", "expected_revision": "1"}), http.StatusConflict)
		page = admin.MakeRequest(t, NewRequest(t, "GET", authzUIBase+"/scopes/repo/1/roles/new?copy_from="+strconv.FormatInt(role.ID, 10)), http.StatusOK)
		require.Equal(t, strconv.FormatInt(role.ID, 10), NewHTMLParser(t, page.Body).GetInputValueByName("copy_from_role_id"))
	}
	for _, key := range []string{"owner", "platform-admin"} {
		builtin := unittest.AssertExistsAndLoadBean(t, &authz_model.RoleDefinition{LowerName: key})
		unittest.AssertExistsAndLoadBean(t, &authz_model.RolePermission{RoleID: builtin.ID, Action: authz.ManageAccess, Effect: "allow"})
		_, _, err := authz_service.PutBinding(t.Context(), actor, authz_model.Scope{Type: authz_model.ScopeSystem}, authz_service.BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 2, RoleID: builtin.ID})
		require.NoError(t, err)
	}
	owner := loginUser(t, "user2")
	owner.MakeRequest(t, NewRequest(t, "GET", authzUIBase+"/selectors/role"), http.StatusForbidden)
	owner.MakeRequest(t, NewRequest(t, "GET", authzUIBase+"/scopes/repo/1/roles"), http.StatusForbidden)
	owner.MakeRequest(t, NewRequest(t, "GET", authzUIBase+"/scopes/system/decisions?mode=enforce&authorization=deny"), http.StatusForbidden)
	owner.MakeRequest(t, NewRequest(t, "GET", authzUIBase+"/scopes/repo/1/decisions/999999"), http.StatusForbidden)
	guest := unittest.AssertExistsAndLoadBean(t, &authz_model.RoleDefinition{LowerName: "guest"})
	res := admin.MakeRequest(t, NewRequestWithValues(t, "POST", authzUIBase+"/scopes/repo/1/roles/new", map[string]string{"authz_csrf": token, "name": "Independent copy", "copy_from_role_id": strconv.FormatInt(guest.ID, 10), "permissions_mode": "unchanged", "permission_count": "0"}), http.StatusSeeOther)
	copyRole := unittest.AssertExistsAndLoadBean(t, &authz_model.RoleDefinition{LowerName: "independent copy"})
	require.NotEqual(t, guest.ID, copyRole.ID)
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", res.Header().Get("Location"), map[string]string{"authz_csrf": token, "name": "Independent copy", "permissions_mode": "replace", "permission_count": "0", "expected_revision": "1"}), http.StatusSeeOther)
	original, err := authz_service.GetRole(t.Context(), actor, authz_model.Scope{Type: authz_model.ScopeSystem}, guest.ID)
	require.NoError(t, err)
	require.Len(t, original.Permissions, 1)
	for _, kind := range []string{"user", "team", "org", "repo", "role"} {
		page = admin.MakeRequest(t, NewRequest(t, "GET", authzUIBase+"/selectors/"+kind+"?scope_type=repo&scope_id=1&limit=1"), http.StatusOK)
		var result struct {
			Items []struct {
				ID int64 `json:"id"`
			} `json:"items"`
			Total int64 `json:"total"`
			Limit int   `json:"limit"`
		}
		require.NoError(t, json.Unmarshal(page.Body.Bytes(), &result))
		require.LessOrEqual(t, len(result.Items), 1)
		require.Equal(t, 1, result.Limit)
	}
	for _, q := range []string{"q=" + strings.Repeat("x", 129), "limit=101", "page=x", "scope_type=repo&scope_id=-1", "q=a&q=b", "caller_id=2"} {
		admin.MakeRequest(t, NewRequest(t, "GET", authzUIBase+"/selectors/user?"+q), http.StatusUnprocessableEntity)
	}
}

func TestEnterpriseAuthzUIRoleValidationAndAuditRollback(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	admin := loginUser(t, "user1")
	base := authzUIBase + "/scopes/repo/1/roles/new"
	page := admin.MakeRequest(t, NewRequest(t, "GET", base), http.StatusOK)
	token := NewHTMLParser(t, page.Body).GetInputValueByName("authz_csrf")
	fields := map[string]string{"authz_csrf": token, "name": "Validated UI role", "permissions_mode": "replace", "permission_count": "1", "permission_0_action": "repo.push_branch", "permission_0_branch": "main", "permission_0_paths": "", "permission_0_sources": "diagnostic"}
	before := unittest.GetCount(t, &authz_model.RoleDefinition{})
	for field, value := range map[string]string{"permissions_mode": "invalid", "permission_count": "129", "permission_0_action": "repo.unknown", "permission_0_branch": "[", "permission_0_sources": "not_a_source"} {
		original := fields[field]
		fields[field] = value
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", base, fields), http.StatusUnprocessableEntity)
		require.Equal(t, before, unittest.GetCount(t, &authz_model.RoleDefinition{}))
		fields[field] = original
	}
	res := admin.MakeRequest(t, NewRequestWithValues(t, "POST", base, fields), http.StatusSeeOther)
	path := res.Header().Get("Location")
	other := loginUser(t, "user1")
	page = other.MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK)
	otherToken := NewHTMLParser(t, page.Body).GetInputValueByName("authz_csrf")
	fields["expected_revision"] = "1"
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", path, fields), http.StatusSeeOther)
	fields["authz_csrf"] = otherToken
	fields["name"] = "Second editor unsaved"
	res = other.MakeRequest(t, NewRequestWithValues(t, "POST", path, fields), http.StatusConflict)
	require.Contains(t, res.Body.String(), "Second editor unsaved")
	require.Equal(t, "1", NewHTMLParser(t, res.Body).GetInputValueByName("expected_revision"))
	fields["authz_csrf"] = token
	fields["name"] = "Validated UI role"
	delete(fields, "expected_revision")
	admin.MakeRequest(t, NewRequestWithValues(t, "POST", base, fields), http.StatusConflict)
	if !setting.Database.Type.IsPostgreSQL() && !setting.Database.Type.IsSQLite3() {
		return
	}
	_, err := db.Exec(t.Context(), "ALTER TABLE audit_event RENAME TO authz_ui_role_audit_unavailable")
	require.NoError(t, err)
	defer func() {
		_, err := db.Exec(t.Context(), "ALTER TABLE authz_ui_role_audit_unavailable RENAME TO audit_event")
		require.NoError(t, err)
	}()
	fields["name"] = "Audit unavailable draft"
	res = admin.MakeRequest(t, NewRequestWithValues(t, "POST", base, fields), http.StatusInternalServerError)
	require.Contains(t, res.Body.String(), "Audit unavailable draft")
	require.NotContains(t, res.Body.String(), "authz_ui_role_audit_unavailable")
	unittest.AssertNotExistsBean(t, &authz_model.RoleDefinition{LowerName: "audit unavailable draft"})
}

func TestEnterpriseAuthzUIAccountStateAndAuthorityFailure(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	admin := loginUser(t, "user1")
	path := authzUIBase + "/selectors/user"
	for _, state := range []user_model.User{{IsActive: true, IsAdmin: true, IsRestricted: true}, {IsActive: false, IsAdmin: true}, {IsActive: true, IsAdmin: true, ProhibitLogin: true}} {
		_, err := db.GetEngine(t.Context()).ID(1).Cols("is_active", "is_admin", "is_restricted", "prohibit_login").Update(&state)
		require.NoError(t, err)
		response := admin.MakeRequest(t, NewRequest(t, "GET", path), NoExpectedStatus)
		require.NotContains(t, response.Body.String(), `"items"`)
		require.NotContains(t, response.Body.String(), `class="admin enterprise-authz"`)
	}
	_, err := db.GetEngine(t.Context()).ID(1).Cols("is_active", "is_admin", "is_restricted", "prohibit_login").Update(&user_model.User{IsActive: true, IsAdmin: true})
	require.NoError(t, err)
	protectEnterpriseWeComAdminForIntegration(t, "user1")
	admin.MakeRequest(t, NewRequest(t, "GET", path), http.StatusOK)
	_, err = db.Exec(t.Context(), "ALTER TABLE wecom_admin_authority RENAME TO authz_ui_authority_unavailable")
	require.NoError(t, err)
	defer func() {
		_, err := db.Exec(t.Context(), "ALTER TABLE authz_ui_authority_unavailable RENAME TO wecom_admin_authority")
		require.NoError(t, err)
	}()
	response := admin.MakeRequest(t, NewRequest(t, "GET", path), http.StatusForbidden)
	require.NotContains(t, response.Body.String(), "authz_ui_authority_unavailable")
}

func TestEnterpriseAuthzUINameFirstInputs(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	admin := loginUser(t, "user1")
	for _, path := range []string{"/scopes/repo/1/roles", "/scopes/repo/1/bindings", "/scopes/repo/1/effective-permissions?user_id=4", "/scopes/system/decisions?actor_id=4&repo_id=1&since=1767225600&until=1767312000"} {
		response := admin.MakeRequest(t, NewRequest(t, "GET", authzUIBase+path), http.StatusOK)
		doc := NewHTMLParser(t, response.Body)
		for _, name := range []string{"scope_id", "subject_id", "role_id", "user_id", "actor_id", "repo_id"} {
			require.Zero(t, doc.Find(`input[name="`+name+`"]:not([type="hidden"])`).Length(), name)
		}
		require.Positive(t, doc.Find(`[data-authz-picker]`).Length())
		if strings.Contains(path, "effective-permissions") {
			require.Equal(t, "user4", doc.Find(`#authz-evaluate-user-selected`).Text())
		}
		if strings.Contains(path, "decisions") {
			require.Equal(t, "1767225600", doc.GetInputValueByName("since"))
			require.Equal(t, "hidden", doc.Find(`[name="since"]`).AttrOr("type", ""))
			require.Equal(t, "datetime-local", doc.Find(`#authz-history-since`).AttrOr("type", ""))
			require.Empty(t, doc.Find(`#authz-history-since`).AttrOr("value", ""))
			require.Contains(t, doc.Find(`#authz-history-actor-selected`).Text(), "user4")
			require.Contains(t, doc.Find(`#authz-history-repo-selected`).Text(), "user2/repo1")
		}
	}
	admin.MakeRequest(t, NewRequest(t, "GET", authzUIBase+"/scopes/system/decisions?since=1767225600&until=1767312000"), http.StatusOK)
	for _, query := range []string{"since=2026-02-30T12%3A00", "since=2026-01-01T00%3A00", "since=1767312000&until=1767225600", "since=-1", "since=253402300800", "since=1&since=2"} {
		admin.MakeRequest(t, NewRequest(t, "GET", authzUIBase+"/scopes/system/decisions?"+query), http.StatusUnprocessableEntity)
	}
}
