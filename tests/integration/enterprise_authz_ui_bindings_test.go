// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/organization"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func authzBindingForm(t *testing.T, session *TestSession, base string, values map[string]string) *RequestWrapper {
	t.Helper()
	response := session.MakeRequest(t, NewRequest(t, "GET", base+"/bindings"), http.StatusOK)
	token := NewHTMLParser(t, response.Body).Find(`input[name="authz_csrf"]`).First().AttrOr("value", "")
	require.NotEmpty(t, token)
	values["authz_csrf"] = token
	return NewRequestWithValues(t, "POST", base+"/bindings", values)
}

func TestEnterpriseAuthzUIBindingLifecycle(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	admin := loginUser(t, "user1")
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	subject := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	nativeBefore, err := access_model.GetDoerRepoPermission(t.Context(), repo, subject)
	require.NoError(t, err)
	orgUsersBefore := unittest.GetCount(t, &organization.OrgUser{})
	teamUsersBefore := unittest.GetCount(t, &organization.TeamUser{})
	for _, item := range []struct {
		scope    authz_model.Scope
		base     string
		subjects map[string]string
	}{
		{authz_model.Scope{Type: authz_model.ScopeSystem}, "/-/admin/enterprise/authz/scopes/system", map[string]string{"user": "4", "team": "2", "org": "3"}},
		{authz_model.Scope{Type: authz_model.ScopeOrg, ID: 3}, "/-/admin/enterprise/authz/scopes/org/3", map[string]string{"user": "4", "team": "2", "org": "3"}},
		{authz_model.Scope{Type: authz_model.ScopeRepo, ID: 3}, "/-/admin/enterprise/authz/scopes/repo/3", map[string]string{"user": "4", "team": "2", "org": "3"}},
	} {
		role, err := authz_service.CreateRole(t.Context(), actor, item.scope, authz_service.CreateRoleInput{Name: "Binding UI role", Permissions: &[]authz_service.PermissionInput{}})
		require.NoError(t, err)
		for subjectType, subjectID := range item.subjects {
			values := map[string]string{"subject_type": subjectType, "subject_id": subjectID, "role_id": strconv.FormatInt(role.Definition.ID, 10)}
			for range 2 {
				admin.MakeRequest(t, authzBindingForm(t, admin, item.base, values), http.StatusSeeOther)
			}
			id, _ := strconv.ParseInt(subjectID, 10, 64)
			binding := unittest.AssertExistsAndLoadBean(t, &authz_model.SubjectRoleBinding{ScopeType: item.scope.Type, ScopeID: item.scope.ID, SubjectType: authz_model.SubjectType(subjectType), SubjectID: id, RoleID: role.Definition.ID})
			response := admin.MakeRequest(t, NewRequest(t, "GET", item.base+"/bindings?limit=1"), http.StatusOK)
			require.Contains(t, response.Body.String(), "Binding UI role")
			require.Contains(t, response.Body.String(), "data-authz-selector")
			request := authzBindingForm(t, admin, item.base, map[string]string{})
			request.Request.URL.Path = item.base + "/bindings/" + strconv.FormatInt(binding.ID, 10) + "/delete"
			admin.MakeRequest(t, request, http.StatusSeeOther)
			unittest.AssertNotExistsBean(t, binding)
		}
	}
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzBindingAdd}, 9)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzBindingRemove}, 9)
	nativeAfter, err := access_model.GetDoerRepoPermission(t.Context(), repo, subject)
	require.NoError(t, err)
	require.Equal(t, nativeBefore, nativeAfter)
	require.Equal(t, orgUsersBefore, unittest.GetCount(t, &organization.OrgUser{}))
	require.Equal(t, teamUsersBefore, unittest.GetCount(t, &organization.TeamUser{}))
	require.Equal(t, subject.IsAdmin, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}).IsAdmin)
}

func TestEnterpriseAuthzUIBindingValidationAndStaleOwner(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	admin := loginUser(t, "user1")
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 3}
	base := "/-/admin/enterprise/authz/scopes/repo/3"
	role, err := authz_service.CreateRole(t.Context(), actor, scope, authz_service.CreateRoleInput{Name: "<script>binding</script>"})
	require.NoError(t, err)
	foreign, err := authz_service.CreateRole(t.Context(), actor, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}, authz_service.CreateRoleInput{Name: "Foreign"})
	require.NoError(t, err)
	roleID := strconv.FormatInt(role.Definition.ID, 10)
	for _, fields := range []map[string]string{
		{"subject_type": "repo", "subject_id": "3", "role_id": roleID},
		{"subject_type": "team", "subject_id": "3", "role_id": roleID},
		{"subject_type": "org", "subject_id": "6", "role_id": roleID},
		{"subject_type": "user", "subject_id": "999999", "role_id": roleID},
		{"subject_type": "user", "subject_id": "4", "role_id": roleID, "scope_id": "1"},
		{"subject_type": "user", "subject_id": "4", "role_id": roleID, "actor_id": "2"},
		{"subject_type": "user", "subject_id": "4", "role_id": roleID, "owner_id": "2"},
		{"subject_type": "user", "subject_id": "4", "role_id": "-1"},
	} {
		admin.MakeRequest(t, authzBindingForm(t, admin, base, fields), http.StatusUnprocessableEntity)
	}
	admin.MakeRequest(t, authzBindingForm(t, admin, base, map[string]string{"subject_type": "user", "subject_id": "4", "role_id": strconv.FormatInt(foreign.Definition.ID, 10)}), http.StatusNotFound)
	key := "platform-admin"
	builtin := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeSystem, Name: "Platform Admin", LowerName: "platform-admin", BuiltinKey: &key, Revision: 1}
	require.NoError(t, db.Insert(t.Context(), builtin))
	admin.MakeRequest(t, authzBindingForm(t, admin, base, map[string]string{"subject_type": "user", "subject_id": "4", "role_id": strconv.FormatInt(builtin.ID, 10)}), http.StatusForbidden)
	binding, _, err := authz_service.PutBinding(t.Context(), actor, scope, authz_service.BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: role.Definition.ID})
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).ID(3).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 6})
	require.NoError(t, err)
	page := admin.MakeRequest(t, NewRequest(t, "GET", base+"/bindings"), http.StatusOK)
	require.Contains(t, page.Body.String(), `data-binding-status="owner_changed"`)
	require.Contains(t, page.Body.String(), "&lt;script&gt;binding&lt;/script&gt;")
	require.NotContains(t, page.Body.String(), "<script>binding</script>")
	require.Equal(t, int64(3), unittest.AssertExistsAndLoadBean(t, &authz_model.SubjectRoleBinding{ID: binding.ID}).ScopeOwnerID)
	// URL 范围不可被隐藏字段或跨范围解绑 ID 扩大。
	request := authzBindingForm(t, admin, "/-/admin/enterprise/authz/scopes/repo/1", map[string]string{})
	request.Request.URL.Path = "/-/admin/enterprise/authz/scopes/repo/1/bindings/" + strconv.FormatInt(binding.ID, 10) + "/delete"
	admin.MakeRequest(t, request, http.StatusNotFound)
	request = authzBindingForm(t, admin, base, map[string]string{})
	request.Request.URL.Path = base + "/bindings/" + strconv.FormatInt(binding.ID, 10) + "/delete"
	admin.MakeRequest(t, request, http.StatusSeeOther)
	unittest.AssertNotExistsBean(t, &authz_model.SubjectRoleBinding{ID: binding.ID})
	for _, query := range []string{"page=x", "page=-1", "limit=101", "limit=-1"} {
		admin.MakeRequest(t, NewRequest(t, "GET", base+"/bindings?"+query), http.StatusUnprocessableEntity)
	}
}

func TestEnterpriseAuthzUIBindingRelationChangeAndAuditRollback(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	admin := loginUser(t, "user1")
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 3}
	base := "/-/admin/enterprise/authz/scopes/repo/3"
	role, err := authz_service.CreateRole(t.Context(), actor, scope, authz_service.CreateRoleInput{Name: "Relations"})
	require.NoError(t, err)
	values := map[string]string{"subject_type": "team", "subject_id": "2", "role_id": strconv.FormatInt(role.Definition.ID, 10)}
	form := authzBindingForm(t, admin, base, values)
	_, err = db.GetEngine(t.Context()).Where("team_id = ? AND repo_id = ?", 2, 3).Delete(new(organization.TeamRepo))
	require.NoError(t, err)
	response := admin.MakeRequest(t, form, http.StatusUnprocessableEntity)
	require.Equal(t, "2", NewHTMLParser(t, response.Body).Find(`input[name="subject_id"]`).AttrOr("value", ""))
	unittest.AssertCount(t, &authz_model.SubjectRoleBinding{}, 0)
	require.NoError(t, db.Insert(t.Context(), &organization.TeamRepo{OrgID: 3, TeamID: 2, RepoID: 3}))
	admin.MakeRequest(t, authzBindingForm(t, admin, base, values), http.StatusSeeOther)
	_, err = db.GetEngine(t.Context()).ID(2).Delete(new(organization.Team))
	require.NoError(t, err)
	response = admin.MakeRequest(t, NewRequest(t, "GET", base+"/bindings"), http.StatusOK)
	require.Contains(t, response.Body.String(), `data-binding-status="subject_deleted"`)
	if !setting.Database.Type.IsPostgreSQL() && !setting.Database.Type.IsSQLite3() {
		t.Skip("audit failure injection requires PostgreSQL or SQLite")
	}
	if setting.Database.Type.IsPostgreSQL() {
		_, err = db.Exec(t.Context(), `CREATE FUNCTION authz_ui_binding_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'secret=TOPSECRET token=TOPTOKEN private/path'; END $$`)
		require.NoError(t, err)
		_, err = db.Exec(t.Context(), `CREATE TRIGGER authz_ui_binding_audit_failure BEFORE INSERT ON audit_event FOR EACH ROW EXECUTE FUNCTION authz_ui_binding_audit_failure()`)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := db.Exec(context.WithoutCancel(t.Context()), `DROP TRIGGER authz_ui_binding_audit_failure ON audit_event`)
			require.NoError(t, err)
			_, err = db.Exec(context.WithoutCancel(t.Context()), `DROP FUNCTION authz_ui_binding_audit_failure()`)
			require.NoError(t, err)
		})
	} else {
		_, err = db.Exec(t.Context(), `CREATE TRIGGER authz_ui_binding_audit_failure BEFORE INSERT ON audit_event BEGIN SELECT RAISE(ABORT, 'secret=TOPSECRET token=TOPTOKEN private/path'); END`)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := db.Exec(context.WithoutCancel(t.Context()), `DROP TRIGGER authz_ui_binding_audit_failure`)
			require.NoError(t, err)
		})
	}
	before := unittest.GetCount(t, &authz_model.SubjectRoleBinding{})
	response = admin.MakeRequest(t, authzBindingForm(t, admin, base, map[string]string{"subject_type": "user", "subject_id": "4", "role_id": strconv.FormatInt(role.Definition.ID, 10)}), http.StatusInternalServerError)
	require.NotContains(t, response.Body.String(), "TOPSECRET")
	require.NotContains(t, response.Body.String(), "TOPTOKEN")
	require.Equal(t, before, unittest.GetCount(t, &authz_model.SubjectRoleBinding{}))
	require.Equal(t, "4", NewHTMLParser(t, response.Body).Find(`input[name="subject_id"]`).AttrOr("value", ""))
	binding := unittest.AssertExistsAndLoadBean(t, &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectTeam, SubjectID: 2})
	request := authzBindingForm(t, admin, base, map[string]string{})
	request.Request.URL.Path = base + "/bindings/" + strconv.FormatInt(binding.ID, 10) + "/delete"
	response = admin.MakeRequest(t, request, http.StatusInternalServerError)
	require.NotContains(t, response.Body.String(), "TOPSECRET")
	unittest.AssertExistsAndLoadBean(t, &authz_model.SubjectRoleBinding{ID: binding.ID})
}

func TestEnterpriseAuthzUIBindingConcurrentCreateAndRoleDelete(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	admin := loginUser(t, "user1")
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 3}
	base := "/-/admin/enterprise/authz/scopes/repo/3"
	role, err := authz_service.CreateRole(t.Context(), actor, scope, authz_service.CreateRoleInput{Name: "Concurrent binding"})
	require.NoError(t, err)
	requests := make([]*RequestWrapper, 2)
	for i := range requests {
		requests[i] = authzBindingForm(t, admin, base, map[string]string{"subject_type": "user", "subject_id": "4", "role_id": strconv.FormatInt(role.Definition.ID, 10)})
	}
	var wait sync.WaitGroup
	start := make(chan struct{})
	for _, request := range requests {
		wait.Go(func() { <-start; admin.MakeRequest(t, request, http.StatusSeeOther) })
	}
	close(start)
	wait.Wait()
	unittest.AssertCount(t, &authz_model.SubjectRoleBinding{RoleID: role.Definition.ID}, 1)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzBindingAdd}, 1)
	require.ErrorIs(t, authz_service.DeleteRole(t.Context(), actor, scope, role.Definition.ID, 1), authz_service.ErrRoleReferenced)
	other, err := authz_service.CreateRole(t.Context(), actor, scope, authz_service.CreateRoleInput{Name: "Delete race"})
	require.NoError(t, err)
	request := authzBindingForm(t, admin, base, map[string]string{"subject_type": "user", "subject_id": "4", "role_id": strconv.FormatInt(other.Definition.ID, 10)})
	results := make(chan int, 1)
	deleteResults := make(chan error, 1)
	start = make(chan struct{})
	wait.Go(func() { <-start; results <- admin.MakeRequest(t, request, NoExpectedStatus).Code })
	wait.Go(func() {
		<-start
		deleteResults <- authz_service.DeleteRole(t.Context(), actor, scope, other.Definition.ID, 1)
	})
	close(start)
	wait.Wait()
	status, deleteErr := <-results, <-deleteResults
	if deleteErr == nil {
		require.Equal(t, http.StatusNotFound, status)
		unittest.AssertNotExistsBean(t, &authz_model.SubjectRoleBinding{RoleID: other.Definition.ID})
	} else {
		require.ErrorIs(t, deleteErr, authz_service.ErrRoleReferenced)
		require.Equal(t, http.StatusSeeOther, status)
		unittest.AssertCount(t, &authz_model.SubjectRoleBinding{RoleID: other.Definition.ID}, 1)
	}
}
