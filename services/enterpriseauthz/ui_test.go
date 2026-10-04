// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"bytes"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	wecom_model "gitea.dev/models/enterprisewecom"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/util"

	"github.com/stretchr/testify/require"
	xormlog "xorm.io/xorm/log"
)

func TestManagementUIRequiresCurrentSuperAdminBeforeTarget(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	for _, scope := range []authz_model.Scope{{Type: authz_model.ScopeSystem}, {Type: authz_model.ScopeOrg, ID: 3}, {Type: authz_model.ScopeRepo, ID: 1}, {Type: authz_model.ScopeRepo, ID: 999999}} {
		_, err := NewManagementUI(t.Context(), owner, scope)
		require.ErrorIs(t, err, util.ErrPermissionDenied)
	}
	forged := *owner
	forged.IsAdmin = true
	require.ErrorIs(t, CheckUIAuthority(t.Context(), &forged), util.ErrPermissionDenied)
	synthetic := *admin
	synthetic.ExtDoerData = user_model.NewActionsUserWithTaskID(1).ExtDoerData
	require.ErrorIs(t, CheckUIAuthority(t.Context(), &synthetic), util.ErrPermissionDenied)
	require.NoError(t, CheckUIAuthority(t.Context(), admin))
	setting.EnterpriseAuthz.Enabled = false
	require.ErrorIs(t, CheckUIAuthority(t.Context(), owner), util.ErrPermissionDenied)
	engine := db.GetXORMEngineForTesting()
	previous := engine.Logger()
	var queries bytes.Buffer
	logger := xormlog.NewSimpleLogger(&queries)
	logger.ShowSQL(true)
	engine.SetLogger(logger)
	t.Cleanup(func() { engine.SetLogger(previous) })
	_, err := NewManagementUI(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 999999})
	require.ErrorIs(t, err, util.ErrNotExist)
	require.NotContains(t, queries.String(), "role_definition")
	require.NotContains(t, queries.String(), "subject_role_binding")
	require.NotContains(t, queries.String(), "FROM `repository`")
}

func TestManagementUIRechecksEveryOperation(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	_, err := db.GetEngine(t.Context()).ID(admin.ID).Cols("is_admin").Update(&user_model.User{IsAdmin: true})
	require.NoError(t, err)
	ui, err := NewManagementUI(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1})
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).ID(admin.ID).Cols("is_admin").Update(&user_model.User{IsAdmin: false})
	require.NoError(t, err)
	calls := []func() error{
		func() error { _, _, e := ui.Select("user", "", PolicyListOptions{}); return e },
		func() error { _, e := ui.Selection("user", 2); return e },
		func() error { _, _, e := ui.Roles(PolicyListOptions{}); return e },
		func() error { _, e := ui.Role(1); return e },
		func() error { _, e := ui.CreateRole(CreateRoleInput{Name: "Denied"}); return e },
		func() error { _, e := ui.UpdateRole(1, UpdateRoleInput{ExpectedRevision: 1}); return e },
		func() error { return ui.DeleteRole(1, 1) },
		func() error { _, _, e := ui.Bindings(PolicyListOptions{}); return e },
		func() error { _, _, e := ui.PutBinding(BindingInput{}); return e },
		func() error { return ui.DeleteBinding(1) },
		func() error { _, _, e := ui.Decisions(DecisionListOptions{}); return e },
		func() error { _, e := ui.Decision(1); return e },
		func() error { _, e := ui.Evaluate(DiagnosticInput{}); return e },
		func() error { _, e := ui.EffectivePermissions(DiagnosticInput{}); return e },
	}
	for _, call := range calls {
		require.ErrorIs(t, call(), util.ErrPermissionDenied)
	}
	unittest.AssertCount(t, &authz_model.RoleDefinition{}, 0)
	unittest.AssertCount(t, &audit_model.Event{}, 0)
}

func TestManagementUIWeComAuthorityRevocation(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "ui-corp", AgentID: "ui-app"}))
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	require.ErrorIs(t, CheckUIAuthority(t.Context(), admin), util.ErrPermissionDenied)
	authority := &wecom_model.AdminAuthority{CorpID: "ui-corp", AgentID: "ui-app", WeComUserID: "super", IsManagement: true, IsActive: true}
	require.NoError(t, db.Insert(t.Context(), authority))
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: admin.ID, CorpID: "ui-corp", WeComUserID: "super", Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	ui, err := NewManagementUI(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1})
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).ID(authority.ID).Cols("is_active").Update(&wecom_model.AdminAuthority{IsActive: false})
	require.NoError(t, err)
	_, _, err = ui.Roles(PolicyListOptions{})
	require.ErrorIs(t, err, util.ErrPermissionDenied)
}

func TestManagementUIReusesScopedPolicyAndForcesDiagnosticCaller(t *testing.T) {
	for _, scope := range []authz_model.Scope{{Type: authz_model.ScopeSystem}, {Type: authz_model.ScopeOrg, ID: 3}, {Type: authz_model.ScopeRepo, ID: 1}} {
		t.Run(string(scope.Type), func(t *testing.T) {
			enableObservation(t)
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
			admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
			ui, err := NewManagementUI(t.Context(), admin, scope)
			require.NoError(t, err)
			role, err := ui.CreateRole(CreateRoleInput{Name: "UI role", Permissions: &[]PermissionInput{{Action: authz.ReadCode, Effect: "allow"}}})
			require.NoError(t, err)
			roles, total, err := ui.Roles(PolicyListOptions{})
			require.NoError(t, err)
			require.EqualValues(t, 1, total)
			require.Len(t, roles, 1)
			loaded, err := ui.Role(role.Definition.ID)
			require.NoError(t, err)
			require.Equal(t, role.Definition.ID, loaded.Definition.ID)
			role, err = ui.UpdateRole(role.Definition.ID, UpdateRoleInput{ExpectedRevision: 1})
			require.NoError(t, err)
			_, err = ui.UpdateRole(role.Definition.ID, UpdateRoleInput{ExpectedRevision: 1})
			require.ErrorIs(t, err, ErrRevisionConflict)
			binding, created, err := ui.PutBinding(BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 2, RoleID: role.Definition.ID})
			require.NoError(t, err)
			require.True(t, created)
			bindings, total, err := ui.Bindings(PolicyListOptions{})
			require.NoError(t, err)
			require.EqualValues(t, 1, total)
			require.Len(t, bindings, 1)
			require.ErrorIs(t, ui.DeleteRole(role.Definition.ID, 2), ErrRoleReferenced)
			require.NoError(t, ui.DeleteBinding(binding.ID))
			require.NoError(t, ui.DeleteRole(role.Definition.ID, 2))
			_, total, err = ui.Decisions(DecisionListOptions{})
			require.NoError(t, err)
			require.Zero(t, total)
			_, err = ui.Decision(99999)
			require.ErrorIs(t, err, util.ErrNotExist)
			if scope.Type != authz_model.ScopeRepo {
				_, err = ui.Evaluate(DiagnosticInput{})
				require.ErrorIs(t, err, util.ErrNotExist)
				return
			}
			input := DiagnosticInput{Caller: &user_model.User{ID: 2}, Repo: &repo_model.Repository{ID: scope.ID, OwnerID: 99999}, Credential: CredentialCeiling{Reference: "access-token:99999"}, Action: authz.ReadCode}
			result, err := ui.Evaluate(input)
			require.NoError(t, err)
			require.Equal(t, "allow", result.CandidateDecision)
			require.True(t, result.CandidateOnly)
			effective, err := ui.EffectivePermissions(input)
			require.NoError(t, err)
			require.Contains(t, effective.NativeActions, authz.ReadCode)
			events := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDiagnostic})
			require.Equal(t, admin.ID, events.ActorID)
			require.Contains(t, events.Metadata, `"target_user_id":1`)
			require.NotEqual(t, "access-token:99999", events.ActorCredential)
			input.Repo.ID = 2
			_, err = ui.Evaluate(input)
			require.ErrorIs(t, err, util.ErrNotExist)
		})
	}
}
