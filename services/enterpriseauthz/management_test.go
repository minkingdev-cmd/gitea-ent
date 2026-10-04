// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"strings"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/util"
	"gitea.dev/modules/web/middleware"
	"gitea.dev/services/audit"

	"github.com/stretchr/testify/require"
)

func TestPolicyManagementCanRemoveInactiveBindingsAfterTransfer(t *testing.T) {
	for _, tt := range []struct {
		name      string
		repoID    int64
		roleScope authz_model.Scope
	}{
		{"repo role", 1, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}},
		{"former org role", 3, authz_model.Scope{Type: authz_model.ScopeOrg, ID: 3}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			enableObservation(t)
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
			newOwner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
			scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: tt.repoID}
			role, err := CreateRole(t.Context(), actor, tt.roleScope, CreateRoleInput{Name: "Transferred", Permissions: &[]PermissionInput{{Action: authz.CreateBranch, Effect: "allow"}}})
			require.NoError(t, err)
			binding, created, err := PutBinding(t.Context(), actor, scope, BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: actor.ID, RoleID: role.Definition.ID})
			require.NoError(t, err)
			require.True(t, created)
			_, err = db.GetEngine(t.Context()).ID(tt.repoID).Cols("owner_id").Update(&repo_model.Repository{OwnerID: newOwner.ID})
			require.NoError(t, err)
			repository := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: tt.repoID})
			permission := access_model.Permission{AccessMode: perm.AccessModeRead}
			permission.SetUnitsWithDefaultAccessMode([]*repo_model.RepoUnit{{Type: unit.TypeCode}}, perm.AccessModeRead)
			decision, err := Evaluate(t.Context(), EvaluateInput{Actor: actor, Repo: repository, Permission: &permission, Credential: CredentialCeiling{Read: true, Write: true}, Action: authz.CreateBranch, ConditionContext: authz.ConditionContext{Source: "api"}})
			require.NoError(t, err)
			require.Equal(t, "missing_action", decision.Reason)
			require.Empty(t, decision.RoleActions)
			bindings, total, err := ListBindings(t.Context(), newOwner, scope, PolicyListOptions{})
			require.NoError(t, err)
			require.EqualValues(t, 1, total)
			require.Len(t, bindings, 1)
			require.Equal(t, binding.ScopeOwnerID, bindings[0].ScopeOwnerID)
			require.NotEqual(t, newOwner.ID, bindings[0].ScopeOwnerID)
			require.ErrorIs(t, DeleteRole(t.Context(), admin, tt.roleScope, role.Definition.ID, 1), ErrRoleReferenced)
			require.NoError(t, DeleteBinding(t.Context(), newOwner, scope, binding.ID))
			if tt.roleScope.Type == authz_model.ScopeRepo {
				newBinding, created, err := PutBinding(t.Context(), newOwner, scope, BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: actor.ID, RoleID: role.Definition.ID})
				require.NoError(t, err)
				require.True(t, created)
				require.Equal(t, newOwner.ID, newBinding.ScopeOwnerID)
				require.NotEqual(t, binding.ID, newBinding.ID)
				require.NoError(t, DeleteBinding(t.Context(), newOwner, scope, newBinding.ID))
			}
			require.NoError(t, DeleteRole(t.Context(), admin, tt.roleScope, role.Definition.ID, 1))
			unittest.AssertCount(t, &authz_model.SubjectRoleBinding{}, 0)
		})
	}
}

func TestPolicyManagementAuditKeepsTrustedCredentialAndImpersonator(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	ctx := reqctx.NewRequestContextForTest(t)
	ctx.GetData()[middleware.ContextDataKeySignedUser] = actor
	ctx.GetData()[middleware.ContextDataKeyAuthCredential] = "access-token:7"
	_, err := CreateRole(audit.WithImpersonator(ctx, &user_model.User{ID: 1, Name: "private-admin@example.com"}), actor, scope, CreateRoleInput{Name: "Trusted"})
	require.NoError(t, err)
	event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzRoleCreate})
	require.Equal(t, "access-token:7", event.ActorCredential)
	require.Equal(t, int64(1), event.ImpersonatorID)
	require.NotContains(t, event.ImpersonatorName, "private-admin")
}

func TestPolicyManagementRejectsMalformedPersistedPermissions(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	role, err := CreateRole(t.Context(), actor, scope, CreateRoleInput{Name: "Corrupt"})
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.Definition.ID, Action: authz.ReadCode, Effect: "allow", ConditionJSON: `{}`, ConditionHash: "invalid"}))
	_, err = GetRole(t.Context(), actor, scope, role.Definition.ID)
	require.ErrorIs(t, err, ErrPolicyStorage)
	_, _, err = ListRoles(t.Context(), actor, scope, PolicyListOptions{})
	require.ErrorIs(t, err, ErrPolicyStorage)
	_, err = CreateRole(t.Context(), actor, scope, CreateRoleInput{Name: "Copy corrupt", CopyFromRoleID: role.Definition.ID})
	require.ErrorIs(t, err, ErrPolicyStorage)
	unittest.AssertCount(t, &authz_model.RoleDefinition{}, 1)
	unittest.AssertCount(t, &audit_model.Event{}, 1)
}

func TestPolicyManagementCopiesBuiltinWithoutInheritance(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	key := "reporter"
	source := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeSystem, Name: "Reporter", LowerName: "reporter", BuiltinKey: &key, Revision: 1}
	require.NoError(t, db.Insert(t.Context(), source))
	_, normalized, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	for _, action := range authz.BuiltinRoles()[key] {
		require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: source.ID, Action: action, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}))
	}
	copyRole, err := CreateRole(t.Context(), actor, scope, CreateRoleInput{Name: "Reviewer custom", CopyFromRoleID: source.ID})
	require.NoError(t, err)
	permissions := []PermissionInput{}
	for _, permission := range copyRole.Permissions {
		permissions = append(permissions, PermissionInput{Action: permission.Action, Effect: permission.Effect, Condition: []byte(permission.ConditionJSON)})
	}
	permissions = append(permissions, PermissionInput{Action: authz.ReviewPullRequest, Effect: "allow"})
	copyRole, err = UpdateRole(t.Context(), actor, scope, copyRole.Definition.ID, UpdateRoleInput{ExpectedRevision: 1, Permissions: &permissions})
	require.NoError(t, err)
	require.Len(t, copyRole.Permissions, 4)
	require.Nil(t, copyRole.Definition.BuiltinKey)
	original, err := GetRole(t.Context(), actor, scope, source.ID)
	require.NoError(t, err)
	require.Len(t, original.Permissions, 3)
	require.Equal(t, int64(1), original.Definition.Revision)
}

func TestPolicyManagementRoleSnapshotRevisionAndBindingLifecycle(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	permissions := []PermissionInput{{Action: authz.ReadCode, Effect: "allow", Condition: []byte(`{}`)}}
	role, err := CreateRole(t.Context(), actor, scope, CreateRoleInput{Name: "Builder", Description: "private-secret@example.com", Permissions: &permissions})
	require.NoError(t, err)
	require.Equal(t, int64(1), role.Definition.Revision)
	require.Len(t, role.Permissions, 1)
	copyRole, err := CreateRole(t.Context(), actor, scope, CreateRoleInput{Name: "Copy", CopyFromRoleID: role.Definition.ID})
	require.NoError(t, err)
	require.Len(t, copyRole.Permissions, 1)
	_, err = CreateRole(t.Context(), actor, scope, CreateRoleInput{Name: "bUiLdEr"})
	require.ErrorIs(t, err, ErrRoleNameConflict)
	_, err = UpdateRole(t.Context(), actor, scope, role.Definition.ID, UpdateRoleInput{})
	require.ErrorIs(t, err, ErrRevisionConflict)
	empty := []PermissionInput{}
	role, err = UpdateRole(t.Context(), actor, scope, role.Definition.ID, UpdateRoleInput{ExpectedRevision: 1, Permissions: &empty})
	require.NoError(t, err)
	require.Equal(t, int64(2), role.Definition.Revision)
	require.Empty(t, role.Permissions)
	copyRole, err = GetRole(t.Context(), actor, scope, copyRole.Definition.ID)
	require.NoError(t, err)
	require.Len(t, copyRole.Permissions, 1)
	listed, total, err := ListRoles(t.Context(), actor, scope, PolicyListOptions{Limit: 1})
	require.NoError(t, err)
	require.Equal(t, int64(2), total)
	require.Len(t, listed, 1)
	_, _, err = ListRoles(t.Context(), actor, scope, PolicyListOptions{Limit: 101})
	require.ErrorIs(t, err, ErrInvalidPolicy)
	role, err = UpdateRole(t.Context(), actor, scope, role.Definition.ID, UpdateRoleInput{ExpectedRevision: 2})
	require.NoError(t, err)
	require.Equal(t, int64(3), role.Definition.Revision)
	require.Empty(t, role.Permissions)
	bindingInput := BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: copyRole.Definition.ID}
	binding, created, err := PutBinding(t.Context(), actor, scope, bindingInput)
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, int64(2), binding.ScopeOwnerID)
	duplicate, created, err := PutBinding(t.Context(), actor, scope, bindingInput)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, binding.ID, duplicate.ID)
	bindings, total, err := ListBindings(t.Context(), actor, scope, PolicyListOptions{})
	require.NoError(t, err)
	require.Equal(t, int64(1), total)
	require.Len(t, bindings, 1)
	_, _, err = ListBindings(t.Context(), actor, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 2}, PolicyListOptions{})
	require.NoError(t, err)
	require.ErrorIs(t, DeleteBinding(t.Context(), actor, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 2}, binding.ID), util.ErrNotExist)
	require.ErrorIs(t, DeleteRole(t.Context(), actor, scope, copyRole.Definition.ID, 1), ErrRoleReferenced)
	require.NoError(t, DeleteBinding(t.Context(), actor, scope, binding.ID))
	require.ErrorIs(t, DeleteBinding(t.Context(), actor, scope, binding.ID), util.ErrNotExist)
	require.NoError(t, DeleteRole(t.Context(), actor, scope, copyRole.Definition.ID, 1))
	require.ErrorIs(t, DeleteRole(t.Context(), actor, scope, role.Definition.ID, 2), ErrRevisionConflict)
	require.NoError(t, DeleteRole(t.Context(), actor, scope, role.Definition.ID, 3))
	unittest.AssertCount(t, &authz_model.RoleDefinition{}, 0)
	unittest.AssertCount(t, &authz_model.RolePermission{}, 0)
	unittest.AssertCount(t, &authz_model.SubjectRoleBinding{}, 0)
	var events []*audit_model.Event
	require.NoError(t, db.GetEngine(t.Context()).Where("action LIKE ?", "enterprise:authz:%").Find(&events))
	require.Len(t, events, 8)
	data, err := json.Marshal(events)
	require.NoError(t, err)
	require.NotContains(t, string(data), "private-secret@example.com")
}

func TestPolicyManagementRejectsInvalidOrCrossScopeMutations(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	member := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	system := authz_model.Scope{Type: authz_model.ScopeSystem}
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	key := "platform-admin"
	builtin := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeSystem, Name: "Platform Admin", LowerName: "platform admin", BuiltinKey: &key, Revision: 1}
	require.NoError(t, db.Insert(t.Context(), builtin))
	_, err := UpdateRole(t.Context(), admin, system, builtin.ID, UpdateRoleInput{ExpectedRevision: 1})
	require.ErrorIs(t, err, ErrBuiltinImmutable)
	require.ErrorIs(t, DeleteRole(t.Context(), owner, scope, builtin.ID, 1), ErrBuiltinImmutable)
	_, _, err = PutBinding(t.Context(), owner, scope, BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: builtin.ID})
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	_, _, err = PutBinding(t.Context(), admin, system, BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: builtin.ID})
	require.NoError(t, err)
	_, err = CreateRole(t.Context(), member, scope, CreateRoleInput{Name: "Self grant"})
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	for _, input := range []CreateRoleInput{
		{Name: " "},
		{Name: strings.Repeat("x", 65)},
		{Name: "Unknown", Permissions: &[]PermissionInput{{Action: "repo.unknown", Effect: "allow"}}},
		{Name: "Deny", Permissions: &[]PermissionInput{{Action: authz.ReadCode, Effect: "deny"}}},
		{Name: "Condition", Permissions: &[]PermissionInput{{Action: authz.ReadCode, Effect: "allow", Condition: []byte(`{"path_pattern":[]}`)}}},
	} {
		_, err := CreateRole(t.Context(), owner, scope, input)
		require.ErrorIs(t, err, ErrInvalidPolicy)
	}
	other, err := CreateRole(t.Context(), owner, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 2}, CreateRoleInput{Name: "Other"})
	require.NoError(t, err)
	_, err = GetRole(t.Context(), owner, scope, other.Definition.ID)
	require.ErrorIs(t, err, util.ErrNotExist)
	_, err = UpdateRole(t.Context(), owner, scope, other.Definition.ID, UpdateRoleInput{ExpectedRevision: 1})
	require.ErrorIs(t, err, util.ErrNotExist)
	_, _, err = PutBinding(t.Context(), owner, scope, BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: other.Definition.ID})
	require.ErrorIs(t, err, util.ErrNotExist)
	local, err := CreateRole(t.Context(), owner, scope, CreateRoleInput{Name: "Local"})
	require.NoError(t, err)
	for _, input := range []BindingInput{
		{SubjectType: "repo", SubjectID: 1, RoleID: local.Definition.ID},
		{SubjectType: authz_model.SubjectUser, SubjectID: 3, RoleID: local.Definition.ID},
		{SubjectType: authz_model.SubjectUser, SubjectID: 99999, RoleID: local.Definition.ID},
		{SubjectType: authz_model.SubjectTeam, SubjectID: 2, RoleID: local.Definition.ID},
		{SubjectType: authz_model.SubjectOrg, SubjectID: 3, RoleID: local.Definition.ID},
	} {
		_, _, err := PutBinding(t.Context(), owner, scope, input)
		require.ErrorIs(t, err, ErrInvalidPolicy)
	}
	orgScope := authz_model.Scope{Type: authz_model.ScopeOrg, ID: 3}
	orgRole, err := CreateRole(t.Context(), owner, orgScope, CreateRoleInput{Name: "Org"})
	require.NoError(t, err)
	orgRepoScope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 3}
	for _, subject := range []BindingInput{
		{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: orgRole.Definition.ID},
		{SubjectType: authz_model.SubjectTeam, SubjectID: 2, RoleID: orgRole.Definition.ID},
		{SubjectType: authz_model.SubjectOrg, SubjectID: 3, RoleID: orgRole.Definition.ID},
	} {
		_, _, err := PutBinding(t.Context(), owner, orgRepoScope, subject)
		require.NoError(t, err)
	}
	_, _, err = PutBinding(t.Context(), owner, orgRepoScope, BindingInput{SubjectType: authz_model.SubjectTeam, SubjectID: 3, RoleID: orgRole.Definition.ID})
	require.ErrorIs(t, err, ErrInvalidPolicy)
	require.NoError(t, organization.RemoveTeamRepo(t.Context(), 2, 3))
	_, _, err = PutBinding(t.Context(), owner, orgRepoScope, BindingInput{SubjectType: authz_model.SubjectTeam, SubjectID: 2, RoleID: orgRole.Definition.ID})
	require.ErrorIs(t, err, ErrInvalidPolicy)
	setting.EnterpriseAuthz.Enabled = false
	_, err = CreateRole(t.Context(), owner, scope, CreateRoleInput{Name: "Disabled"})
	require.ErrorIs(t, err, util.ErrNotExist)
	_, err = CreateRole(t.Context(), member, scope, CreateRoleInput{Name: "Disabled unauthorized"})
	require.ErrorIs(t, err, util.ErrPermissionDenied)
}

func TestPolicyManagementAuditFailureRollsBackWithoutLeakingError(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	permissions := []PermissionInput{{Action: authz.ReadCode, Effect: "allow"}}
	role, err := CreateRole(t.Context(), actor, scope, CreateRoleInput{Name: "Unchanged", Permissions: &permissions})
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Exec(`CREATE TRIGGER authz_management_audit_failure BEFORE INSERT ON audit_event BEGIN SELECT RAISE(ABORT, 'secret=TOPSECRET token=TOPTOKEN code=OAUTH private/path'); END`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.GetEngine(context.WithoutCancel(t.Context())).Exec("DROP TRIGGER authz_management_audit_failure")
		require.NoError(t, err)
	})
	_, err = UpdateRole(t.Context(), actor, scope, role.Definition.ID, UpdateRoleInput{ExpectedRevision: 1, Permissions: &[]PermissionInput{}})
	require.ErrorIs(t, err, ErrPolicyStorage)
	require.NotContains(t, err.Error(), "TOPSECRET")
	_, err = CreateRole(t.Context(), actor, scope, CreateRoleInput{Name: "Not persisted"})
	require.ErrorIs(t, err, ErrPolicyStorage)
	err = db.WithTx(t.Context(), func(tx context.Context) error {
		_, mutationErr := UpdateRole(tx, actor, scope, role.Definition.ID, UpdateRoleInput{ExpectedRevision: 1, Permissions: &[]PermissionInput{}})
		require.ErrorIs(t, mutationErr, ErrPolicyStorage)
		return nil
	})
	require.ErrorIs(t, err, ErrPolicyStorage)
	unchanged, err := GetRole(t.Context(), actor, scope, role.Definition.ID)
	require.NoError(t, err)
	require.Equal(t, int64(1), unchanged.Definition.Revision)
	require.Len(t, unchanged.Permissions, 1)
	_, _, err = PutBinding(t.Context(), actor, scope, BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: role.Definition.ID})
	require.ErrorIs(t, err, ErrPolicyStorage)
	unittest.AssertCount(t, &authz_model.SubjectRoleBinding{}, 0)
	require.ErrorIs(t, DeleteRole(t.Context(), actor, scope, role.Definition.ID, 1), ErrPolicyStorage)
	unittest.AssertCount(t, &authz_model.RoleDefinition{}, 1)
	unittest.AssertCount(t, &authz_model.RolePermission{}, 1)
	unittest.AssertCount(t, &audit_model.Event{}, 1)
}

func TestManagementAuthorityUsesNativeStateNotRoleOrActorClaims(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	system := authz_model.Scope{Type: authz_model.ScopeSystem}
	org := authz_model.Scope{Type: authz_model.ScopeOrg, ID: 3}
	repo := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 3}
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	member := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	for _, scope := range []authz_model.Scope{system, org, repo} {
		require.NoError(t, CheckManagementAuthority(t.Context(), admin, scope))
	}
	require.NoError(t, CheckManagementAuthority(t.Context(), owner, org))
	require.NoError(t, CheckManagementAuthority(t.Context(), owner, repo))
	member.IsAdmin = true
	require.ErrorIs(t, CheckManagementAuthority(t.Context(), member, system), util.ErrPermissionDenied)
	require.ErrorIs(t, CheckManagementAuthority(t.Context(), member, org), util.ErrPermissionDenied)
	require.ErrorIs(t, CheckManagementAuthority(t.Context(), member, repo), util.ErrPermissionDenied)
	_, err := db.GetEngine(t.Context()).Where("user_id = ? AND repo_id = ?", member.ID, repo.ID).Cols("mode").Update(&access_model.Access{Mode: perm.AccessModeAdmin})
	require.NoError(t, err)
	require.NoError(t, CheckManagementAuthority(t.Context(), member, repo))
	key := "platform-admin"
	role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeSystem, Name: "Platform Admin", LowerName: "platform admin", BuiltinKey: &key, Revision: 1}
	require.NoError(t, db.Insert(t.Context(), role))
	require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: member.ID, ScopeType: authz_model.ScopeSystem, RoleID: role.ID}))
	require.ErrorIs(t, CheckManagementAuthority(t.Context(), member, system), util.ErrPermissionDenied)
	require.ErrorIs(t, CheckManagementAuthority(t.Context(), nil, system), util.ErrPermissionDenied)
	require.ErrorIs(t, CheckManagementAuthority(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeOrg, ID: 1}), util.ErrNotExist)
	_, err = db.GetEngine(t.Context()).ID(admin.ID).Cols("is_active").Update(&user_model.User{IsActive: false})
	require.NoError(t, err)
	require.ErrorIs(t, CheckManagementAuthority(t.Context(), admin, system), util.ErrPermissionDenied)
}

func TestManagementAuthorityPreservesStrictWeComCreatorOwnerAndBoundSuperAdmin(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-authz-manage", AgentID: "1000002"}))
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	creator := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
	repo := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 3}
	org := authz_model.Scope{Type: authz_model.ScopeOrg, ID: 3}
	system := authz_model.Scope{Type: authz_model.ScopeSystem}
	require.NoError(t, db.Insert(t.Context(), &wecom_model.RepositoryGovernance{RepoID: 3, CreatorID: creator.ID}))
	require.ErrorIs(t, CheckManagementAuthority(t.Context(), admin, system), util.ErrPermissionDenied)
	require.ErrorIs(t, CheckManagementAuthority(t.Context(), admin, org), util.ErrPermissionDenied)
	require.ErrorIs(t, CheckManagementAuthority(t.Context(), admin, repo), util.ErrPermissionDenied)
	require.NoError(t, CheckManagementAuthority(t.Context(), owner, org))
	require.NoError(t, CheckManagementAuthority(t.Context(), owner, repo))
	require.ErrorIs(t, CheckManagementAuthority(t.Context(), creator, repo), util.ErrPermissionDenied)
	require.NoError(t, db.Insert(t.Context(), &access_model.Access{UserID: creator.ID, RepoID: repo.ID, Mode: perm.AccessModeRead}))
	require.NoError(t, CheckManagementAuthority(t.Context(), creator, repo))
	require.ErrorIs(t, CheckManagementAuthority(t.Context(), creator, org), util.ErrPermissionDenied)
	require.NoError(t, db.Insert(t.Context(), &wecom_model.AdminAuthority{CorpID: "corp-authz-manage", AgentID: "1000002", WeComUserID: "management.super", IsManagement: true, IsActive: true}))
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: admin.ID, CorpID: "corp-authz-manage", WeComUserID: "management.super", Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	for _, scope := range []authz_model.Scope{system, org, repo} {
		require.NoError(t, CheckManagementAuthority(t.Context(), admin, scope))
	}
	_, err = db.GetEngine(t.Context()).Where("corp_id = ?", "corp-authz-manage").Cols("is_active").Update(&wecom_model.AdminAuthority{IsActive: false})
	require.NoError(t, err)
	require.ErrorIs(t, CheckManagementAuthority(t.Context(), admin, repo), util.ErrPermissionDenied)
}
