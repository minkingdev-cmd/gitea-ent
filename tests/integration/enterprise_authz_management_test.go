// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"errors"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/util"
	authz_service "gitea.dev/services/enterpriseauthz"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzPolicySnapshotIncludesNativeStateAndPermissions(t *testing.T) {
	if !setting.Database.Type.IsPostgreSQL() {
		t.Skip("PostgreSQL 一致读快照验收")
	}
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repository := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: repository.ID}
	role, err := authz_service.CreateRole(t.Context(), actor, scope, authz_service.CreateRoleInput{Name: "Snapshot", Permissions: &[]authz_service.PermissionInput{{Action: authz.CreateBranch, Effect: "allow"}}})
	require.NoError(t, err)
	_, _, err = authz_service.PutBinding(t.Context(), actor, scope, authz_service.BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: actor.ID, RoleID: role.Definition.ID})
	require.NoError(t, err)
	require.NoError(t, db.WithIndependentReadTx(t.Context(), func(snapshot context.Context) error {
		before, exists, err := db.GetByID[authz_model.RoleDefinition](snapshot, role.Definition.ID)
		require.NoError(t, err)
		require.True(t, exists)
		require.EqualValues(t, 1, before.Revision)
		require.NoError(t, db.WithIndependentTx(t.Context(), func(writer context.Context) error {
			_, err := authz_service.UpdateRole(writer, actor, scope, role.Definition.ID, authz_service.UpdateRoleInput{ExpectedRevision: 1, Permissions: &[]authz_service.PermissionInput{}})
			if err != nil {
				return err
			}
			if _, err := db.GetEngine(writer).ID(repository.ID).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 4}); err != nil {
				return err
			}
			_, err = db.GetEngine(writer).ID(actor.ID).Cols("is_active").Update(&user_model.User{IsActive: false})
			return err
		}))
		current, exists, err := db.GetByID[authz_model.RoleDefinition](snapshot, role.Definition.ID)
		require.NoError(t, err)
		require.True(t, exists)
		require.Equal(t, before.Revision, current.Revision)
		var permissions []authz_model.RolePermission
		require.NoError(t, db.GetEngine(snapshot).Where("role_id = ?", role.Definition.ID).Find(&permissions))
		require.Len(t, permissions, 1)
		oldRepo, exists, err := db.GetByID[repo_model.Repository](snapshot, repository.ID)
		require.NoError(t, err)
		require.True(t, exists)
		require.Equal(t, repository.OwnerID, oldRepo.OwnerID)
		oldActor, exists, err := db.GetByID[user_model.User](snapshot, actor.ID)
		require.NoError(t, err)
		require.True(t, exists)
		require.True(t, oldActor.IsActive)
		return nil
	}))
	permission := access_model.Permission{AccessMode: perm.AccessModeRead}
	permission.SetUnitsWithDefaultAccessMode([]*repo_model.RepoUnit{{Type: unit.TypeCode}}, perm.AccessModeRead)
	decision, err := authz_service.Evaluate(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: repository, Permission: &permission, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, Action: authz.CreateBranch, ConditionContext: authz.ConditionContext{Source: "api"}})
	require.NoError(t, err)
	require.Equal(t, "actor_inactive", decision.Reason)
	var snapshot struct {
		OwnerID int64 `json:"owner_id"`
	}
	require.NoError(t, json.Unmarshal([]byte(decision.Snapshot), &snapshot))
	require.EqualValues(t, 4, snapshot.OwnerID)
	unittest.AssertCount(t, &authz_model.RolePermission{RoleID: role.Definition.ID}, 0)
	unittest.AssertExistsAndLoadBean(t, &authz_model.RoleDefinition{ID: role.Definition.ID, Revision: 2})
}

func TestEnterpriseAuthzPolicyConcurrentMutations(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	scope := authz_model.Scope{Type: authz_model.ScopeSystem}
	repoScope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	initial := []authz_service.PermissionInput{{Action: authz.ReadCode, Effect: "allow"}}
	role, err := authz_service.CreateRole(t.Context(), admin, scope, authz_service.CreateRoleInput{Name: "Concurrent", Permissions: &initial})
	require.NoError(t, err)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, action := range []authz.Action{authz.PushBranch, authz.ReviewPullRequest} {
		go func() {
			<-start
			permissions := []authz_service.PermissionInput{{Action: action, Effect: "allow"}}
			_, err := authz_service.UpdateRole(t.Context(), admin, scope, role.Definition.ID, authz_service.UpdateRoleInput{ExpectedRevision: 1, Permissions: &permissions})
			results <- err
		}()
	}
	close(start)
	first, second := <-results, <-results
	if first != nil {
		first, second = second, first
	}
	require.NoError(t, first)
	require.ErrorIs(t, second, authz_service.ErrRevisionConflict)
	updated, err := authz_service.GetRole(t.Context(), admin, scope, role.Definition.ID)
	require.NoError(t, err)
	require.Equal(t, int64(2), updated.Definition.Revision)
	require.Len(t, updated.Permissions, 1)
	require.Contains(t, []authz.Action{authz.PushBranch, authz.ReviewPullRequest}, updated.Permissions[0].Action)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzRoleUpdate}, 1)
	start = make(chan struct{})
	go func() {
		<-start
		_, _, err := authz_service.PutBinding(t.Context(), actor, repoScope, authz_service.BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: role.Definition.ID})
		results <- err
	}()
	go func() { <-start; results <- authz_service.DeleteRole(t.Context(), admin, scope, role.Definition.ID, 2) }()
	close(start)
	first, second = <-results, <-results
	if first != nil {
		first, second = second, first
	}
	require.NoError(t, first)
	require.True(t, errors.Is(second, authz_service.ErrRoleReferenced) || errors.Is(second, util.ErrNotExist))
	if errors.Is(second, authz_service.ErrRoleReferenced) {
		unittest.AssertCount(t, &authz_model.RoleDefinition{ID: role.Definition.ID}, 1)
		unittest.AssertCount(t, &authz_model.SubjectRoleBinding{RoleID: role.Definition.ID}, 1)
		unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzBindingAdd}, 1)
		unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzRoleDelete}, 0)
	} else {
		unittest.AssertCount(t, &authz_model.RoleDefinition{ID: role.Definition.ID}, 0)
		unittest.AssertCount(t, &authz_model.SubjectRoleBinding{RoleID: role.Definition.ID}, 0)
		unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzRoleDelete}, 1)
		unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzBindingAdd}, 0)
	}
}

func TestEnterpriseAuthzPolicyAuditFailureRollsBackAllChanges(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	permissions := []authz_service.PermissionInput{{Action: authz.ReadCode, Effect: "allow"}}
	role, err := authz_service.CreateRole(t.Context(), actor, scope, authz_service.CreateRoleInput{Name: "Original", Permissions: &permissions})
	require.NoError(t, err)
	_, err = db.Exec(t.Context(), "ALTER TABLE audit_event RENAME TO audit_event_authz_fault")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE audit_event_authz_fault RENAME TO audit_event")
		require.NoError(t, err)
	})
	_, err = authz_service.CreateRole(t.Context(), actor, scope, authz_service.CreateRoleInput{Name: "Rollback"})
	require.ErrorIs(t, err, authz_service.ErrPolicyStorage)
	_, err = authz_service.UpdateRole(t.Context(), actor, scope, role.Definition.ID, authz_service.UpdateRoleInput{ExpectedRevision: 1, Permissions: &[]authz_service.PermissionInput{}})
	require.ErrorIs(t, err, authz_service.ErrPolicyStorage)
	_, _, err = authz_service.PutBinding(t.Context(), actor, scope, authz_service.BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: role.Definition.ID})
	require.ErrorIs(t, err, authz_service.ErrPolicyStorage)
	require.ErrorIs(t, authz_service.DeleteRole(t.Context(), actor, scope, role.Definition.ID, 1), authz_service.ErrPolicyStorage)
	unchanged, err := authz_service.GetRole(t.Context(), actor, scope, role.Definition.ID)
	require.NoError(t, err)
	require.Equal(t, int64(1), unchanged.Definition.Revision)
	require.Len(t, unchanged.Permissions, 1)
	unittest.AssertCount(t, &authz_model.RoleDefinition{}, 1)
	unittest.AssertCount(t, &authz_model.SubjectRoleBinding{}, 0)
}

func TestEnterpriseAuthzPolicySubjectCleanupLocksNativeObject(t *testing.T) {
	if !setting.Database.Type.IsPostgreSQL() {
		t.Skip("PostgreSQL 行锁验收")
	}
	defer tests.PrepareTestEnv(t)()
	require.NoError(t, db.WithTx(t.Context(), func(tx context.Context) error {
		if err := authz_model.DeleteSubject(tx, authz_model.SubjectUser, 4); err != nil {
			return err
		}
		err := db.WithIndependentTx(t.Context(), func(other context.Context) error {
			_, err := db.Exec(other, "SELECT id FROM `user` WHERE id=4 FOR UPDATE NOWAIT")
			return err
		})
		var state interface{ SQLState() string }
		require.ErrorAs(t, err, &state)
		require.Equal(t, "55P03", state.SQLState())
		return nil
	}))
}

func TestEnterpriseAuthzPolicyUpdateCompetesWithBindingAndDelete(t *testing.T) {
	for _, concurrent := range []string{"binding", "delete"} {
		t.Run(concurrent, func(t *testing.T) {
			defer tests.PrepareTestEnv(t)()
			defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
			defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
			defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
			admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
			owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			scope := authz_model.Scope{Type: authz_model.ScopeSystem}
			role, err := authz_service.CreateRole(t.Context(), admin, scope, authz_service.CreateRoleInput{Name: "Concurrent update"})
			require.NoError(t, err)
			start := make(chan struct{})
			results := make(chan error, 2)
			go func() {
				<-start
				permissions := []authz_service.PermissionInput{{Action: authz.Clone, Effect: "allow"}, {Action: authz.ReadCode, Effect: "allow"}}
				_, err := authz_service.UpdateRole(t.Context(), admin, scope, role.Definition.ID, authz_service.UpdateRoleInput{ExpectedRevision: 1, Permissions: &permissions})
				results <- err
			}()
			go func() {
				<-start
				if concurrent == "binding" {
					_, _, err := authz_service.PutBinding(t.Context(), owner, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}, authz_service.BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: role.Definition.ID})
					results <- err
				} else {
					results <- authz_service.DeleteRole(t.Context(), admin, scope, role.Definition.ID, 1)
				}
			}()
			close(start)
			first, second := <-results, <-results
			if first != nil {
				first, second = second, first
			}
			require.NoError(t, first)
			if concurrent == "binding" {
				require.NoError(t, second)
				updated, err := authz_service.GetRole(t.Context(), admin, scope, role.Definition.ID)
				require.NoError(t, err)
				require.Equal(t, int64(2), updated.Definition.Revision)
				require.Len(t, updated.Permissions, 2)
				unittest.AssertCount(t, &authz_model.SubjectRoleBinding{RoleID: role.Definition.ID}, 1)
				unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzRoleUpdate}, 1)
				unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzBindingAdd}, 1)
			} else {
				require.True(t, errors.Is(second, authz_service.ErrRevisionConflict) || errors.Is(second, util.ErrNotExist))
				if errors.Is(second, authz_service.ErrRevisionConflict) {
					unittest.AssertCount(t, &authz_model.RolePermission{RoleID: role.Definition.ID}, 2)
					unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzRoleUpdate}, 1)
					unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzRoleDelete}, 0)
				} else {
					unittest.AssertCount(t, &authz_model.RolePermission{RoleID: role.Definition.ID}, 0)
					unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzRoleUpdate}, 0)
					unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzRoleDelete}, 1)
				}
			}
		})
	}
}
