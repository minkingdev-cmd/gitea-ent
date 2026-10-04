// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"testing"

	"gitea.dev/modelmigration/migrationtest"
	"gitea.dev/models/enterpriseauthz" //nolint:depguard // 验证迁移后的真实决策写入合同

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzEnforcementMigration(t *testing.T) {
	x, cleanup := migrationtest.PrepareTestEnv(t, 0)
	defer cleanup()
	if x == nil || t.Failed() {
		return
	}
	require.NoError(t, AddEnterpriseAuthzFoundation(t.Context(), x))
	history := &authzDecisionV361{ObservationID: "legacy-decision", OperationID: "legacy-operation", ActorID: 2, RepoID: 1, OwnerID: 2, Action: "repo.clone", RequestSource: "api", CandidateDecision: "allow", Reason: "native_action", MissingActions: "[]", NativeOutcome: "success", NativeStage: "operation", SnapshotJSON: `{"catalog_version":1}`, CreatedUnix: 100}
	_, err := x.NoAutoTime().Insert(history)
	require.NoError(t, err)
	custom := &authzRoleDefinitionV361{ScopeType: "repo", ScopeID: 1, Name: "Copied Owner", LowerName: "copied owner", Revision: 7, CreatedUnix: 101, UpdatedUnix: 102}
	_, err = x.NoAutoTime().Insert(custom)
	require.NoError(t, err)
	for _, action := range authzBuiltinPermissionsV361["owner"] {
		_, err = x.Insert(&authzRolePermissionV361{RoleID: custom.ID, Action: action, Effect: "allow", ConditionJSON: "{}", ConditionHash: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"})
		require.NoError(t, err)
	}
	customBefore, err := x.Query("SELECT * FROM enterprise_role_permission WHERE role_id = ? ORDER BY id", custom.ID)
	require.NoError(t, err)
	require.Len(t, customBefore, 19)
	rolesBefore := authzMigrationRows(t, x, []string{"enterprise_role_definition", "enterprise_subject_role_binding"})
	permissionsBefore, err := x.Query("SELECT * FROM enterprise_role_permission ORDER BY id")
	require.NoError(t, err)
	indicesBefore := migrationtest.LoadTableSchemasMap(t, x)[history.TableName()].Indexes
	for iteration := range 2 {
		require.NoError(t, AddEnterpriseAuthzEnforcement(t.Context(), x))
		indicesAfter := migrationtest.LoadTableSchemasMap(t, x)[history.TableName()].Indexes
		for name, index := range indicesBefore {
			require.Contains(t, indicesAfter, name)
			require.True(t, index.Equal(indicesAfter[name]))
		}
		record := &enterpriseauthz.DecisionRecord{ObservationID: "post-migration-decision", OperationID: "post-migration-operation", Action: "repo.clone", RequestSource: "api", CandidateDecision: "allow", Reason: "native_action", MissingActions: "[]", SnapshotJSON: `{"catalog_version":2}`}
		inserted, err := enterpriseauthz.InsertDecisionIfAbsent(t.Context(), record)
		require.NoError(t, err)
		require.Equal(t, iteration == 0, inserted)
		inserted, err = enterpriseauthz.InsertDecisionIfAbsent(t.Context(), record)
		require.NoError(t, err)
		require.False(t, inserted)
		require.Equal(t, rolesBefore, authzMigrationRows(t, x, []string{"enterprise_role_definition", "enterprise_subject_role_binding"}))
		customAfter, err := x.Query("SELECT * FROM enterprise_role_permission WHERE role_id = ? ORDER BY id", custom.ID)
		require.NoError(t, err)
		require.Equal(t, customBefore, customAfter)
		permissionsAfter, err := x.Query("SELECT * FROM enterprise_role_permission WHERE action <> ? ORDER BY id", "repo.manage_access")
		require.NoError(t, err)
		require.Equal(t, permissionsBefore, permissionsAfter)
		stored := new(authzDecisionV361)
		has, err := x.ID(history.ID).Get(stored)
		require.NoError(t, err)
		require.True(t, has)
		require.Equal(t, *history, *stored)
		admission := new(authzDecisionV362)
		has, err = x.ID(history.ID).Get(admission)
		require.NoError(t, err)
		require.True(t, has)
		require.Equal(t, "shadow", admission.DecisionMode)
		require.Equal(t, "not_enforced", admission.AuthorizationDecision)
		require.Empty(t, admission.AuthorizationReason)
		require.False(t, admission.ExecutionStarted)
		count, err := x.Count(new(authzPermissionV362))
		require.NoError(t, err)
		require.EqualValues(t, 89, count)
		var permissions []authzPermissionV362
		require.NoError(t, x.Where("action = ?", "repo.manage_access").Find(&permissions))
		require.Len(t, permissions, 2)
		for _, p := range permissions {
			role := new(authzRoleV362)
			has, err := x.ID(p.RoleID).Get(role)
			require.NoError(t, err)
			require.True(t, has)
			require.Contains(t, []string{"owner", "platform-admin"}, *role.BuiltinKey)
			require.EqualValues(t, 1, role.Revision)
			require.Equal(t, "allow", p.Effect)
			require.Equal(t, "{}", p.ConditionJSON)
		}
	}
}

func TestEnterpriseAuthzEnforcementMigrationConflictRecovery(t *testing.T) {
	x, cleanup := migrationtest.PrepareTestEnv(t, 0)
	defer cleanup()
	if x == nil || t.Failed() {
		return
	}
	require.NoError(t, AddEnterpriseAuthzFoundation(t.Context(), x))
	_, err := x.Where("builtin_key = ?", "platform-admin").Cols("revision").Update(&authzRoleDefinitionV361{Revision: 2})
	require.NoError(t, err)
	before := authzMigrationRows(t, x, []string{"enterprise_role_definition", "enterprise_role_permission", "enterprise_subject_role_binding"})
	require.EqualError(t, AddEnterpriseAuthzEnforcement(t.Context(), x), "builtin_role_conflict")
	require.Equal(t, before, authzMigrationRows(t, x, []string{"enterprise_role_definition", "enterprise_role_permission", "enterprise_subject_role_binding"}))
	_, err = x.Where("builtin_key = ?", "platform-admin").Cols("revision").Update(&authzRoleDefinitionV361{Revision: 1})
	require.NoError(t, err)
	require.NoError(t, AddEnterpriseAuthzEnforcement(t.Context(), x))
	require.NoError(t, AddEnterpriseAuthzEnforcement(t.Context(), x))
	count, err := x.Where("action = ?", "repo.manage_access").Count(new(authzPermissionV362))
	require.NoError(t, err)
	require.EqualValues(t, 2, count)
}
