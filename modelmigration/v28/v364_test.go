// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"gitea.dev/modelmigration/migrationtest"
	audit_model "gitea.dev/models/audit"           //nolint:depguard // 验证迁移后的审计依赖。
	"gitea.dev/models/db"                          //nolint:depguard // 验证迁移后的真实 CAS 存储。
	authz_model "gitea.dev/models/enterpriseauthz" //nolint:depguard // 验证迁移后的真实 CAS 存储。
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/schemas"
)

func TestEnterpriseMergeGateMigration(t *testing.T) {
	x, cleanup := migrationtest.PrepareTestEnv(t, 0)
	defer cleanup()
	require.NoError(t, AddEnterpriseAuthzFoundation(t.Context(), x))
	require.NoError(t, AddEnterpriseAuthzEnforcement(t.Context(), x))
	before := authzMigrationRows(t, x, []string{"enterprise_role_definition", "enterprise_subject_role_binding"})
	for range 2 {
		require.NoError(t, AddEnterpriseMergeGate(t.Context(), x))
		require.Equal(t, before, authzMigrationRows(t, x, []string{"enterprise_role_definition", "enterprise_subject_role_binding"}))
		for _, table := range []string{"enterprise_protected_path_rule", "enterprise_merge_gate_evaluation"} {
			exists, err := x.IsTableExist(table)
			require.NoError(t, err)
			require.True(t, exists)
		}
		var permissions []authzPermissionV362
		require.NoError(t, x.In("action", []string{"repo.manage_sensitive_paths", "repo.bypass_merge_gate"}).Find(&permissions))
		require.Len(t, permissions, 4)
		for _, permission := range permissions {
			role := new(authzRoleV362)
			found, err := x.ID(permission.RoleID).Get(role)
			require.NoError(t, err)
			require.True(t, found)
			require.Contains(t, []string{"owner", "platform-admin"}, *role.BuiltinKey)
		}
	}
}

func TestEnterpriseMergeGateMigrationStorageAndRecovery(t *testing.T) {
	x, cleanup := migrationtest.PrepareTestEnv(t, 0)
	defer cleanup()
	require.NoError(t, AddEnterpriseAuthzFoundation(t.Context(), x))
	require.NoError(t, AddEnterpriseAuthzEnforcement(t.Context(), x))
	custom := &authzRoleDefinitionV361{ScopeType: "repo", ScopeID: 1, Name: "Custom", LowerName: "custom", Description: "preserved", Revision: 7, CreatedBy: 2}
	_, err := x.Insert(custom)
	require.NoError(t, err)
	permission := &authzPermissionV362{RoleID: custom.ID, Action: "repo.clone", Effect: "allow", ConditionJSON: "{}", ConditionHash: "original"}
	_, err = x.Insert(permission)
	require.NoError(t, err)
	require.NoError(t, AddEnterpriseMergeGate(t.Context(), x))
	defer test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true})()
	require.NoError(t, x.Sync(new(audit_model.Event)))
	require.NoError(t, authz_model.CheckMergeGateReady(t.Context()))
	_, err = db.Exec(t.Context(), "DROP INDEX `UQE_enterprise_merge_gate_evaluation_operation_attempt_phase`")
	require.NoError(t, err)
	require.EqualError(t, authz_model.CheckMergeGateReady(t.Context()), "merge_gate_schema_missing")
	require.NoError(t, AddEnterpriseMergeGate(t.Context(), x))
	require.NoError(t, authz_model.CheckMergeGateReady(t.Context()))
	count, err := x.Where("role_id=?", custom.ID).Count(new(authzPermissionV362))
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	_, canonical, err := authz.ParseProtectedPathConfig([]byte(`{"path_pattern":"**","required_role_id":1}`))
	require.NoError(t, err)
	rule := &authz_model.ProtectedPathRule{ScopeType: authz_model.ScopeRepo, ScopeID: 1, OwnerID: 2, RequiredRoleID: 1, ConfigJSON: canonical, Enabled: true, CreatedBy: 2, UpdatedBy: 2}
	require.NoError(t, db.WithTx(t.Context(), func(tx context.Context) error { return authz_model.SaveProtectedPathRule(tx, rule, 0) }))
	rule.Enabled, rule.Deleted = false, true
	require.NoError(t, db.WithTx(t.Context(), func(tx context.Context) error { return authz_model.SaveProtectedPathRule(tx, rule, 1) }))
	require.Error(t, db.WithTx(t.Context(), func(tx context.Context) error { return authz_model.SaveProtectedPathRule(tx, rule, 1) }))
	snapshot := `{"snapshot_version":1}`
	evaluation := &authz_model.MergeGateEvaluation{OperationID: "migration-operation", Attempt: 1, Phase: "admission", RepoID: 1, PullID: 1, IssueID: 1, ActorID: 2, Source: "api", Mode: "enforce", HeadSHA: strings.Repeat("a", 40), BaseSHA: strings.Repeat("b", 40), CandidateDecision: "allow", AdmissionDecision: "allow", ExecutionState: "not_started", SnapshotJSON: snapshot, SnapshotVersion: 1, SnapshotHash: fmt.Sprintf("%x", sha256.Sum256([]byte(snapshot))), ReasonsJSON: "[]"}
	inserted, err := authz_model.InsertMergeGateEvaluation(t.Context(), evaluation)
	require.NoError(t, err)
	require.True(t, inserted)
	inserted, err = authz_model.InsertMergeGateEvaluation(t.Context(), evaluation)
	require.NoError(t, err)
	require.False(t, inserted)
	require.NoError(t, authz_model.TransitionMergeGateExecution(t.Context(), evaluation.ID, "not_started", "started", ""))
	require.Error(t, authz_model.TransitionMergeGateExecution(t.Context(), evaluation.ID, "not_started", "started", ""))
	require.NoError(t, authz_model.TransitionMergeGateExecution(t.Context(), evaluation.ID, "started", "succeeded", strings.Repeat("c", 40)))
	require.Error(t, authz_model.TransitionMergeGateExecution(t.Context(), evaluation.ID, "succeeded", "failed", ""))
	duplicate := *evaluation
	duplicate.ID = 0
	_, err = x.Insert(&duplicate)
	require.Error(t, err)
	schema := migrationtest.LoadTableSchemasMap(t, x)["enterprise_merge_gate_evaluation"]
	unique := false
	for _, index := range schema.Indexes {
		if index.Type == schemas.UniqueType && len(index.Cols) == 3 {
			unique = true
		}
	}
	require.True(t, unique)
	before := authzMigrationRows(t, x, []string{"enterprise_protected_path_rule", "enterprise_merge_gate_evaluation", "enterprise_subject_role_binding"})
	_, err = x.Where("action=?", "repo.manage_sensitive_paths").Delete(new(authzPermissionV362))
	require.NoError(t, err)
	require.EqualError(t, authz_model.CheckMergeGateReady(t.Context()), "authz_seed_incomplete")
	require.NoError(t, AddEnterpriseMergeGate(t.Context(), x))
	require.Equal(t, before, authzMigrationRows(t, x, []string{"enterprise_protected_path_rule", "enterprise_merge_gate_evaluation", "enterprise_subject_role_binding"}))
	_, err = x.Where("action=?", "repo.bypass_merge_gate").Cols("effect").Update(&authzPermissionV362{Effect: "deny"})
	require.NoError(t, err)
	_, err = x.Where("action=?", "repo.manage_sensitive_paths").Delete(new(authzPermissionV362))
	require.NoError(t, err)
	require.EqualError(t, AddEnterpriseMergeGate(t.Context(), x), "builtin_permission_conflict")
	count, err = x.Where("action=?", "repo.manage_sensitive_paths").Count(new(authzPermissionV362))
	require.NoError(t, err)
	require.Zero(t, count)
	_, err = x.Where("action=?", "repo.bypass_merge_gate").Cols("effect").Update(&authzPermissionV362{Effect: "allow"})
	require.NoError(t, err)
	require.NoError(t, AddEnterpriseMergeGate(t.Context(), x))
}
