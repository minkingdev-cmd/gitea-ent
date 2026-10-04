// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"testing"

	"gitea.dev/models/db"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func seedBuiltinRoles(t *testing.T) {
	t.Helper()
	_, normalized, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	for key, actions := range authz.BuiltinRoles() {
		role := &RoleDefinition{ScopeType: ScopeSystem, Name: key, LowerName: key, BuiltinKey: &key, Revision: 1}
		require.NoError(t, db.Insert(t.Context(), role))
		for _, action := range actions {
			require.NoError(t, db.Insert(t.Context(), &RolePermission{RoleID: role.ID, Action: action, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}))
		}
	}
}

func TestAuthzReadiness(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	setting.EnterpriseAuthz.Enabled = false
	require.NoError(t, CheckReady(t.Context()))
	setting.EnterpriseAuthz.Enabled = true
	require.EqualError(t, CheckReady(t.Context()), "authz_seed_incomplete")
	seedBuiltinRoles(t)
	require.NoError(t, CheckReady(t.Context()))
	role := unittest.AssertExistsAndLoadBean(t, &RoleDefinition{LowerName: "guest"})
	_, err := db.GetEngine(t.Context()).Where("role_id = ?", role.ID).Delete(new(RolePermission))
	require.NoError(t, err)
	require.EqualError(t, CheckReady(t.Context()), "authz_seed_incomplete")
	unittest.AssertCount(t, &SubjectRoleBinding{}, 0)
}

func TestDisabledAuthzRequiresNoPolicyTables(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	x := db.GetXORMEngineForTesting()
	require.NoError(t, x.DropTables(new(RoleDefinition), new(RolePermission), new(SubjectRoleBinding), new(DecisionRecord)))
	defer func() {
		require.NoError(t, x.Sync(new(RoleDefinition), new(RolePermission), new(SubjectRoleBinding), new(DecisionRecord)))
	}()
	setting.EnterpriseAuthz.Enabled = false
	require.NoError(t, CheckReady(t.Context()))
	setting.EnterpriseAuthz.Enabled = true
	require.EqualError(t, CheckReady(t.Context()), "authz_schema_missing")
}

func TestReadinessSanitizesTransactionErrors(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	setting.EnterpriseAuthz.Enabled = true
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		require.EqualError(t, CheckReady(ctx), "authz_preflight_failed")
		return nil
	}))
}
