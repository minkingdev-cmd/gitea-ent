// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package modelmigration

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gitea.dev/modelmigration/migrationtest"
	"gitea.dev/modelmigration/v28"
	authzmodel "gitea.dev/models/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm"
	"xorm.io/xorm/contexts"
)

func TestMain(m *testing.M) { migrationtest.MainTest(m) }

func TestEnterpriseAuthzFreshInstall(t *testing.T) {
	x, cleanup := migrationtest.PrepareTestEnv(t, 0)
	defer cleanup()
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	setting.EnterpriseAuthz.Enabled = true
	require.NoError(t, Migrate(t.Context(), x))
	require.NoError(t, authzmodel.CheckReady(t.Context()))
	require.NoError(t, x.Sync(new(authzmodel.RoleDefinition), new(authzmodel.RolePermission), new(authzmodel.SubjectRoleBinding), new(authzmodel.DecisionRecord), new(authzmodel.FeatureDefinition), new(authzmodel.FeatureGrant), new(v28.FeatureHookTaskV363), new(authzmodel.CargoIndexSource), new(v28.FeatureRepositoryV363)))
	before, err := x.Query("SELECT * FROM enterprise_role_definition ORDER BY id")
	require.NoError(t, err)
	permissionsBefore, err := x.Query("SELECT * FROM enterprise_role_permission ORDER BY id")
	require.NoError(t, err)
	for range 2 {
		require.NoError(t, Migrate(t.Context(), x))
		after, err := x.Query("SELECT * FROM enterprise_role_definition ORDER BY id")
		require.NoError(t, err)
		require.Equal(t, before, after)
		permissionsAfter, err := x.Query("SELECT * FROM enterprise_role_permission ORDER BY id")
		require.NoError(t, err)
		require.Equal(t, permissionsBefore, permissionsAfter)
		count, err := x.Count(new(authzmodel.RolePermission))
		require.NoError(t, err)
		require.EqualValues(t, 70, count)
		require.NoError(t, authzmodel.CheckReady(t.Context()))
	}
	var bindings []authzmodel.SubjectRoleBinding
	require.NoError(t, x.Find(&bindings))
	require.Empty(t, bindings)
	roles := make([]authzmodel.RoleDefinition, 0)
	require.NoError(t, x.Find(&roles))
	require.Len(t, roles, 8)
	var accessPermissions []authzmodel.RolePermission
	require.NoError(t, x.Where("action = ?", "repo.manage_access").Find(&accessPermissions))
	require.Len(t, accessPermissions, 2)
	for _, permission := range accessPermissions {
		role := new(authzmodel.RoleDefinition)
		has, err := x.ID(permission.RoleID).Get(role)
		require.NoError(t, err)
		require.True(t, has)
		require.Contains(t, []string{"owner", "platform-admin"}, *role.BuiltinKey)
	}
	for _, role := range roles {
		require.Equal(t, authzmodel.ScopeSystem, role.ScopeType)
		require.Zero(t, role.ScopeID)
		require.EqualValues(t, 1, role.Revision)
	}
	var permissions []authzmodel.RolePermission
	require.NoError(t, x.Find(&permissions))
	for _, permission := range permissions {
		require.Equal(t, "allow", permission.Effect)
		require.Equal(t, "{}", permission.ConditionJSON)
		require.Equal(t, "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", permission.ConditionHash)
	}
	version, err := GetCurrentDBVersion(x)
	require.NoError(t, err)
	require.EqualValues(t, 364, version)
}

func TestEnterpriseAuthzInstallRejectsUnversionedDatabase(t *testing.T) {
	for _, table := range []string{"user", "version", "enterprise_role_definition"} {
		t.Run(table, func(t *testing.T) {
			x, cleanup := migrationtest.PrepareTestEnv(t, 1)
			defer cleanup()
			_, err := x.Exec("CREATE TABLE `" + table + "` (id INTEGER PRIMARY KEY, version INTEGER)")
			require.NoError(t, err)
			require.EqualError(t, Migrate(t.Context(), x), "database has tables but no valid version record; restore the database version before migration")
			exists, err := x.IsTableExist("enterprise_role_permission")
			require.NoError(t, err)
			require.False(t, exists)
		})
	}
}

func TestEnterpriseAuthzInstallDoesNotRepairCurrentDatabase(t *testing.T) {
	x, cleanup := migrationtest.PrepareTestEnv(t, 0, new(Version))
	defer cleanup()
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	setting.EnterpriseAuthz.Enabled = true
	_, err := x.Insert(&Version{ID: 1, Version: 364})
	require.NoError(t, err)
	require.NoError(t, x.Sync(new(authzmodel.RoleDefinition), new(authzmodel.RolePermission), new(authzmodel.SubjectRoleBinding), new(authzmodel.DecisionRecord), new(authzmodel.FeatureDefinition), new(authzmodel.FeatureGrant), new(v28.FeatureHookTaskV363), new(authzmodel.CargoIndexSource), new(v28.FeatureRepositoryV363)))
	require.NoError(t, Migrate(t.Context(), x))
	require.EqualError(t, authzmodel.CheckReady(t.Context()), "authz_seed_incomplete")
	count, err := x.Count(new(authzmodel.RoleDefinition))
	require.NoError(t, err)
	require.Zero(t, count)
}

func TestEnterpriseAuthzUpgradeReadiness(t *testing.T) {
	x, cleanup := migrationtest.PrepareTestEnv(t, 0, new(Version))
	defer cleanup()
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	setting.EnterpriseAuthz.Enabled = true
	require.NoError(t, v28.AddEnterpriseAuthzFoundation(t.Context(), x))
	_, err := x.Insert(&Version{ID: 1, Version: 362})
	require.NoError(t, err)
	require.NoError(t, Migrate(t.Context(), x))
	require.NoError(t, authzmodel.CheckReady(t.Context()))
	defer test.MockVariableValue(&preparedMigrations)()
	preparedMigrations = prepareMigrationTasks()[:len(prepareMigrationTasks())-1]
	require.EqualValues(t, 363, ExpectedDBVersion())
	require.ErrorContains(t, EnsureUpToDate(t.Context(), x), "current database version 364 is not equal to the expected version 363")
}

func TestEnterpriseAuthzFreshInstallInterruptedRecovery(t *testing.T) {
	x, cleanup := migrationtest.PrepareTestEnv(t, 0)
	defer cleanup()
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	setting.EnterpriseAuthz.Enabled = true
	hook := &installVersionFailure{enabled: true}
	engine, ok := x.(*xorm.Engine)
	require.True(t, ok)
	engine.AddHook(hook)
	require.ErrorContains(t, Migrate(t.Context(), x), "install_interrupted")
	require.True(t, hook.fired)
	tables, err := x.DBMetas()
	require.NoError(t, err)
	require.Empty(t, tables)
	hook.enabled = false
	require.NoError(t, Migrate(t.Context(), x))
	require.NoError(t, authzmodel.CheckReady(t.Context()))
}

type installVersionFailure struct{ enabled, fired bool }

func (h *installVersionFailure) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.enabled && strings.HasPrefix(c.SQL, "INSERT INTO") && strings.Contains(c.SQL, "version") {
		h.fired = true
		return c.Ctx, errors.New("install_interrupted")
	}
	return c.Ctx, nil
}
func (*installVersionFailure) AfterProcess(*contexts.ContextHook) error { return nil }
