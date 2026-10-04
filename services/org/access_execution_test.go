// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package org

import (
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/organization"
	"gitea.dev/models/perm"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/audit"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func TestTeamAccessMutationRequiresAdmission(t *testing.T) {
	for _, operation := range []string{"permissions", "unit-flags-lied", "includes-all", "delete", "create-all"} {
		t.Run(operation, func(t *testing.T) {
			unittest.PrepareTestEnv(t)
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
			t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
			setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
			ctx := audit.WithOrigin(t.Context(), audit_model.OriginAPI)
			team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
			before := *team
			var err error
			switch operation {
			case "permissions":
				team.AccessMode = perm.AccessModeAdmin
				err = UpdateTeam(ctx, team, true, false)
			case "unit-flags-lied":
				team.AccessMode = perm.AccessModeAdmin
				err = UpdateTeam(ctx, team, false, false)
			case "includes-all":
				team.IncludesAllRepositories = true
				err = UpdateTeam(ctx, team, false, true)
			case "delete":
				err = DeleteTeam(ctx, team)
			case "create-all":
				err = NewTeam(ctx, &organization.Team{OrgID: 3, Name: "restricted-new", AccessMode: perm.AccessModeRead, IncludesAllRepositories: true})
			}
			var rejection *authz_service.ExecutionError
			require.ErrorAs(t, err, &rejection)
			require.Equal(t, 403, rejection.Status)
			stored := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: team.ID})
			require.Equal(t, before.AccessMode, stored.AccessMode)
			require.Equal(t, before.IncludesAllRepositories, stored.IncludesAllRepositories)
			unittest.AssertNotExistsBean(t, &organization.Team{Name: "restricted-new"})
			unittest.AssertExistsAndLoadBean(t, &organization.TeamRepo{TeamID: team.ID, RepoID: 3})
		})
	}
}

func TestTeamAccessOwnerAtomicMutation(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	ctx := audit.WithDoer(audit.WithOrigin(t.Context(), audit_model.OriginAPI), actor)
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	team.AccessMode = perm.AccessModeAdmin
	require.NoError(t, UpdateTeam(ctx, team, true, false))
	require.Equal(t, perm.AccessModeAdmin, unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: team.ID}).AccessMode)
	team.IncludesAllRepositories = true
	require.NoError(t, UpdateTeam(ctx, team, false, true))
	require.Equal(t, 3, unittest.GetCount(t, &organization.TeamRepo{TeamID: team.ID}))
	require.NoError(t, DeleteTeam(ctx, team))
	unittest.AssertNotExistsBean(t, &organization.Team{ID: team.ID})
	unittest.AssertNotExistsBean(t, &organization.TeamRepo{TeamID: team.ID})
	rows := make([]authz_model.DecisionRecord, 0)
	require.NoError(t, db.GetEngine(ctx).Where("action = ? AND decision_mode = ?", authz.ManageAccess, "enforce").Find(&rows))
	require.Len(t, rows, 7)
	for _, row := range rows {
		require.Equal(t, "allow", row.AuthorizationDecision)
		require.True(t, row.ExecutionStarted)
		require.Equal(t, "success", row.NativeOutcome)
	}
}

func TestTeamAccessEmptyOrganizationNativeMutation(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	ctx := audit.WithDoer(audit.WithOrigin(t.Context(), audit_model.OriginAPI), actor)
	team := &organization.Team{OrgID: 6, Name: "empty-native-team", AccessMode: perm.AccessModeRead, IncludesAllRepositories: true}
	require.NoError(t, NewTeam(ctx, team))
	require.Positive(t, team.ID)
	team.AccessMode = perm.AccessModeAdmin
	require.NoError(t, UpdateTeam(ctx, team, true, false))
	require.NoError(t, DeleteTeam(ctx, team))
	unittest.AssertNotExistsBean(t, &organization.Team{ID: team.ID})
	unittest.AssertNotExistsBean(t, &authz_model.DecisionRecord{Action: authz.ManageAccess})
}
