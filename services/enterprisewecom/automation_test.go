// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"errors"
	"testing"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

type fakeAutomationClient struct {
	fakeDirectoryClient
	admins   []AppAdminInfo
	adminErr error
}

func (f fakeAutomationClient) ListAppAdmins(context.Context) ([]AppAdminInfo, error) {
	return f.admins, f.adminErr
}

func mockAutomationSettings(t *testing.T) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:         true,
		CorpID:          "corp-auto",
		AgentID:         "1000002",
		CorpSecret:      "secret",
		SyncDepartments: true,
		SyncTags:        false,
	}))
}

func TestRunAutomationPipelineSyncsRefreshesDerivesAndApplies(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockAutomationSettings(t)

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	require.NoError(t, seedGeneratedDepartmentTeam(t, team.OrgID, "Backend", 42))
	require.NoError(t, wecom_model.UpsertDepartment(t.Context(), &wecom_model.Department{CorpID: "corp-auto", DepartmentID: 42, Name: "Backend"}))
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 1, CorpID: "corp-auto", WeComUserID: "auto-user", LoginSourceID: 1, Status: wecom_model.IdentityStatusOutOfScope})
	require.NoError(t, err)
	_, err = CreateAuthzMapping(t.Context(), AuthzMappingOptions{SourceType: wecom_model.AuthzSourceDepartment, SourceID: "42", TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID, ActorID: 1})
	require.NoError(t, err)

	run, err := RunAutomationPipeline(t.Context(), fakeAutomationClient{
		fakeDirectoryClient: fakeDirectoryClient{
			departments: []DepartmentInfo{{ID: 42, Name: "Backend"}},
			members:     map[int64][]MemberInfo{42: {{UserID: "auto-user"}}},
		},
		admins: []AppAdminInfo{{UserID: "auto-admin", AuthType: 1}},
	}, AutomationRunOptions{Trigger: "cron", RunID: "auto-run", OrgID: team.OrgID})
	require.NoError(t, err)
	require.Equal(t, wecom_model.ReconcileRunStatusSuccess, run.Status)
	require.Equal(t, "success", run.DirectorySyncStatus)
	require.Equal(t, "success", run.AuthorityRefreshStatus)
	require.Equal(t, 1, run.GeneratedMappings)
	require.Equal(t, 1, run.GeneratedTeams)
	require.Equal(t, 1, run.AddedMemberships)
	require.Equal(t, 1, run.ProtectedCount)

	generatedTeam := unittest.AssertExistsAndLoadBean(t, &organization.Team{OrgID: team.OrgID, LowerName: generatedTeamName("dept", "Backend", 42)})
	isMember, err := organization.IsTeamMember(t.Context(), generatedTeam.OrgID, generatedTeam.ID, 1)
	require.NoError(t, err)
	require.True(t, isMember)
}

func TestRunAutomationPipelineAuthorityFailureDoesNotApplyAuthorization(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockAutomationSettings(t)

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	require.NoError(t, seedGeneratedDepartmentTeam(t, team.OrgID, "Backend", 42))
	require.NoError(t, wecom_model.UpsertDepartment(t.Context(), &wecom_model.Department{CorpID: "corp-auto", DepartmentID: 42, Name: "Backend"}))
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 1, CorpID: "corp-auto", WeComUserID: "auto-user", LoginSourceID: 1, Status: wecom_model.IdentityStatusOutOfScope})
	require.NoError(t, err)
	_, err = CreateAuthzMapping(t.Context(), AuthzMappingOptions{SourceType: wecom_model.AuthzSourceDepartment, SourceID: "42", TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID, ActorID: 1})
	require.NoError(t, err)

	run, err := RunAutomationPipeline(t.Context(), fakeAutomationClient{
		fakeDirectoryClient: fakeDirectoryClient{
			departments: []DepartmentInfo{{ID: 42, Name: "Backend"}},
			members:     map[int64][]MemberInfo{42: {{UserID: "auto-user"}}},
		},
		adminErr: errors.New("authority refresh failed"),
	}, AutomationRunOptions{Trigger: "cron", RunID: "auto-run-failed", OrgID: team.OrgID})
	require.Error(t, err)
	require.Equal(t, wecom_model.ReconcileRunStatusFailed, run.Status)
	require.Equal(t, "failed", run.AuthorityRefreshStatus)

	isMember, err := organization.IsTeamMember(t.Context(), team.OrgID, team.ID, 1)
	require.NoError(t, err)
	require.False(t, isMember)
}

func seedGeneratedDepartmentTeam(t *testing.T, orgID int64, name string, departmentID int64) error {
	t.Helper()
	teamName := generatedTeamName("dept", name, departmentID)
	return db.Insert(t.Context(), &organization.Team{OrgID: orgID, Name: teamName, LowerName: teamName})
}
