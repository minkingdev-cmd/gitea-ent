// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"net/http"
	"strconv"
	"testing"

	auth_model "gitea.dev/models/auth"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestAPIEnterpriseWeComManagedTeamLocalMaintenanceDenied(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-team-api", AgentID: "1000002"})()

	baseTeam := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	managedTeam := &organization.Team{OrgID: baseTeam.OrgID, Name: "wecom-managed-api", LowerName: "wecom-managed-api"}
	_, err := unittest.GetXORMEngine().Insert(managedTeam)
	require.NoError(t, err)
	_, err = unittest.GetXORMEngine().Insert(&wecom_model.GeneratedTeam{
		CorpID:      "corp-team-api",
		AgentID:     "1000002",
		SourceType:  wecom_model.AuthzSourceDepartment,
		SourceID:    "api-team",
		OrgID:       baseTeam.OrgID,
		TeamID:      managedTeam.ID,
		TeamName:    managedTeam.Name,
		Status:      wecom_model.GeneratedStateApplied,
		AdminStatus: wecom_model.GeneratedStateApplied,
	})
	require.NoError(t, err)

	token := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization)

	createReq := NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/teams", &api.CreateTeamOption{Name: "local-created-team"}).AddTokenAuth(token)
	MakeRequest(t, createReq, http.StatusForbidden)

	renameReq := NewRequestWithJSON(t, "PATCH", "/api/v1/teams/"+strconv.FormatInt(managedTeam.ID, 10), &api.EditTeamOption{Name: "renamed-managed-team"}).AddTokenAuth(token)
	MakeRequest(t, renameReq, http.StatusForbidden)
	unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: managedTeam.ID, Name: "wecom-managed-api"})

	adminPermission := api.RepoWritePermissionAdmin
	adminReq := NewRequestWithJSON(t, "PATCH", "/api/v1/teams/"+strconv.FormatInt(managedTeam.ID, 10), &api.EditTeamOption{Permission: adminPermission}).AddTokenAuth(token)
	MakeRequest(t, adminReq, http.StatusForbidden)

	addMemberReq := NewRequest(t, "PUT", "/api/v1/teams/"+strconv.FormatInt(managedTeam.ID, 10)+"/members/user4").AddTokenAuth(token)
	MakeRequest(t, addMemberReq, http.StatusForbidden)
	isMember, err := organization.IsTeamMember(t.Context(), managedTeam.OrgID, managedTeam.ID, 4)
	require.NoError(t, err)
	require.False(t, isMember)

	deleteReq := NewRequest(t, "DELETE", "/api/v1/teams/"+strconv.FormatInt(managedTeam.ID, 10)).AddTokenAuth(token)
	MakeRequest(t, deleteReq, http.StatusForbidden)
	unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: managedTeam.ID})
}
