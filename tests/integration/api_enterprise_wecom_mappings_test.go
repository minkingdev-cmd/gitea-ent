// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"net/http"
	"testing"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	wecom_service "gitea.dev/services/enterprisewecom"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestAPIEnterpriseWeComMappings(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:         true,
		CorpID:          "corp-api-map",
		AgentID:         "1000002",
		CorpSecret:      "corp-secret-value",
		SyncDepartments: true,
		SyncTags:        true,
	})()

	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	nonAdminToken := getUserToken(t, "user2", auth_model.AccessTokenScopeAll)
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	seedAPIWeComIdentity(t, "api-user", 1, wecom_model.IdentityStatusActive)
	require.NoError(t, db.Insert(t.Context(), &wecom_model.AdminAuthority{
		CorpID:       "corp-api-map",
		AgentID:      "1000002",
		WeComUserID:  "api-user",
		AuthType:     wecom_model.AdminAuthorityAuthTypeManagement,
		IsManagement: true,
		IsActive:     true,
	}))

	option := api.EnterpriseWeComAuthzMappingOption{
		SourceType: "user",
		SourceID:   "api-user",
		TargetType: "team",
		OrgID:      team.OrgID,
		TeamID:     team.ID,
	}

	req := NewRequestWithJSON(t, "POST", "/api/v1/enterprise/wecom/mappings", &option).
		AddTokenAuth(nonAdminToken)
	MakeRequest(t, req, http.StatusForbidden)

	req = NewRequestWithJSON(t, "POST", "/api/v1/enterprise/wecom/mappings", &api.EnterpriseWeComAuthzMappingOption{
		SourceType: "user",
		SourceID:   "missing-user",
		TargetType: "team",
		OrgID:      team.OrgID,
		TeamID:     team.ID,
	}).AddTokenAuth(adminToken)
	MakeRequest(t, req, http.StatusGone)

	req = NewRequestWithJSON(t, "POST", "/api/v1/enterprise/wecom/mappings", &option).
		AddTokenAuth(adminToken)
	MakeRequest(t, req, http.StatusGone)

	mapping, err := wecom_service.CreateAuthzMapping(t.Context(), wecom_service.AuthzMappingOptions{
		CorpID:     "corp-api-map",
		SourceType: wecom_model.AuthzSourceUser,
		SourceID:   "api-user",
		TargetType: wecom_model.AuthzTargetTeam,
		OrgID:      team.OrgID,
		TeamID:     team.ID,
		ActorID:    1,
	})
	require.NoError(t, err)

	req = NewRequest(t, "GET", "/api/v1/enterprise/wecom/mappings").AddTokenAuth(adminToken)
	resp := MakeRequest(t, req, http.StatusOK)
	listed := DecodeJSON(t, resp, &[]api.EnterpriseWeComAuthzMapping{})
	require.Len(t, *listed, 1)
	require.Equal(t, mapping.ID, (*listed)[0].ID)

	req = NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/enterprise/wecom/mappings/%d", mapping.ID), &option).
		AddTokenAuth(adminToken)
	MakeRequest(t, req, http.StatusGone)

	req = NewRequestWithJSON(t, "POST", "/api/v1/enterprise/wecom/mappings/dry-run", &api.EnterpriseWeComAuthzReconcileOption{ApplyID: "dry-run"}).
		AddTokenAuth(adminToken)
	MakeRequest(t, req, http.StatusGone)
	isMember, err := organization.IsTeamMember(t.Context(), team.OrgID, team.ID, 1)
	require.NoError(t, err)
	require.False(t, isMember)

	req = NewRequestWithJSON(t, "POST", "/api/v1/enterprise/wecom/mappings/apply", &api.EnterpriseWeComAuthzReconcileOption{ApplyID: "manual-apply"}).
		AddTokenAuth(adminToken)
	MakeRequest(t, req, http.StatusGone)
	isMember, err = organization.IsTeamMember(t.Context(), team.OrgID, team.ID, 1)
	require.NoError(t, err)
	require.False(t, isMember)

	req = NewRequest(t, "DELETE", fmt.Sprintf("/api/v1/enterprise/wecom/mappings/%d", mapping.ID)).AddTokenAuth(adminToken)
	MakeRequest(t, req, http.StatusGone)
	stillActive := unittest.AssertExistsAndLoadBean(t, &wecom_model.AuthzMapping{ID: mapping.ID})
	require.True(t, stillActive.IsActive)
}

func seedAPIWeComIdentity(t *testing.T, wecomUserID string, userID int64, status wecom_model.IdentityStatus) {
	t.Helper()
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: userID, CorpID: "corp-api-map", WeComUserID: wecomUserID, LoginSourceID: 1, Status: status})
	require.NoError(t, err)
	count, err := db.GetEngine(t.Context()).Count(new(wecom_model.AuthzMapping))
	require.NoError(t, err)
	require.Zero(t, count)
}
