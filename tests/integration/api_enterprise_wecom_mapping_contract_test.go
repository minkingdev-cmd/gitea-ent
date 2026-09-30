// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestAPIEnterpriseWeComLegacyMappingContract(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-api-map", AgentID: "1000002"})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	userToken := getUserToken(t, "user2", auth_model.AccessTokenScopeAll)
	noScopeToken := getUserToken(t, "user1", auth_model.AccessTokenScopeReadUser)
	readToken := getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin)
	seedAPIWeComIdentity(t, "contract-admin", 1, wecom_model.IdentityStatusActive)
	require.NoError(t, db.Insert(t.Context(), &wecom_model.AdminAuthority{CorpID: "corp-api-map", AgentID: "1000002", WeComUserID: "contract-admin", AuthType: wecom_model.AdminAuthorityAuthTypeManagement, IsManagement: true, IsActive: true}))
	mapping := &wecom_model.AuthzMapping{CorpID: "corp-api-map", SourceType: wecom_model.AuthzSourceUser, SourceID: "contract-admin", TargetType: wecom_model.AuthzTargetTeam, OrgID: 3, TeamID: 2, IsActive: true}
	require.NoError(t, db.Insert(t.Context(), mapping))
	beforeMapping := unittest.AssertExistsAndLoadBean(t, &wecom_model.AuthzMapping{ID: mapping.ID})
	beforeMembership := unittest.GetCount(t, new(wecom_model.ManagedMembership))
	beforeRuns := unittest.GetCount(t, new(wecom_model.ReconcileRun))
	beforeTeamUser := unittest.GetCount(t, new(organization.TeamUser))
	for _, endpoint := range []struct{ method, path string }{
		{"POST", "/api/v1/enterprise/wecom/mappings"},
		{"POST", "/api/v1/enterprise/wecom/mappings/dry-run"},
		{"POST", "/api/v1/enterprise/wecom/mappings/apply"},
		{"PATCH", fmt.Sprintf("/api/v1/enterprise/wecom/mappings/%d", mapping.ID)},
		{"DELETE", fmt.Sprintf("/api/v1/enterprise/wecom/mappings/%d", mapping.ID)},
		{"PATCH", "/api/v1/enterprise/wecom/mappings/999999"},
		{"DELETE", "/api/v1/enterprise/wecom/mappings/999999"},
	} {
		for _, body := range []string{"", `{"source_type":"user","source_id":"contract-admin","target_type":"team","org_id":3,"team_id":2}`, `{"source_id":"secret-canary","corpsecret":"secret-canary"`, `{"source_type":"invalid"}`} {
			req := NewRequestWithBody(t, endpoint.method, endpoint.path, strings.NewReader(body)).AddTokenAuth(adminToken)
			req.Header.Set("Content-Type", "application/json")
			resp := MakeRequest(t, req, http.StatusGone)
			require.Contains(t, resp.Body.String(), "manual_mapping_unavailable")
			require.NotContains(t, resp.Body.String(), "secret-canary")
		}
		MakeRequest(t, NewRequest(t, endpoint.method, endpoint.path), http.StatusUnauthorized)
		for _, token := range []string{userToken, noScopeToken, readToken} {
			MakeRequest(t, NewRequestWithBody(t, endpoint.method, endpoint.path, strings.NewReader("{")).AddTokenAuth(token), http.StatusForbidden)
		}
	}
	afterMapping := unittest.AssertExistsAndLoadBean(t, &wecom_model.AuthzMapping{ID: mapping.ID})
	require.Equal(t, beforeMapping, afterMapping)
	require.Equal(t, 1, unittest.GetCount(t, new(wecom_model.AuthzMapping)))
	require.Equal(t, beforeMembership, unittest.GetCount(t, new(wecom_model.ManagedMembership)))
	require.Equal(t, beforeTeamUser, unittest.GetCount(t, new(organization.TeamUser)))
	require.Equal(t, beforeRuns, unittest.GetCount(t, new(wecom_model.ReconcileRun)))
	events, _, err := audit_model.FindEvents(t.Context(), &audit_model.EventSearchOptions{Action: audit_model.EnterpriseWeComMappingUpdate})
	require.NoError(t, err)
	require.Len(t, events, 28)
	for _, event := range events {
		metadata := audit_model.DecodeMetadata(event.Metadata)
		require.Equal(t, "denied", metadata["outcome"])
		require.Contains(t, metadata, "mapping_id")
		require.Equal(t, "manual_mapping_unavailable", metadata["reason"])
		require.NotContains(t, event.Metadata, "secret-canary")
	}
}

func TestAPIEnterpriseWeComMappingReadAvailability(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-api-map", AgentID: "1000002"})()
	token := getUserToken(t, "user1", auth_model.AccessTokenScopeReadAdmin)
	seedAPIWeComIdentity(t, "read-admin", 1, wecom_model.IdentityStatusActive)
	require.NoError(t, db.Insert(t.Context(), &wecom_model.AdminAuthority{CorpID: "corp-api-map", AgentID: "1000002", WeComUserID: "read-admin", AuthType: wecom_model.AdminAuthorityAuthTypeManagement, IsManagement: true, IsActive: true}))
	mapping := &wecom_model.AuthzMapping{CorpID: "corp-api-map", SourceType: wecom_model.AuthzSourceUser, SourceID: "read-admin", TargetType: wecom_model.AuthzTargetOrg, OrgID: 3, IsActive: true}
	require.NoError(t, db.Insert(t.Context(), mapping))
	resp := MakeRequest(t, NewRequest(t, "GET", "/api/v1/enterprise/wecom/mappings").AddTokenAuth(token), http.StatusOK)
	require.JSONEq(t, "[]", resp.Body.String())
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/enterprise/wecom/mappings/1").AddTokenAuth(token), http.StatusNotFound)
	noScopeToken := getUserToken(t, "user1", auth_model.AccessTokenScopeReadUser)
	userToken := getUserToken(t, "user2", auth_model.AccessTokenScopeAll)
	for _, path := range []string{"/api/v1/enterprise/wecom/mappings", fmt.Sprintf("/api/v1/enterprise/wecom/mappings/%d", mapping.ID)} {
		MakeRequest(t, NewRequest(t, "GET", path), http.StatusUnauthorized)
		for _, denied := range []string{noScopeToken, userToken} {
			MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(denied), http.StatusForbidden)
		}
	}
	_, err := db.GetEngine(t.Context()).Where("corp_id = ? AND agent_id = ?", "corp-api-map", "1000002").Cols("is_active").Update(&wecom_model.AdminAuthority{IsActive: false})
	require.NoError(t, err)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/enterprise/wecom/mappings").AddTokenAuth(token), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "POST", "/api/v1/enterprise/wecom/mappings").AddTokenAuth(token), http.StatusForbidden)
	setting.EnterpriseWeCom.Enabled = false
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/enterprise/wecom/mappings").AddTokenAuth(token), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/enterprise/wecom/mappings/1").AddTokenAuth(token), http.StatusNotFound)
}
