// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"net/http"
	"strconv"
	"testing"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnterpriseWeComAdminUIReadOnlyVisibility(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-ui", AgentID: "1000002"})()
	seedEnterpriseWeComAdminUIState(t)

	userSession := loginUser(t, "user2")
	resp := userSession.MakeRequest(t, NewRequest(t, "GET", "/user/settings"), http.StatusOK)
	assert.NotContains(t, resp.Body.String(), `href="/-/admin"`)
	userSession.MakeRequest(t, NewRequest(t, "GET", "/-/admin"), http.StatusForbidden)
	userSession.MakeRequest(t, NewRequest(t, "GET", "/-/admin/enterprise/wecom"), http.StatusForbidden)

	adminSession := loginUser(t, "user1")
	resp = adminSession.MakeRequest(t, NewRequest(t, "GET", "/user/settings"), http.StatusOK)
	assert.NotContains(t, resp.Body.String(), `href="/-/admin"`)
	adminSession.MakeRequest(t, NewRequest(t, "GET", "/-/admin"), http.StatusForbidden)
	adminSession.MakeRequest(t, NewRequest(t, "GET", "/-/admin/enterprise/wecom"), http.StatusForbidden)

	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 1, CorpID: "corp-ui", WeComUserID: "ui.admin", LoginSourceID: 1, Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	resp = adminSession.MakeRequest(t, NewRequest(t, "GET", "/user/settings"), http.StatusOK)
	assert.Contains(t, resp.Body.String(), `href="/-/admin"`)
	adminSession.MakeRequest(t, NewRequest(t, "GET", "/-/admin"), http.StatusOK)

	resp = adminSession.MakeRequest(t, NewRequest(t, "GET", "/-/admin/enterprise/wecom"), http.StatusOK)
	body := resp.Body.String()
	assert.Contains(t, body, "Enterprise WeCom")
	assert.Contains(t, body, "read-only")
	assert.Contains(t, body, "Only Enterprise WeCom super administrators can create organizations")
	assert.Contains(t, body, "/-/admin/enterprise/wecom/generated-mappings")
	assert.NotContains(t, body, "Dry Run")
	assert.NotContains(t, body, "Apply Mappings")
	assert.NotContains(t, body, "Create Mapping")
	assert.NotContains(t, body, "Edit Mapping")

	for _, tc := range []struct {
		path     string
		contains string
	}{
		{"/-/admin/enterprise/wecom/generated-mappings", "ui-dept"},
		{"/-/admin/enterprise/wecom/generated-teams", "ui-team"},
		{"/-/admin/enterprise/wecom/reconciliation-runs", "ui-run"},
		{"/-/admin/enterprise/wecom/authority", "ui.admin"},
		{"/-/admin/enterprise/wecom/org-repo-requests", "ui-request-repo"},
	} {
		resp = adminSession.MakeRequest(t, NewRequest(t, "GET", tc.path), http.StatusOK)
		assert.Contains(t, resp.Body.String(), tc.contains)
	}
	resp = adminSession.MakeRequest(t, NewRequest(t, "GET", "/-/admin/enterprise/wecom/org-repo-requests"), http.StatusOK)
	assert.Contains(t, resp.Body.String(), "Approve")
	assert.Contains(t, resp.Body.String(), "Reject")

	request := unittest.AssertExistsAndLoadBean(t, &wecom_model.OrgRepoRequest{Name: "ui-request-repo"})
	req := NewRequest(t, "POST", "/-/admin/enterprise/wecom/org-repo-requests/"+strconv.FormatInt(request.ID, 10)+"/approve")
	adminSession.MakeRequest(t, req, http.StatusSeeOther)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: request.OrgID, Name: request.Name})
	assert.True(t, repo.IsPrivate)
}

func TestEnterpriseWeComOrganizationRepositoryRequestFromCreateForm(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-ui", AgentID: "1000002"})()

	org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 3})
	session := loginUser(t, "user2")
	repoName := "requested-org-repo-ui"
	req := NewRequestWithValues(t, "POST", "/repo/create", map[string]string{
		"uid":                     "3",
		"repo_name":               repoName,
		"private":                 "true",
		"description":             "requested from web form",
		"org_repo_request_reason": "please create it",
	})
	resp := session.MakeRequest(t, req, http.StatusSeeOther)
	assert.Equal(t, "/user/settings/organization", resp.Header().Get("Location"))

	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: org.ID, Name: repoName})
	request := unittest.AssertExistsAndLoadBean(t, &wecom_model.OrgRepoRequest{OrgID: org.ID, RequesterID: 2, Name: repoName})
	assert.Equal(t, wecom_model.OrgRepoRequestStatusPending, request.Status)
	assert.Equal(t, "please create it", request.Reason)

	resp = session.MakeRequest(t, NewRequest(t, "GET", "/user/settings/organization"), http.StatusOK)
	body := resp.Body.String()
	assert.Contains(t, body, "Organization Repository Requests")
	assert.Contains(t, body, repoName)
	assert.Contains(t, body, "pending")
}

func TestEnterpriseWeComOrganizationRepositoryRequestAvailableToNonOrgMember(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-ui", AgentID: "1000002"})()

	org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 3})
	session := loginUser(t, "user5")

	resp := session.MakeRequest(t, NewRequest(t, "GET", "/repo/create?org=3"), http.StatusOK)
	body := resp.Body.String()
	assert.Contains(t, body, `data-value="3" title="org3"`)
	assert.Contains(t, body, `name="org_repo_request_reason"`)

	repoName := "requested-org-repo-non-member-ui"
	req := NewRequestWithValues(t, "POST", "/repo/create", map[string]string{
		"uid":                     "3",
		"repo_name":               repoName,
		"private":                 "true",
		"description":             "requested by a non org member",
		"org_repo_request_reason": "please create it for a regular member",
	})
	resp = session.MakeRequest(t, req, http.StatusSeeOther)
	assert.Equal(t, "/user/settings/organization", resp.Header().Get("Location"))

	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: org.ID, Name: repoName})
	request := unittest.AssertExistsAndLoadBean(t, &wecom_model.OrgRepoRequest{OrgID: org.ID, RequesterID: 5, Name: repoName})
	assert.Equal(t, wecom_model.OrgRepoRequestStatusPending, request.Status)

	resp = session.MakeRequest(t, NewRequest(t, "GET", "/user/settings/organization"), http.StatusOK)
	body = resp.Body.String()
	assert.Contains(t, body, repoName)
	assert.Contains(t, body, "pending")

	require.NoError(t, db.Insert(t.Context(), &wecom_model.AdminAuthority{
		CorpID:       "corp-ui",
		AgentID:      "1000002",
		WeComUserID:  "request.approver",
		AuthType:     wecom_model.AdminAuthorityAuthTypeManagement,
		IsManagement: true,
		IsActive:     true,
	}))
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{
		UserID:        1,
		CorpID:        "corp-ui",
		WeComUserID:   "request.approver",
		LoginSourceID: 1,
		Status:        wecom_model.IdentityStatusActive,
	})
	require.NoError(t, err)

	adminSession := loginUser(t, "user1")
	resp = adminSession.MakeRequest(t, NewRequest(t, "GET", "/-/admin/enterprise/wecom/org-repo-requests"), http.StatusOK)
	body = resp.Body.String()
	assert.Contains(t, body, repoName)
	assert.Contains(t, body, "Approve")

	req = NewRequest(t, "POST", "/-/admin/enterprise/wecom/org-repo-requests/"+strconv.FormatInt(request.ID, 10)+"/approve")
	adminSession.MakeRequest(t, req, http.StatusSeeOther)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: org.ID, Name: repoName})
	assert.True(t, repo.IsPrivate)
}

func TestEnterpriseWeComOrganizationCreateEntryVisibility(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-org-create-ui", AgentID: "1000002"})()

	adminSession := loginUser(t, "user1")
	adminSession.MakeRequest(t, NewRequest(t, "GET", "/-/admin/orgs"), http.StatusForbidden)

	require.NoError(t, db.Insert(t.Context(), &wecom_model.AdminAuthority{
		CorpID:       "corp-org-create-ui",
		AgentID:      "1000002",
		WeComUserID:  "org.create.ui.admin",
		AuthType:     wecom_model.AdminAuthorityAuthTypeManagement,
		IsManagement: true,
		IsActive:     true,
	}))
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{
		UserID:        1,
		CorpID:        "corp-org-create-ui",
		WeComUserID:   "org.create.ui.admin",
		LoginSourceID: 1,
		Status:        wecom_model.IdentityStatusActive,
	})
	require.NoError(t, err)

	resp := adminSession.MakeRequest(t, NewRequest(t, "GET", "/-/admin/orgs"), http.StatusOK)
	assert.Contains(t, resp.Body.String(), "/org/create")
}

func seedEnterpriseWeComAdminUIState(t *testing.T) {
	t.Helper()
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	require.NoError(t, db.Insert(t.Context(), &wecom_model.GeneratedMapping{
		RunID:      "ui-run",
		CorpID:     "corp-ui",
		AgentID:    "1000002",
		SourceType: wecom_model.AuthzSourceDepartment,
		SourceID:   "ui-dept",
		SourceName: "UI Dept",
		TargetType: wecom_model.AuthzTargetTeam,
		OrgID:      team.OrgID,
		TeamID:     team.ID,
		Status:     wecom_model.GeneratedStateApplied,
	}))
	require.NoError(t, db.Insert(t.Context(), &wecom_model.GeneratedTeam{
		RunID:       "ui-run",
		CorpID:      "corp-ui",
		AgentID:     "1000002",
		SourceType:  wecom_model.AuthzSourceDepartment,
		SourceID:    "ui-dept",
		SourceName:  "UI Dept",
		OrgID:       team.OrgID,
		TeamID:      team.ID,
		TeamName:    "ui-team",
		Status:      wecom_model.GeneratedStateApplied,
		AdminStatus: wecom_model.GeneratedStateUnresolved,
	}))
	require.NoError(t, db.Insert(t.Context(), &wecom_model.ReconcileRun{
		RunID:                  "ui-run",
		CorpID:                 "corp-ui",
		AgentID:                "1000002",
		Trigger:                "cron",
		Status:                 wecom_model.ReconcileRunStatusSuccess,
		DirectorySyncStatus:    "success",
		AuthorityRefreshStatus: "success",
		GeneratedMappings:      1,
		GeneratedTeams:         1,
	}))
	require.NoError(t, db.Insert(t.Context(), &wecom_model.AdminAuthority{
		CorpID:       "corp-ui",
		AgentID:      "1000002",
		WeComUserID:  "ui.admin",
		AuthType:     wecom_model.AdminAuthorityAuthTypeManagement,
		IsManagement: true,
		IsActive:     true,
	}))
	require.NoError(t, db.Insert(t.Context(), &wecom_model.OrgRepoRequest{
		OrgID:       team.OrgID,
		RequesterID: 2,
		Name:        "ui-request-repo",
		Reason:      "UI request",
		Status:      wecom_model.OrgRepoRequestStatusPending,
	}))
}
