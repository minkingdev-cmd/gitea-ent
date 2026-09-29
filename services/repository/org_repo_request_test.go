// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"testing"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOrganizationRepositoryRequestApprovalCreatesPrivateRepository(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-org-repo", AgentID: "1000002"})()

	requester := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	reviewer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	require.NoError(t, seedRepoGovernanceSuperAdmin(t, reviewer.ID))

	req, err := SubmitOrganizationRepositoryRequest(t.Context(), requester, org, OrganizationRepositoryRequestOptions{
		Name:        "approved-org-request-repo",
		Description: "approved by super admin",
		Reason:      "project onboarding",
	})
	require.NoError(t, err)
	assert.Equal(t, wecom_model.OrgRepoRequestStatusPending, req.Status)
	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: org.ID, Name: "approved-org-request-repo"})

	repo, err := ApproveOrganizationRepositoryRequest(t.Context(), reviewer, req.ID, "ok")
	require.NoError(t, err)
	require.NotNil(t, repo)
	assert.True(t, repo.IsPrivate)

	req = unittest.AssertExistsAndLoadBean(t, &wecom_model.OrgRepoRequest{ID: req.ID})
	assert.Equal(t, wecom_model.OrgRepoRequestStatusApproved, req.Status)
	assert.Equal(t, repo.ID, req.RepoID)
	assert.Equal(t, reviewer.ID, req.ReviewerID)

	governance := unittest.AssertExistsAndLoadBean(t, &wecom_model.RepositoryGovernance{RepoID: repo.ID})
	assert.Equal(t, requester.ID, governance.CreatorID)
	assert.Equal(t, wecom_model.RepositoryGovernanceSourceOrgRequest, governance.Source)
	assert.Equal(t, req.ID, governance.RequestID)

	permission, err := access_model.GetDoerRepoPermission(t.Context(), repo, requester)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, permission.AccessMode, perm.AccessModeAdmin)
}

func TestOrganizationRepositoryRequestApprovalRequiresSuperAdmin(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-org-repo", AgentID: "1000002"})()

	requester := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	ordinaryAdmin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})

	req, err := SubmitOrganizationRepositoryRequest(t.Context(), requester, org, OrganizationRepositoryRequestOptions{Name: "denied-org-request-repo"})
	require.NoError(t, err)

	repo, err := ApproveOrganizationRepositoryRequest(t.Context(), ordinaryAdmin, req.ID, "not super")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEnterpriseOrgRepoApprovalRequiresSuperAdmin)
	assert.Nil(t, repo)
	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: org.ID, Name: "denied-org-request-repo"})
}

func TestOrganizationRepositoryRequestRejectRecordsDecisionWithoutCreatingRepository(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-org-repo", AgentID: "1000002"})()

	requester := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	reviewer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	require.NoError(t, seedRepoGovernanceSuperAdmin(t, reviewer.ID))

	req, err := SubmitOrganizationRepositoryRequest(t.Context(), requester, org, OrganizationRepositoryRequestOptions{Name: "rejected-org-request-repo"})
	require.NoError(t, err)
	require.NoError(t, RejectOrganizationRepositoryRequest(t.Context(), reviewer, req.ID, "duplicate"))

	req = unittest.AssertExistsAndLoadBean(t, &wecom_model.OrgRepoRequest{ID: req.ID})
	assert.Equal(t, wecom_model.OrgRepoRequestStatusRejected, req.Status)
	assert.Equal(t, reviewer.ID, req.ReviewerID)
	assert.Equal(t, "duplicate", req.DecisionReason)
	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: org.ID, Name: "rejected-org-request-repo"})
}

func seedRepoGovernanceSuperAdmin(t *testing.T, userID int64) error {
	t.Helper()
	if err := db.Insert(t.Context(), &wecom_model.AdminAuthority{
		CorpID:       "corp-org-repo",
		AgentID:      "1000002",
		WeComUserID:  "request.super",
		AuthType:     wecom_model.AdminAuthorityAuthTypeManagement,
		IsManagement: true,
		IsActive:     true,
	}); err != nil {
		return err
	}
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{
		UserID:      userID,
		CorpID:      "corp-org-repo",
		WeComUserID: "request.super",
		Status:      wecom_model.IdentityStatusActive,
	})
	return err
}
