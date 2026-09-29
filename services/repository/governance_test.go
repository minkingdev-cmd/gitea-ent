// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"fmt"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnterpriseRepoCreationGovernancePersonalPrivateQuota(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-repo-governance", AgentID: "1000002"})()

	doer := &user_model.User{ID: 987654, Name: "quota-owner", Type: user_model.UserTypeIndividual}
	opts := CreateRepoOptions{Name: "private-default"}
	require.NoError(t, enforceEnterpriseRepoCreationGovernance(t.Context(), doer, doer, &opts))
	assert.True(t, opts.IsPrivate)

	count, err := db.GetEngine(t.Context()).Where("owner_id = ?", doer.ID).Count(new(repo_model.Repository))
	require.NoError(t, err)
	for i := count; i < 10; i++ {
		require.NoError(t, db.Insert(t.Context(), &repo_model.Repository{
			OwnerID:   doer.ID,
			OwnerName: doer.Name,
			Name:      fmt.Sprintf("quota-repo-%d", i),
			LowerName: fmt.Sprintf("quota-repo-%d", i),
		}))
	}

	err = enforceEnterpriseRepoCreationGovernance(t.Context(), doer, doer, &CreateRepoOptions{Name: "over-quota"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEnterprisePersonalRepoQuotaExceeded)
}

func TestEnterpriseRepoCreationGovernanceOrgRequiresSuperAdmin(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-repo-governance", AgentID: "1000002"})()

	doer := &user_model.User{ID: 987655, Name: "repo-super", Type: user_model.UserTypeIndividual}
	org := &user_model.User{ID: 987656, Name: "repo-org", Type: user_model.UserTypeOrganization}

	err := enforceEnterpriseRepoCreationGovernance(t.Context(), doer, org, &CreateRepoOptions{Name: "org-needs-approval"})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEnterpriseOrgRepoRequiresApproval)

	require.NoError(t, db.Insert(t.Context(), &wecom_model.AdminAuthority{
		CorpID:       "corp-repo-governance",
		AgentID:      "1000002",
		WeComUserID:  "repo.super",
		AuthType:     wecom_model.AdminAuthorityAuthTypeManagement,
		IsManagement: true,
		IsActive:     true,
	}))
	_, _, err = wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{
		UserID:      doer.ID,
		CorpID:      "corp-repo-governance",
		WeComUserID: "repo.super",
		Status:      wecom_model.IdentityStatusActive,
	})
	require.NoError(t, err)

	opts := CreateRepoOptions{Name: "org-private-default"}
	require.NoError(t, enforceEnterpriseRepoCreationGovernance(t.Context(), doer, org, &opts))
	assert.True(t, opts.IsPrivate)
}

func TestEnterpriseRepoAuthorizationGuardRequiresCreatorOwnerOrSuperAdmin(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-repo-authz", AgentID: "1000002"})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()

	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	creator := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
	ownerLevel := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	writeCollaborator := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	siteAdmin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	require.NoError(t, db.Insert(t.Context(), &wecom_model.RepositoryGovernance{
		RepoID:    repo.ID,
		CreatorID: creator.ID,
		Source:    wecom_model.RepositoryGovernanceSourceOrgRequest,
	}))

	require.NoError(t, CheckEnterpriseRepoAuthorizationChange(t.Context(), creator, repo))
	require.NoError(t, CheckEnterpriseRepoAuthorizationChange(t.Context(), ownerLevel, repo))

	err := CheckEnterpriseRepoAuthorizationChange(t.Context(), writeCollaborator, repo)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEnterpriseRepoAuthorizationDenied)

	err = CheckEnterpriseRepoAuthorizationChange(t.Context(), siteAdmin, repo)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEnterpriseRepoAuthorizationDenied)
	events, _, err := audit_model.FindEvents(t.Context(), &audit_model.EventSearchOptions{Action: audit_model.EnterpriseWeComRepoAuthorizationDeny})
	require.NoError(t, err)
	require.NotEmpty(t, events)
	metadata := audit_model.DecodeMetadata(events[0].Metadata)
	assert.Equal(t, "actor_not_creator_owner_or_super_admin", metadata["reason"])
	assert.Equal(t, "denied", metadata["outcome"])

	require.NoError(t, db.Insert(t.Context(), &wecom_model.AdminAuthority{
		CorpID:       "corp-repo-authz",
		AgentID:      "1000002",
		WeComUserID:  "authz.super",
		AuthType:     wecom_model.AdminAuthorityAuthTypeManagement,
		IsManagement: true,
		IsActive:     true,
	}))
	_, _, err = wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{
		UserID:      siteAdmin.ID,
		CorpID:      "corp-repo-authz",
		WeComUserID: "authz.super",
		Status:      wecom_model.IdentityStatusActive,
	})
	require.NoError(t, err)
	require.NoError(t, CheckEnterpriseRepoAuthorizationChange(t.Context(), siteAdmin, repo))
}
