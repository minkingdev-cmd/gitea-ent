// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
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
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-repo-governance", AgentID: "1000002", PersonalRepoQuota: 10})()

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

func TestEnterprisePersonalRepoConfiguredQuota(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	count, err := repo_model.CountRepositories(t.Context(), repo_model.CountRepositoryOptions{OwnerID: owner.ID})
	require.NoError(t, err)
	for _, quota := range []int{0, int(count) - 1, int(count), int(count) + 1} {
		t.Run(strconv.Itoa(quota), func(t *testing.T) {
			setting.EnterpriseWeCom.PersonalRepoQuota = quota
			opts := CreateRepoOptions{Name: "configured-quota"}
			err := enforceEnterpriseRepoCreationGovernance(t.Context(), owner, owner, &opts)
			if quota > int(count) {
				require.NoError(t, err)
				require.True(t, opts.IsPrivate)
				return
			}
			require.ErrorIs(t, err, ErrEnterprisePersonalRepoQuotaExceeded)
			events, _, err := audit_model.FindEvents(t.Context(), &audit_model.EventSearchOptions{Action: audit_model.EnterpriseWeComPersonalRepoQuotaDeny})
			require.NoError(t, err)
			require.NotEmpty(t, events)
			metadata := audit_model.DecodeMetadata(events[0].Metadata)
			require.EqualValues(t, quota, metadata["quota"])
			require.Equal(t, "personal_repo_quota_exceeded", metadata["reason"])
		})
	}
	setting.EnterpriseWeCom.Enabled = false
	require.NoError(t, enforceEnterpriseRepoCreationGovernance(t.Context(), owner, owner, &CreateRepoOptions{}))
	other := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	setting.EnterpriseWeCom.Enabled = true
	require.ErrorIs(t, enforceEnterpriseRepoCreationGovernance(t.Context(), other, owner, &CreateRepoOptions{}), ErrEnterpriseRepoOwnerDenied)
	unittest.AssertCount(t, &repo_model.Repository{OwnerID: owner.ID}, count)
}

func TestEnterprisePersonalRepoFinalTransactionQuota(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true})()
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	count, err := repo_model.CountRepositories(t.Context(), repo_model.CountRepositoryOptions{OwnerID: owner.ID})
	require.NoError(t, err)
	setting.EnterpriseWeCom.PersonalRepoQuota = int(count)
	repo := &repo_model.Repository{OwnerID: owner.ID, Owner: owner, OwnerName: owner.Name, Name: "final-quota", LowerName: "final-quota"}
	err = db.WithTx(t.Context(), func(ctx context.Context) error {
		return createRepositoryInDB(ctx, owner, owner, repo, false)
	})
	require.ErrorIs(t, err, ErrEnterprisePersonalRepoQuotaExceeded)
	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: owner.ID, Name: "final-quota"})
}

func TestEnterprisePersonalRepoConcurrentLastQuota(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true})()
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	count, err := repo_model.CountRepositories(t.Context(), repo_model.CountRepositoryOptions{OwnerID: owner.ID})
	require.NoError(t, err)
	setting.EnterpriseWeCom.PersonalRepoQuota = int(count) + 1
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i := range 2 {
		wg.Go(func() {
			copyOwner := *owner
			name := fmt.Sprintf("last-quota-%d", i)
			repo := &repo_model.Repository{OwnerID: owner.ID, Owner: &copyOwner, OwnerName: owner.Name, Name: name, LowerName: name}
			<-start
			results <- db.WithTx(t.Context(), func(ctx context.Context) error {
				return createRepositoryInDB(ctx, &copyOwner, &copyOwner, repo, false)
			})
		})
	}
	close(start)
	wg.Wait()
	close(results)
	var succeeded, denied int
	for err := range results {
		if err == nil {
			succeeded++
		} else {
			require.ErrorIs(t, err, ErrEnterprisePersonalRepoQuotaExceeded)
			denied++
		}
	}
	require.Equal(t, 1, succeeded)
	require.Equal(t, 1, denied)
	unittest.AssertCount(t, &repo_model.Repository{OwnerID: owner.ID}, count+1)
}

func TestEnterprisePersonalRepoCreationPathsAtQuota(t *testing.T) {
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	for _, path := range []string{"create", "fork", "template", "migration", "adopt"} {
		t.Run(path, func(t *testing.T) {
			require.NoError(t, unittest.PrepareTestDatabase())
			owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			count, err := repo_model.CountRepositories(t.Context(), repo_model.CountRepositoryOptions{OwnerID: owner.ID})
			require.NoError(t, err)
			setting.EnterpriseWeCom.PersonalRepoQuota = int(count)
			name := "quota-path-" + path
			var repo *repo_model.Repository
			switch path {
			case "create", "migration":
				repo, err = CreateRepositoryDirectly(t.Context(), owner, owner, CreateRepoOptions{Name: name, IsMirror: path == "migration"}, true)
			case "fork":
				base := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
				repo, err = ForkRepository(t.Context(), owner, owner, ForkRepoOptions{Name: name, BaseRepo: base})
			case "template":
				base := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
				repo, err = GenerateRepository(t.Context(), owner, owner, base, GenerateRepoOptions{Name: name})
			case "adopt":
				repo, err = AdoptRepository(t.Context(), owner, owner, CreateRepoOptions{Name: name})
			}
			require.ErrorIs(t, err, ErrEnterprisePersonalRepoQuotaExceeded)
			require.Nil(t, repo)
			unittest.AssertCount(t, &repo_model.Repository{OwnerID: owner.ID}, count)
			events, _, err := audit_model.FindEvents(t.Context(), &audit_model.EventSearchOptions{Action: audit_model.EnterpriseWeComPersonalRepoQuotaDeny})
			require.NoError(t, err)
			require.NotEmpty(t, events)
			metadata := audit_model.DecodeMetadata(events[0].Metadata)
			require.Equal(t, "personal_repo_quota_exceeded", metadata["reason"])
			require.EqualValues(t, count, metadata["current_count"])
		})
	}
}

func TestEnterprisePersonalRepoFinalNativeLimitAndRollback(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true})()
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	count, err := repo_model.CountRepositories(t.Context(), repo_model.CountRepositoryOptions{OwnerID: owner.ID})
	require.NoError(t, err)
	setting.EnterpriseWeCom.PersonalRepoQuota = int(count) + 1
	owner.MaxRepoCreation = int(count)
	require.NoError(t, user_model.UpdateUserCols(t.Context(), owner, "max_repo_creation"))
	owner.NumRepos = 0
	repo := &repo_model.Repository{OwnerID: owner.ID, Owner: owner, OwnerName: owner.Name, Name: "native-quota", LowerName: "native-quota"}
	err = db.WithTx(t.Context(), func(ctx context.Context) error {
		return createRepositoryInDB(ctx, owner, owner, repo, false)
	})
	require.True(t, repo_model.IsErrReachLimitOfRepo(err), "%v", err)
	owner.MaxRepoCreation = -1
	require.NoError(t, user_model.UpdateUserCols(t.Context(), owner, "max_repo_creation"))
	rollback := errors.New("rollback repository insertion")
	err = db.WithTx(t.Context(), func(ctx context.Context) error {
		if err := createRepositoryInDB(ctx, owner, owner, repo, false); err != nil {
			return err
		}
		require.True(t, repo.IsPrivate)
		return rollback
	})
	require.ErrorIs(t, err, rollback)
	unittest.AssertCount(t, &repo_model.Repository{OwnerID: owner.ID}, count)
	repo.ID = 0
	err = db.WithTx(t.Context(), func(ctx context.Context) error {
		return createRepositoryInDB(ctx, owner, owner, repo, false)
	})
	require.NoError(t, err)
	unittest.AssertCount(t, &repo_model.Repository{OwnerID: owner.ID}, count+1)
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
