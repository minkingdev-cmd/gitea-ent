// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	"gitea.dev/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIEnterpriseWeComRepositoryGovernance(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-repo-api", AgentID: "1000002", PersonalRepoQuota: 10})()

	orgToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteOrganization)
	orgReq := NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "blocked_extra_org"}).AddTokenAuth(orgToken)
	MakeRequest(t, orgReq, http.StatusForbidden)
	unittest.AssertNotExistsBean(t, &user_model.User{LowerName: "blocked_extra_org"})

	require.NoError(t, db.Insert(t.Context(), &wecom_model.AdminAuthority{
		CorpID:       "corp-repo-api",
		AgentID:      "1000002",
		WeComUserID:  "repo.api.user2.super",
		AuthType:     wecom_model.AdminAuthorityAuthTypeManagement,
		IsManagement: true,
		IsActive:     true,
	}))
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{
		UserID:        2,
		CorpID:        "corp-repo-api",
		WeComUserID:   "repo.api.user2.super",
		LoginSourceID: 1,
		Status:        wecom_model.IdentityStatusActive,
	})
	require.NoError(t, err)
	superOrgToken := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteOrganization)
	superOrgReq := NewRequestWithJSON(t, "POST", "/api/v1/orgs", &api.CreateOrgOption{UserName: "super_admin_extra_org"}).AddTokenAuth(superOrgToken)
	MakeRequest(t, superOrgReq, http.StatusCreated)
	unittest.AssertExistsAndLoadBean(t, &user_model.User{LowerName: "super_admin_extra_org", Type: user_model.UserTypeOrganization})

	personalOwner := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "user5"})
	repoToken := getUserToken(t, personalOwner.Name, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
	privateReq := NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "wecom-private-default", Private: false}).AddTokenAuth(repoToken)
	privateResp := MakeRequest(t, privateReq, http.StatusCreated)
	created := DecodeJSON(t, privateResp, &api.Repository{})
	assert.True(t, created.Private)

	count, err := db.GetEngine(t.Context()).Where("owner_id = ?", personalOwner.ID).Count(new(repo_model.Repository))
	require.NoError(t, err)
	for i := count; i < 10; i++ {
		name := fmt.Sprintf("wecom-quota-%d", i)
		require.NoError(t, db.Insert(t.Context(), &repo_model.Repository{OwnerID: personalOwner.ID, OwnerName: personalOwner.Name, Name: name, LowerName: strings.ToLower(name)}))
	}
	quotaReq := NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "wecom-over-quota", Private: true}).AddTokenAuth(repoToken)
	MakeRequest(t, quotaReq, http.StatusForbidden)
	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: personalOwner.ID, Name: "wecom-over-quota"})
	setting.EnterpriseWeCom.PersonalRepoQuota = 11
	customReq := NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: "wecom-custom-quota", Private: false}).AddTokenAuth(repoToken)
	customResp := MakeRequest(t, customReq, http.StatusCreated)
	assert.True(t, DecodeJSON(t, customResp, &api.Repository{}).Private)
	for _, quota := range []int{0, 5} {
		setting.EnterpriseWeCom.PersonalRepoQuota = quota
		name := "wecom-lowered-quota-" + strconv.Itoa(quota)
		req := NewRequestWithJSON(t, "POST", "/api/v1/user/repos", &api.CreateRepoOption{Name: name, Private: true}).AddTokenAuth(repoToken)
		MakeRequest(t, req, http.StatusForbidden)
		unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: personalOwner.ID, Name: name})
		unittest.AssertCount(t, &repo_model.Repository{OwnerID: personalOwner.ID}, 11)
	}

	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
	repoOwner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: repo.OwnerID})
	require.NoError(t, db.Insert(t.Context(), &wecom_model.RepositoryGovernance{RepoID: repo.ID, CreatorID: repoOwner.ID, Source: wecom_model.RepositoryGovernanceSourcePersonal}))
	permission := api.RepoWritePermissionRead

	adminToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteRepository)
	adminReq := NewRequestWithJSON(t, "PUT", "/api/v1/repos/"+repoOwner.Name+"/"+repo.Name+"/collaborators/user4", &api.AddCollaboratorOption{Permission: &permission}).AddTokenAuth(adminToken)
	MakeRequest(t, adminReq, http.StatusForbidden)

	creatorToken := getUserToken(t, repoOwner.Name, auth_model.AccessTokenScopeWriteRepository)
	creatorReq := NewRequestWithJSON(t, "PUT", "/api/v1/repos/"+repoOwner.Name+"/"+repo.Name+"/collaborators/user4", &api.AddCollaboratorOption{Permission: &permission}).AddTokenAuth(creatorToken)
	MakeRequest(t, creatorReq, http.StatusNoContent)

	require.NoError(t, db.Insert(t.Context(), &wecom_model.AdminAuthority{
		CorpID:       "corp-repo-api",
		AgentID:      "1000002",
		WeComUserID:  "repo.api.user1.super",
		AuthType:     wecom_model.AdminAuthorityAuthTypeManagement,
		IsManagement: true,
		IsActive:     true,
	}))
	_, _, err = wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{
		UserID:        1,
		CorpID:        "corp-repo-api",
		WeComUserID:   "repo.api.user1.super",
		LoginSourceID: 1,
		Status:        wecom_model.IdentityStatusActive,
	})
	require.NoError(t, err)
	superAdminOrgToken := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)
	superAdminOrgReq := NewRequestWithJSON(t, "POST", "/api/v1/admin/users/user2/orgs", &api.CreateOrgOption{UserName: "super_admin_owned_org"}).AddTokenAuth(superAdminOrgToken)
	MakeRequest(t, superAdminOrgReq, http.StatusCreated)
	unittest.AssertExistsAndLoadBean(t, &user_model.User{LowerName: "super_admin_owned_org", Type: user_model.UserTypeOrganization})
}

func TestEnterprisePersonalRepoWebQuota(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true})()
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: "user5"})
	count, err := repo_model.CountRepositories(t.Context(), repo_model.CountRepositoryOptions{OwnerID: owner.ID})
	require.NoError(t, err)
	setting.EnterpriseWeCom.PersonalRepoQuota = int(count) + 1
	session := loginUser(t, owner.Name)
	create := func(name string, status int) {
		req := NewRequestWithValues(t, "POST", "/repo/create", map[string]string{
			"uid": strconv.FormatInt(owner.ID, 10), "repo_name": name, "default_branch": "master",
		})
		session.MakeRequest(t, req, status)
	}
	create("wecom-web-private", http.StatusSeeOther)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: owner.ID, Name: "wecom-web-private"})
	require.True(t, repo.IsPrivate)
	setting.EnterpriseWeCom.PersonalRepoQuota = 0
	create("wecom-web-zero-quota", http.StatusForbidden)
	templateReq := NewRequestWithValues(t, "POST", "/repo/create", map[string]string{
		"uid": strconv.FormatInt(owner.ID, 10), "repo_name": "wecom-web-template-zero-quota", "repo_template": "44", "topics": "true",
	})
	session.MakeRequest(t, templateReq, http.StatusForbidden)
	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: owner.ID, Name: "wecom-web-template-zero-quota"})
	forkReq := NewRequestWithValues(t, "POST", "/user2/repo1/fork", map[string]string{
		"uid": strconv.FormatInt(owner.ID, 10), "repo_name": "wecom-web-fork-zero-quota",
	})
	session.MakeRequest(t, forkReq, http.StatusForbidden)
	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: owner.ID, Name: "wecom-web-fork-zero-quota"})
	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: owner.ID, Name: "wecom-web-zero-quota"})
	unittest.AssertCount(t, &repo_model.Repository{OwnerID: owner.ID}, count+1)
	setting.EnterpriseWeCom.Enabled = false
	create("native-web-public", http.StatusSeeOther)
	repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: owner.ID, Name: "native-web-public"})
	require.False(t, repo.IsPrivate)
}
