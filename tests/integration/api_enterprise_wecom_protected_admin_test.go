// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"net/http"
	"strconv"
	"testing"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	wecom_service "gitea.dev/services/enterprisewecom"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestAPIProtectedWeComAdminMutationDeniedForOtherSiteAdmin(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	protected := protectEnterpriseWeComAdminForIntegration(t, "user2")
	token := getUserToken(t, "user1", auth_model.AccessTokenScopeWriteAdmin)

	fullName := "blocked protected admin edit"
	req := NewRequestWithJSON(t, "PATCH", "/api/v1/admin/users/"+protected.Name, api.EditUserOption{FullName: &fullName}).AddTokenAuth(token)
	MakeRequest(t, req, http.StatusForbidden)

	req = NewRequestWithJSON(t, "POST", "/api/v1/admin/users/"+protected.Name+"/rename", api.RenameUserOption{NewName: "blocked-protected-rename"}).AddTokenAuth(token)
	MakeRequest(t, req, http.StatusForbidden)

	req = NewRequest(t, "DELETE", "/api/v1/admin/users/"+protected.Name).AddTokenAuth(token)
	MakeRequest(t, req, http.StatusForbidden)

	req = NewRequest(t, "DELETE", "/api/v1/admin/users/"+protected.Name+"?purge=true").AddTokenAuth(token)
	MakeRequest(t, req, http.StatusForbidden)

	req = NewRequestWithJSON(t, "POST", "/api/v1/admin/users/"+protected.Name+"/keys", api.CreateKeyOption{
		Title: "blocked-admin-key",
		Key:   "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4cn+iXnA4KvcQYSV88vGn0Yi91vG47t1P7okprVmhNTkipNRIHWr6WdCO4VDr/cvsRkuVJAsLO2enwjGWWueOO6BodiBgyAOZ/5t5nJNMCNuLGT5UIo/RI1b0WRQwxEZTRjt6mFNw6lH14wRd8ulsr9toSWBPMOGWoYs1PDeDL0JuTjL+tr1SZi/EyxCngpYszKdXllJEHyI79KQgeD0Vt3pTrkbNVTOEcCNqZePSVmUH8X8Vhugz3bnE0/iE9Pb5fkWO9c4AnM1FgI/8Bvp27Fw2ShryIXuR6kKvUqhVMTuOSDHwu6A8jLE5Owt3GAYugDpDYuwTVNGrHLXKpPzrGGPE/jPmaLCMZcsdkec95dYeU3zKODEm8UQZFhmJmDeWVJ36nGrGZHL4J5aTTaeFUJmmXDaJYiJ+K2/ioKgXqnXvltu0A9R8/LGy4nrTJRr4JMLuJFoUXvGm1gXQ70w2LSpk6yl71RNC0hCtsBe8BP8IhYCM0EP5jh7eCMQZNvM= blocked\n",
	}).AddTokenAuth(token)
	MakeRequest(t, req, http.StatusForbidden)

	req = NewRequestWithJSON(t, "POST", "/api/v1/admin/users/"+protected.Name+"/badges", api.UserBadgeOption{BadgeSlugs: []string{"protected-badge"}}).AddTokenAuth(token)
	MakeRequest(t, req, http.StatusForbidden)

	unchanged := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: protected.ID})
	require.Equal(t, protected.Name, unchanged.Name)
	require.NotEqual(t, fullName, unchanged.FullName)
}

func TestAPIProtectedWeComAdminSelfUpdateBoundaries(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	protected := protectEnterpriseWeComAdminForIntegration(t, "user2")
	token := getUserToken(t, protected.Name, auth_model.AccessTokenScopeWriteAdmin)

	fullName := "allowed protected admin self edit"
	req := NewRequestWithJSON(t, "PATCH", "/api/v1/admin/users/"+protected.Name, api.EditUserOption{FullName: &fullName}).AddTokenAuth(token)
	MakeRequest(t, req, http.StatusOK)

	admin := false
	req = NewRequestWithJSON(t, "PATCH", "/api/v1/admin/users/"+protected.Name, api.EditUserOption{Admin: &admin}).AddTokenAuth(token)
	MakeRequest(t, req, http.StatusForbidden)

	active := false
	req = NewRequestWithJSON(t, "PATCH", "/api/v1/admin/users/"+protected.Name, api.EditUserOption{Active: &active}).AddTokenAuth(token)
	MakeRequest(t, req, http.StatusForbidden)

	prohibitLogin := true
	req = NewRequestWithJSON(t, "PATCH", "/api/v1/admin/users/"+protected.Name, api.EditUserOption{ProhibitLogin: &prohibitLogin}).AddTokenAuth(token)
	MakeRequest(t, req, http.StatusForbidden)

	unchanged := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: protected.ID})
	require.Equal(t, fullName, unchanged.FullName)
	require.True(t, unchanged.IsAdmin)
	require.True(t, unchanged.IsActive)
	require.False(t, unchanged.ProhibitLogin)
}

func TestWebProtectedWeComAdminMutationDeniedForOtherSiteAdmin(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	protected := protectEnterpriseWeComAdminForIntegration(t, "user2")
	protectEnterpriseWeComAdminForIntegration(t, "user1")
	session := loginUser(t, "user1")

	fullName := "blocked web protected admin edit"
	req := NewRequestWithValues(t, "POST", fmt.Sprintf("/-/admin/users/%d/edit", protected.ID), protectedAdminEditValues(protected, map[string]string{
		"full_name": fullName,
	}))
	session.MakeRequest(t, req, http.StatusSeeOther)
	resp := session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/-/admin/users/%d", protected.ID)), http.StatusOK)
	require.Contains(t, resp.Body.String(), "protected enterprise wecom administrator management denied")

	req = NewRequest(t, "POST", fmt.Sprintf("/-/admin/users/%d/delete", protected.ID))
	session.MakeRequest(t, req, http.StatusSeeOther)

	req = NewRequest(t, "POST", fmt.Sprintf("/-/admin/users/%d/impersonate", protected.ID))
	session.MakeRequest(t, req, http.StatusBadRequest)

	unchanged := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: protected.ID})
	require.Equal(t, protected.Name, unchanged.Name)
	require.NotEqual(t, fullName, unchanged.FullName)
}

func TestWebProtectedWeComAdminSelfUpdateBoundaries(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	protected := protectEnterpriseWeComAdminForIntegration(t, "user2")
	session := loginUser(t, protected.Name)

	fullName := "allowed web protected admin self edit"
	req := NewRequestWithValues(t, "POST", fmt.Sprintf("/-/admin/users/%d/edit", protected.ID), protectedAdminEditValues(protected, map[string]string{
		"full_name": fullName,
	}))
	session.MakeRequest(t, req, http.StatusSeeOther)

	req = NewRequestWithValues(t, "POST", fmt.Sprintf("/-/admin/users/%d/edit", protected.ID), protectedAdminEditValues(protected, map[string]string{
		"admin": "",
	}))
	session.MakeRequest(t, req, http.StatusSeeOther)

	unchanged := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: protected.ID})
	require.Equal(t, fullName, unchanged.FullName)
	require.True(t, unchanged.IsAdmin)
}

func protectEnterpriseWeComAdminForIntegration(t *testing.T, username string) *user_model.User {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled: true,
		CorpID:  "corp-protected-integration",
		AgentID: "1000002",
	}))

	u := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: username})
	wecomUserID := "protected-" + username
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: u.ID, CorpID: "corp-protected-integration", WeComUserID: wecomUserID, LoginSourceID: 1, Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &wecom_model.AdminAuthority{
		CorpID:       "corp-protected-integration",
		AgentID:      "1000002",
		WeComUserID:  wecomUserID,
		AuthType:     wecom_model.AdminAuthorityAuthTypeManagement,
		IsManagement: true,
		IsActive:     true,
	}))
	_, err = wecom_service.PromoteProtectedAdmins(t.Context(), wecom_service.ProtectedAdminResolveOptions{})
	require.NoError(t, err)
	return unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: u.ID})
}

func protectedAdminEditValues(u *user_model.User, overrides map[string]string) map[string]string {
	values := map[string]string{
		"user_name":         u.Name,
		"login_name":        u.LoginName,
		"login_type":        "0-0",
		"email":             u.Email,
		"full_name":         u.FullName,
		"visibility":        strconv.Itoa(int(u.Visibility)),
		"max_repo_creation": strconv.Itoa(u.MaxRepoCreation),
		"language":          u.Language,
		"active":            "on",
		"admin":             "on",
	}
	for k, v := range overrides {
		if v == "" {
			delete(values, k)
			continue
		}
		values[k] = v
	}
	return values
}
