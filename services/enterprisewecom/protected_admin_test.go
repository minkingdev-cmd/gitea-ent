// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"testing"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/require"
)

func mockProtectedAdminSettings(t *testing.T) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:          true,
		LoginOnly:        true,
		CorpID:           "corp-protected",
		AgentID:          "1000002",
		CorpSecret:       "secret",
		UsernameTemplate: "{userid}",
		AutoCreateUser:   true,
	}))
}

func TestResolveAndPromoteProtectedAdmins(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockProtectedAdminSettings(t)

	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.False(t, user.IsAdmin)
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: user.ID, CorpID: "corp-protected", WeComUserID: "protected.admin", LoginSourceID: 1, Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	require.NoError(t, dbInsertAdminAuthority(t, "protected.admin", true, true))
	require.NoError(t, dbInsertAdminAuthority(t, "message.admin", true, false))
	require.NoError(t, dbInsertAdminAuthority(t, "inactive.admin", false, true))

	users, err := ResolveProtectedAdminUsers(t.Context(), ProtectedAdminResolveOptions{})
	require.NoError(t, err)
	require.Len(t, users, 1)
	require.Equal(t, user.ID, users[0].ID)

	promoted, err := PromoteProtectedAdmins(t.Context(), ProtectedAdminResolveOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, promoted)
	require.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: user.ID}).IsAdmin)

	promoted, err = PromoteProtectedAdmins(t.Context(), ProtectedAdminResolveOptions{})
	require.NoError(t, err)
	require.Zero(t, promoted)
}

func TestAuthenticateOAuthLoginPromotesBoundManagementAuthorityUser(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockProtectedAdminSettings(t)
	require.NoError(t, dbInsertAdminAuthority(t, "login.admin", true, true))

	u, err := AuthenticateOAuthLogin(t.Context(), wecomAuthSource(10), nil, nil, goth.User{
		UserID: "login.admin",
		RawData: map[string]any{
			"wecom_corp_id":  "corp-protected",
			"wecom_agent_id": "1000002",
			"wecom_userid":   "login.admin",
		},
	})
	require.NoError(t, err)
	require.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: u.ID}).IsAdmin)
}

func dbInsertAdminAuthority(t *testing.T, wecomUserID string, active, management bool) error {
	t.Helper()
	authType := wecom_model.AdminAuthorityAuthTypeMessage
	if management {
		authType = wecom_model.AdminAuthorityAuthTypeManagement
	}
	return db.Insert(t.Context(), &wecom_model.AdminAuthority{
		CorpID:       "corp-protected",
		AgentID:      "1000002",
		WeComUserID:  wecomUserID,
		AuthType:     authType,
		IsManagement: management,
		IsActive:     active,
	})
}
