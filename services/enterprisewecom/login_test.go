// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"testing"

	auth_model "gitea.dev/models/auth"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/require"
)

func TestAuthenticateOAuthLoginAutoCreatesUserWithoutUsingEmailAsKey(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:          true,
		LoginOnly:        true,
		CorpID:           "corp-1",
		AgentID:          "1000002",
		CorpSecret:       "secret",
		UsernameTemplate: "{userid}",
		AutoCreateUser:   true,
	})()

	existing := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	authSource := wecomAuthSource(10)
	u, err := AuthenticateOAuthLogin(t.Context(), authSource, nil, nil, goth.User{
		UserID: "zhangsan",
		Email:  existing.Email,
		RawData: map[string]any{
			"wecom_corp_id":  "corp-1",
			"wecom_agent_id": "1000002",
			"wecom_userid":   "zhangsan",
		},
	})
	require.NoError(t, err)
	require.NotEqual(t, existing.ID, u.ID)
	require.Equal(t, auth_model.OAuth2, u.LoginType)
	require.Equal(t, int64(10), u.LoginSource)
	require.Equal(t, "zhangsan", u.LoginName)

	identity, has, err := wecom_model.GetIdentityByCorpAndUserID(t.Context(), "corp-1", "zhangsan")
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, u.ID, identity.UserID)
	require.Equal(t, existing.Email, identity.Email)
}

func TestAuthenticateOAuthLoginDeniesInactiveIdentity(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:        true,
		LoginOnly:      true,
		CorpID:         "corp-1",
		AgentID:        "1000002",
		CorpSecret:     "secret",
		AutoCreateUser: true,
	})()

	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{
		UserID:        1,
		CorpID:        "corp-1",
		WeComUserID:   "lisi",
		LoginSourceID: 10,
		Status:        wecom_model.IdentityStatusLeft,
	})
	require.NoError(t, err)

	_, err = AuthenticateOAuthLogin(t.Context(), wecomAuthSource(10), nil, nil, goth.User{
		UserID: "lisi",
		RawData: map[string]any{
			"wecom_corp_id":  "corp-1",
			"wecom_agent_id": "1000002",
			"wecom_userid":   "lisi",
		},
	})
	require.ErrorIs(t, err, ErrWeComDenied)
}

func wecomAuthSource(id int64) *auth_model.Source {
	return &auth_model.Source{
		ID:       id,
		Type:     auth_model.OAuth2,
		Name:     "wecom",
		IsActive: true,
	}
}
