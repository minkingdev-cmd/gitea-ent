// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package oauth2

import (
	"net/url"
	"testing"

	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestWeComProviderBuildsAuthorizationURL(t *testing.T) {
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:          true,
		LoginOnly:        true,
		CorpID:           "corp-1",
		AgentID:          "1000002",
		CorpSecret:       "secret-1",
		UsernameTemplate: "{userid}",
		APIBaseURL:       "https://qyapi.weixin.qq.com",
		OAuthBaseURL:     "https://login.work.weixin.qq.com",
	})()

	provider, err := gothProviders["wecom"].CreateGothProvider("wecom-source", "https://git.example.com/user/oauth2/wecom-source/callback", &Source{})
	require.NoError(t, err)

	session, err := provider.BeginAuth("state-1")
	require.NoError(t, err)
	authURL, err := session.GetAuthURL()
	require.NoError(t, err)

	u, err := url.Parse(authURL)
	require.NoError(t, err)
	require.Equal(t, "https", u.Scheme)
	require.Equal(t, "login.work.weixin.qq.com", u.Host)
	require.Equal(t, "/wwlogin/sso/login", u.Path)
	require.Equal(t, "CorpApp", u.Query().Get("login_type"))
	require.Equal(t, "corp-1", u.Query().Get("appid"))
	require.Equal(t, "1000002", u.Query().Get("agentid"))
	require.Equal(t, "https://git.example.com/user/oauth2/wecom-source/callback", u.Query().Get("redirect_uri"))
	require.Empty(t, u.Query().Get("response_type"))
	require.Empty(t, u.Query().Get("scope"))
	require.Equal(t, "state-1", u.Query().Get("state"))
}
