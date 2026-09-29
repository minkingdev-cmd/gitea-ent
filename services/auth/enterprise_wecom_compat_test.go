// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseWeComLoginOnlyDoesNotBlockPATVerification(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer mockEnterpriseWeComLoginOnly()()

	token := &auth_model.AccessToken{UID: 1, Name: "api-token", Scope: auth_model.AccessTokenScopeAll}
	require.NoError(t, auth_model.NewAccessToken(t.Context(), token))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/user", nil)
	req = req.WithContext(t.Context())
	u, err := (&Basic{}).VerifyAuthToken(req, httptest.NewRecorder(), reqctx.ContextData{}, nil, token.Token)
	require.NoError(t, err)
	require.NotNil(t, u)
	require.Equal(t, int64(1), u.ID)
}

func TestEnterpriseWeComLoginOnlyDoesNotBlockGitHTTPBasicTokenVerification(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer mockEnterpriseWeComLoginOnly()()

	token := &auth_model.AccessToken{UID: 1, Name: "git-http-token", Scope: auth_model.AccessTokenScopeAll}
	require.NoError(t, auth_model.NewAccessToken(t.Context(), token))

	req := httptest.NewRequest(http.MethodGet, "/owner/repo.git/info/refs?service=git-upload-pack", nil)
	req = req.WithContext(t.Context())
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user1:"+token.Token)))
	u, err := (&Basic{}).Verify(req, httptest.NewRecorder(), reqctx.ContextData{}, nil)
	require.NoError(t, err)
	require.NotNil(t, u)
	require.Equal(t, int64(1), u.ID)
}

func mockEnterpriseWeComLoginOnly() func() {
	return test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:          true,
		LoginOnly:        true,
		CorpID:           "corp-1",
		AgentID:          "1000002",
		CorpSecret:       "secret",
		UsernameTemplate: "{userid}",
		AutoCreateUser:   true,
	})
}
