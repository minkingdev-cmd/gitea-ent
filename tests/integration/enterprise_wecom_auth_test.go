// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"bytes"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/routers"
	"gitea.dev/services/auth/source/oauth2"
	"gitea.dev/services/auth/source/sspi"
	wecom_service "gitea.dev/services/enterprisewecom"
	"gitea.dev/tests"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

func TestEnterpriseWeComLoginOnlyIntegration(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	token := getUserToken(t, "user2", auth_model.AccessTokenScopeReadUser, auth_model.AccessTokenScopeReadRepository)
	mockWeCom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/cgi-bin/gettoken":
			require.Equal(t, "corp-integration", r.URL.Query().Get("corpid"))
			require.Equal(t, "integration-secret", r.URL.Query().Get("corpsecret"))
			_, _ = w.Write([]byte(`{"errcode":0,"access_token":"integration-token","expires_in":7200}`))
		case "/cgi-bin/auth/getuserinfo":
			require.Equal(t, "integration-token", r.URL.Query().Get("access_token"))
			require.Equal(t, "integration-code", r.URL.Query().Get("code"))
			_, _ = w.Write([]byte(`{"errcode":0,"userid":"wecom-integration-user","deviceid":"device-1"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockWeCom.Close()

	const sourceName = "wecom-integration"
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:          true,
		LoginOnly:        true,
		LoginSourceName:  sourceName,
		CorpID:           "corp-integration",
		AgentID:          "1000002",
		CorpSecret:       "integration-secret",
		UsernameTemplate: "{userid}",
		AutoCreateUser:   true,
		APIBaseURL:       mockWeCom.URL,
		OAuthBaseURL:     mockWeCom.URL,
		HTTPTimeout:      5 * time.Second,
	})()
	defer test.MockVariableValue(&setting.Service.EnablePasswordSignInForm, true)()
	defer test.MockVariableValue(&setting.Service.EnableOpenIDSignIn, true)()
	defer test.MockVariableValue(&setting.Service.EnableOpenIDSignUp, true)()
	defer test.MockVariableValue(&setting.Service.EnablePasskeyAuth, true)()
	defer test.MockVariableValue(&setting.Service.EnableReverseProxyAuth, true)()
	defer test.MockVariableValue(&setting.ReverseProxyAuthUser, "X-WEBAUTH-USER")()

	addOAuth2Source(t, sourceName, oauth2.Source{Provider: oauth2.ProviderNameWeCom})
	addOAuth2Source(t, "non-wecom-integration", oauth2.Source{Provider: "gitea"})
	require.NoError(t, auth_model.CreateSource(t.Context(), &auth_model.Source{
		Name: "sspi-integration", Type: auth_model.SSPI, IsActive: true,
		Cfg: &sspi.Source{AutoCreateUsers: true, AutoActivateUsers: true},
	}))

	t.Run("only WeCom Web login is reachable", func(t *testing.T) {
		resp := MakeRequest(t, NewRequest(t, "GET", "/user/login"), http.StatusSeeOther)
		assert.Equal(t, "/user/oauth2/"+sourceName, resp.Header().Get("Location"))

		for _, tc := range []struct {
			method string
			path   string
		}{
			{"POST", "/user/login"},
			{"GET", "/user/sign_up"},
			{"POST", "/user/sign_up"},
			{"GET", "/user/login/openid"},
			{"GET", "/user/webauthn/passkey/assertion"},
			{"GET", "/user/link_account"},
			{"POST", "/user/link_account_signin"},
			{"POST", "/user/link_account_signup"},
			{"GET", "/user/forgot_password"},
			{"POST", "/user/forgot_password"},
			{"GET", "/user/recover_account"},
			{"POST", "/user/recover_account"},
			{"GET", "/user/activate"},
			{"POST", "/user/activate"},
			{"GET", "/user/two_factor"},
			{"GET", "/user/webauthn/assertion"},
			{"GET", "/user/oauth2/non-wecom-integration"},
		} {
			t.Run(tc.method+" "+tc.path, func(t *testing.T) {
				MakeRequest(t, NewRequest(t, tc.method, tc.path), http.StatusForbidden)
			})
		}

		req := NewRequest(t, "GET", "/user/settings").SetHeader(setting.ReverseProxyAuthUser, "user2")
		resp = MakeRequest(t, req, http.StatusSeeOther)
		assert.Contains(t, resp.Header().Get("Location"), "/user/login")
	})

	t.Run("SSPI Negotiate cannot create a Web session", func(t *testing.T) {
		require.True(t, auth_model.IsSSPIEnabled(t.Context()))
		defer test.MockVariableValue(&testWebRoutes)()
		func() {
			defer test.MockVariableValue(&setting.EnterpriseWeCom.LoginOnly, false)()
			testWebRoutes = routers.NormalRoutes()
		}()
		usersBefore := unittest.GetCount(t, &user_model.User{})
		session := emptyTestSession(t)
		req := NewRequestWithValues(t, "POST", "/user/login", map[string]string{"auth_with_sspi": "1"}).SetHeader("Authorization", "Negotiate dGVzdA==")
		resp := session.MakeRequest(t, req, http.StatusForbidden)
		require.Empty(t, resp.Header().Get("WWW-Authenticate"))
		req = NewRequest(t, "GET", "/user/login?auth_with_sspi=1").SetHeader("Authorization", "Negotiate dGVzdA==")
		resp = session.MakeRequest(t, req, http.StatusSeeOther)
		require.Equal(t, "/user/oauth2/"+sourceName, resp.Header().Get("Location"))
		require.Empty(t, resp.Header().Get("WWW-Authenticate"))
		session.MakeRequest(t, NewRequest(t, "GET", "/user/settings"), http.StatusSeeOther)
		require.Equal(t, usersBefore, unittest.GetCount(t, &user_model.User{}))
	})

	t.Run("WeCom callback creates a Web session", func(t *testing.T) {
		session := emptyTestSession(t)
		resp := session.MakeRequest(t, NewRequest(t, "GET", "/user/oauth2/"+sourceName), http.StatusTemporaryRedirect)
		authorizeURL, err := url.Parse(resp.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, mockWeCom.URL, authorizeURL.Scheme+"://"+authorizeURL.Host)
		assert.Equal(t, "corp-integration", authorizeURL.Query().Get("appid"))
		state := authorizeURL.Query().Get("state")
		require.NotEmpty(t, state)

		callback := "/user/oauth2/" + sourceName + "/callback?code=integration-code&state=" + url.QueryEscape(state)
		resp = session.MakeRequest(t, NewRequest(t, "GET", callback), http.StatusSeeOther)
		assert.Equal(t, "/", resp.Header().Get("Location"))
		session.MakeRequest(t, NewRequest(t, "GET", "/user/settings"), http.StatusOK)

		identity, has, err := wecom_model.GetIdentityByCorpAndUserID(t.Context(), "corp-integration", "wecom-integration-user")
		require.NoError(t, err)
		require.True(t, has)
		assert.Positive(t, identity.UserID)
	})

	t.Run("WeCom OAuth continues through legitimate MFA", func(t *testing.T) {
		identity := unittest.AssertExistsAndLoadBean(t, &wecom_model.Identity{CorpID: "corp-integration", WeComUserID: "wecom-integration-user"})
		key, err := totp.Generate(totp.GenerateOpts{Issuer: "gitea-test", AccountName: "wecom-mfa"})
		require.NoError(t, err)
		factor := &auth_model.TwoFactor{UID: identity.UserID}
		require.NoError(t, factor.SetSecret(key.Secret()))
		require.NoError(t, auth_model.NewTwoFactor(t.Context(), factor))
		session := emptyTestSession(t)
		response := session.MakeRequest(t, NewRequest(t, "GET", "/user/oauth2/"+sourceName), http.StatusTemporaryRedirect)
		authorizeURL, err := url.Parse(response.Header().Get("Location"))
		require.NoError(t, err)
		state := authorizeURL.Query().Get("state")
		require.NotEmpty(t, state)
		response = session.MakeRequest(t, NewRequest(t, "GET", "/user/oauth2/"+sourceName+"/callback?code=integration-code&state="+url.QueryEscape(state)), http.StatusSeeOther)
		require.Contains(t, response.Header().Get("Location"), "/user/two_factor")
		session.MakeRequest(t, NewRequest(t, "GET", "/user/settings"), http.StatusSeeOther)
		session.MakeRequest(t, NewRequest(t, "GET", "/user/two_factor"), http.StatusOK)
		passcode, err := totp.GenerateCode(key.Secret(), time.Now())
		require.NoError(t, err)
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/two_factor", map[string]string{"passcode": passcode}), http.StatusSeeOther)
		session.MakeRequest(t, NewRequest(t, "GET", "/user/settings"), http.StatusOK)
	})

	t.Run("PAT and Git HTTP token remain valid after mapping apply", func(t *testing.T) {
		applyEnterpriseWeComAuthzMappingForUser(t, "corp-integration", "mapped-user2", "user2")

		MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(token), http.StatusOK)
		resp := MakeRequest(t, NewRequest(t, "GET", "/user2/repo2/info/refs?service=git-upload-pack").AddBasicAuth("user2", token), http.StatusOK)
		assert.Contains(t, resp.Body.String(), "refs/heads/master")
	})
}

func TestEnterpriseWeComLoginOnlySmoke(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		ctx := NewAPITestContext(t, "user2", "repo1", auth_model.AccessTokenScopeWriteUser, auth_model.AccessTokenScopeReadRepository)
		const sourceName = "enterprise-wecom-smoke"
		defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
			Enabled: true, LoginOnly: false, LoginSourceName: sourceName,
			CorpID: "corp-smoke", AgentID: "1000002", CorpSecret: "smoke-secret",
		})()
		addOAuth2Source(t, sourceName, oauth2.Source{Provider: oauth2.ProviderNameWeCom})
		require.NoError(t, auth_model.CreateSource(t.Context(), &auth_model.Source{
			Name: "sspi-smoke", Type: auth_model.SSPI, IsActive: true,
			Cfg: &sspi.Source{AutoCreateUsers: true, AutoActivateUsers: true},
		}))
		withKeyFile(t, "wecom-login-only-ssh", func(keyFile string) {
			t.Run("CreateUserKey", doAPICreateUserKey(ctx, "wecom-login-only-ssh", keyFile))
			applyEnterpriseWeComAuthzMappingForUser(t, "corp-smoke", "mapped-ssh-user2", "user2")

			privateKey, err := os.ReadFile(keyFile)
			require.NoError(t, err)
			signer, err := gossh.ParsePrivateKey(privateKey)
			require.NoError(t, err)

			setting.EnterpriseWeCom.LoginOnly = true

			jar, err := cookiejar.New(nil)
			require.NoError(t, err)
			httpClient := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			req, err := http.NewRequest(http.MethodGet, u.ResolveReference(&url.URL{Path: "/user/login"}).String(), nil)
			require.NoError(t, err)
			resp, err := httpClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusSeeOther, resp.StatusCode)
			assert.Equal(t, "/user/oauth2/"+sourceName, resp.Header.Get("Location"))

			req, err = http.NewRequest(http.MethodPost, u.ResolveReference(&url.URL{Path: "/user/login"}).String(), nil)
			require.NoError(t, err)
			resp, err = httpClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusForbidden, resp.StatusCode)

			req, err = http.NewRequest(http.MethodPost, u.ResolveReference(&url.URL{Path: "/user/login"}).String(), strings.NewReader(url.Values{"auth_with_sspi": {"1"}}.Encode()))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("Authorization", "Negotiate dGVzdA==")
			resp, err = httpClient.Do(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, http.StatusForbidden, resp.StatusCode)
			require.Empty(t, resp.Header.Get("WWW-Authenticate"))

			req, err = http.NewRequest(http.MethodGet, u.ResolveReference(&url.URL{Path: "/user/settings"}).String(), nil)
			require.NoError(t, err)
			resp, err = httpClient.Do(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, http.StatusSeeOther, resp.StatusCode)

			req, err = http.NewRequest(http.MethodGet, u.ResolveReference(&url.URL{Path: "/api/v1/user"}).String(), nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+ctx.Token)
			resp, err = httpClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			gitURL := u.ResolveReference(&url.URL{Path: "/user2/repo2/info/refs", RawQuery: "service=git-upload-pack"})
			req, err = http.NewRequest(http.MethodGet, gitURL.String(), nil)
			require.NoError(t, err)
			req.SetBasicAuth("user2", ctx.Token)
			resp, err = httpClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			sshClient, err := gossh.Dial("tcp", net.JoinHostPort(setting.SSH.ListenHost, strconv.Itoa(setting.SSH.ListenPort)), &gossh.ClientConfig{
				User:            setting.SSH.BuiltinServerUser,
				Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
				HostKeyCallback: gossh.InsecureIgnoreHostKey(),
			})
			require.NoError(t, err)
			defer sshClient.Close()

			session, err := sshClient.NewSession()
			require.NoError(t, err)
			var stderr bytes.Buffer
			session.Stderr = &stderr
			require.NoError(t, session.Shell())
			require.NoError(t, session.Wait())
			assert.Contains(t, stderr.String(), "You've successfully authenticated with the SSH key named wecom-login-only-ssh.")
		})
	})
}

func applyEnterpriseWeComAuthzMappingForUser(t *testing.T, corpID, wecomUserID, username string) {
	t.Helper()
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{Name: username})
	org := unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 7})
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{
		UserID:      user.ID,
		CorpID:      corpID,
		WeComUserID: wecomUserID,
		Status:      wecom_model.IdentityStatusActive,
	})
	require.NoError(t, err)
	mapping, err := wecom_service.CreateAuthzMapping(t.Context(), wecom_service.AuthzMappingOptions{
		CorpID:     corpID,
		SourceType: wecom_model.AuthzSourceUser,
		SourceID:   wecomUserID,
		TargetType: wecom_model.AuthzTargetOrg,
		OrgID:      org.ID,
		ActorID:    user.ID,
	})
	require.NoError(t, err)
	mapping.AgentID, mapping.Origin = setting.EnterpriseWeCom.AgentID, wecom_model.AuthzMappingOriginGenerated
	_, err = db.GetEngine(t.Context()).ID(mapping.ID).Cols("agent_id", "origin").Update(mapping)
	require.NoError(t, err)
	defer test.MockVariableValue(&setting.EnterpriseWeCom.ManagedOrgID, org.ID)()
	_, err = wecom_service.ApplyAuthzMappings(t.Context(), wecom_service.AuthzReconcileOptions{CorpID: corpID, ActorID: user.ID, ApplyID: "auth-regression"})
	require.NoError(t, err)
}
