// Copyright 2024 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/session"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/util"
	"gitea.dev/services/auth/source/oauth2"
	"gitea.dev/services/context"
	"gitea.dev/services/contexttest"

	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func addOAuth2Source(t *testing.T, authName string, cfg oauth2.Source) {
	cfg.Provider = util.IfZero(cfg.Provider, "gitea")
	err := auth_model.CreateSource(t.Context(), &auth_model.Source{
		Type:     auth_model.OAuth2,
		Name:     authName,
		IsActive: true,
		Cfg:      &cfg,
	})
	require.NoError(t, err)
}

func TestEnterpriseWeComLoginOnlyWebSurface(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:          true,
		LoginOnly:        true,
		LoginSourceName:  "wecom-login-only-source",
		CorpID:           "corp-1",
		AgentID:          "1000002",
		CorpSecret:       "secret",
		UsernameTemplate: "{userid}",
		AutoCreateUser:   true,
	})()
	defer test.MockVariableValue(&setting.Service.EnablePasswordSignInForm, true)()
	defer test.MockVariableValue(&setting.Service.EnableOpenIDSignIn, true)()
	defer test.MockVariableValue(&setting.Service.EnableOpenIDSignUp, true)()
	defer test.MockVariableValue(&setting.Service.EnablePasskeyAuth, true)()
	defer test.MockVariableValue(&setting.Service.ShowRegistrationButton, true)()

	addOAuth2Source(t, "wecom-login-only-source", oauth2.Source{Provider: oauth2.ProviderNameWeCom})
	addOAuth2Source(t, "non-wecom-login-only-source", oauth2.Source{Provider: "gitea"})

	ctx, resp := contexttest.MockContext(t, "/user/login")
	SignIn(ctx)
	require.Equal(t, http.StatusSeeOther, resp.Code)
	require.Equal(t, "/user/oauth2/wecom-login-only-source", test.RedirectURL(resp))
	require.Equal(t, false, ctx.Data["EnablePasswordSignInForm"])
	require.Equal(t, false, ctx.Data["EnableOpenIDSignIn"])
	require.Equal(t, false, ctx.Data["EnableOpenIDSignUp"])
	require.Equal(t, false, ctx.Data["EnablePasskeyAuth"])
	require.Len(t, ctx.Data["OAuth2Providers"], 1)

	ctx, resp = contexttest.MockContext(t, "/user/login")
	SignInPost(ctx)
	require.Equal(t, http.StatusForbidden, resp.Code)

	ctx, resp = contexttest.MockContext(t, "/user/sign_up")
	SignUp(ctx)
	require.Equal(t, http.StatusForbidden, resp.Code)

	ctx, resp = contexttest.MockContext(t, "/user/login/openid")
	SignInOpenID(ctx)
	require.Equal(t, http.StatusForbidden, resp.Code)

	ctx, resp = contexttest.MockContext(t, "/user/webauthn/passkey/assertion")
	WebAuthnPasskeyAssertion(ctx)
	require.Equal(t, http.StatusForbidden, resp.Code)

	ctx, resp = contexttest.MockContext(t, "/user/oauth2/non-wecom-login-only-source")
	ctx.SetPathParamRaw("provider", "non-wecom-login-only-source")
	SignInOAuth(ctx)
	require.Equal(t, http.StatusForbidden, resp.Code)

	for name, handler := range map[string]func(*context.Context){
		"link account":          LinkAccount,
		"link account sign-in":  LinkAccountPostSignIn,
		"link account sign-up":  LinkAccountPostRegister,
		"forgot password":       ForgotPasswd,
		"forgot password post":  ForgotPasswdPost,
		"reset password":        ResetPasswd,
		"reset password post":   ResetPasswdPost,
		"activate account":      Activate,
		"activate account post": ActivatePost,
		"non-WeCom two-factor":  TwoFactor,
		"non-WeCom WebAuthn":    WebAuthn,
	} {
		t.Run(name, func(t *testing.T) {
			ctx, resp := contexttest.MockContext(t, "/user/login")
			handler(ctx)
			require.Equal(t, http.StatusForbidden, resp.Code)
		})
	}

	ctx, resp = contexttest.MockContext(t, "/user/two_factor", contexttest.MockContextOption{SessionStore: session.NewMockMemStore("oauth-mfa-sid")})
	require.NoError(t, ctx.Session.Set(session.KeySignInMethod, session.SignInMethodOAuth2))
	require.True(t, rejectNonWeComSecondFactor(ctx))
	require.Equal(t, http.StatusForbidden, resp.Code)

	ctx, _ = contexttest.MockContext(t, "/user/two_factor", contexttest.MockContextOption{SessionStore: session.NewMockMemStore("wecom-mfa-sid")})
	require.NoError(t, ctx.Session.Set(session.KeySignInMethod, session.SignInMethodOAuth2))
	require.NoError(t, ctx.Session.Set(sessionKeyWeComSecondFactor, true))
	require.False(t, rejectNonWeComSecondFactor(ctx))
}

func TestEnterpriseWeComOAuthCallbackCreatesIdentity(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:          true,
		LoginOnly:        true,
		LoginSourceName:  "wecom-callback-source",
		CorpID:           "corp-1",
		AgentID:          "1000002",
		CorpSecret:       "secret",
		UsernameTemplate: "{userid}",
		AutoCreateUser:   true,
	})()
	defer test.MockVariableValue(&setting.OAuth2Client.EnableAutoRegistration, false)()
	defer test.MockVariableValue(&gothic.CompleteUserAuth, func(res http.ResponseWriter, req *http.Request) (goth.User, error) {
		return goth.User{
			Provider: "wecom-callback-source",
			UserID:   "wangwu",
			RawData: map[string]any{
				"wecom_corp_id":  "corp-1",
				"wecom_agent_id": "1000002",
				"wecom_userid":   "wangwu",
			},
		}, nil
	})()

	addOAuth2Source(t, "wecom-callback-source", oauth2.Source{Provider: oauth2.ProviderNameWeCom})

	mockOpt := contexttest.MockContextOption{SessionStore: session.NewMockMemStore("wecom-callback-sid")}
	ctx, resp := contexttest.MockContext(t, "/user/oauth2/wecom-callback-source/callback?code=dummy-code", mockOpt)
	ctx.SetPathParamRaw("provider", "wecom-callback-source")
	SignInOAuthCallback(ctx)

	require.Equal(t, http.StatusSeeOther, resp.Code)
	require.Equal(t, "/", test.RedirectURL(resp))
	identity, has, err := wecom_model.GetIdentityByCorpAndUserID(t.Context(), "corp-1", "wangwu")
	require.NoError(t, err)
	require.True(t, has)
	require.NotZero(t, identity.UserID)
}

func TestEnterpriseWeComOAuthCallbackInvalidStateAuditsDeny(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:          true,
		LoginOnly:        true,
		LoginSourceName:  "wecom-invalid-state-source",
		CorpID:           "corp-1",
		AgentID:          "1000002",
		CorpSecret:       "secret",
		UsernameTemplate: "{userid}",
		AutoCreateUser:   true,
	})()
	deleteWeComAuditEvents(t)

	addOAuth2Source(t, "wecom-invalid-state-source", oauth2.Source{Provider: oauth2.ProviderNameWeCom})

	mockOpt := contexttest.MockContextOption{SessionStore: session.NewMockMemStore("wecom-invalid-state-sid")}
	ctx, resp := contexttest.MockContext(t, "/user/oauth2/wecom-invalid-state-source/callback?code=authorization-code", mockOpt)
	ctx.SetPathParamRaw("provider", "wecom-invalid-state-source")
	SignInOAuthCallback(ctx)

	require.Equal(t, http.StatusSeeOther, resp.Code)
	events := weComAuditEvents(t)
	require.Contains(t, eventActions(events), audit_model.EnterpriseWeComLoginDeny)
	for _, event := range events {
		metadata := audit_model.DecodeMetadata(event.Metadata)
		require.NotContains(t, metadata, "code")
		require.NotContains(t, metadata, "token")
		require.NotContains(t, metadata, "secret")
	}
}

func TestEnterpriseWeComDisabledSourceIsRejected(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled: true, LoginOnly: false, LoginSourceName: "wecom-disabled-source",
		CorpID: "corp-1", AgentID: "1000002", CorpSecret: "secret",
	})()
	addOAuth2Source(t, "wecom-disabled-source", oauth2.Source{Provider: oauth2.ProviderNameWeCom})
	setting.EnterpriseWeCom.Enabled = false

	ctx, resp := contexttest.MockContext(t, "/user/oauth2/wecom-disabled-source")
	ctx.SetPathParamRaw("provider", "wecom-disabled-source")
	SignInOAuth(ctx)
	require.Equal(t, http.StatusNotFound, resp.Code)

	ctx, resp = contexttest.MockContext(t, "/user/oauth2/wecom-disabled-source/callback")
	ctx.SetPathParamRaw("provider", "wecom-disabled-source")
	SignInOAuthCallback(ctx)
	require.Equal(t, http.StatusNotFound, resp.Code)
}

func TestEnterpriseWeComCallbackErrorDoesNotExposeParameters(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled: true, LoginOnly: true, LoginSourceName: "wecom-error-source",
		CorpID: "corp-1", AgentID: "1000002", CorpSecret: "secret",
	})()
	addOAuth2Source(t, "wecom-error-source", oauth2.Source{Provider: oauth2.ProviderNameWeCom})

	mockOpt := contexttest.MockContextOption{SessionStore: session.NewMockMemStore("wecom-error-sid")}
	ctx, resp := contexttest.MockContext(t, "/user/oauth2/wecom-error-source/callback?error=access_denied&error_description=secret-description&code=secret-code", mockOpt)
	ctx.SetPathParamRaw("provider", "wecom-error-source")
	SignInOAuthCallback(ctx)

	require.Equal(t, http.StatusSeeOther, resp.Code)
	require.Contains(t, ctx.Flash.ErrorMsg, "auth.oauth.signin.error.wecom")
	require.NotContains(t, ctx.Flash.ErrorMsg, "secret-description")
	require.NotContains(t, ctx.Flash.ErrorMsg, "secret-code")
}

func TestWebAuthUserLogin(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	ctx, resp := contexttest.MockContext(t, "/user/login")
	SignIn(ctx)
	assert.Equal(t, http.StatusOK, resp.Code)

	ctx, resp = contexttest.MockContext(t, "/user/login")
	ctx.IsSigned = true
	SignIn(ctx)
	assert.Equal(t, http.StatusSeeOther, resp.Code)
	assert.Equal(t, "/", test.RedirectURL(resp))

	ctx, resp = contexttest.MockContext(t, "/user/login?redirect_to=/other")
	ctx.IsSigned = true
	SignIn(ctx)
	assert.Equal(t, "/other", test.RedirectURL(resp))

	ctx, resp = contexttest.MockContext(t, "/user/login")
	ctx.Req.AddCookie(&http.Cookie{Name: "redirect_to", Value: "/other-cookie"})
	ctx.IsSigned = true
	SignIn(ctx)
	assert.Equal(t, "/other-cookie", test.RedirectURL(resp))

	ctx, resp = contexttest.MockContext(t, "/user/login?redirect_to="+url.QueryEscape("https://example.com"))
	ctx.IsSigned = true
	SignIn(ctx)
	assert.Equal(t, "/", test.RedirectURL(resp))
}

func TestWebAuthOAuth2(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.OAuth2Client.EnableAutoRegistration, true)()

	_ = oauth2.Init(t.Context())
	addOAuth2Source(t, "dummy+auth's source", oauth2.Source{})

	t.Run("OAuth2MissingField", func(t *testing.T) {
		defer test.MockVariableValue(&gothic.CompleteUserAuth, func(res http.ResponseWriter, req *http.Request) (goth.User, error) {
			return goth.User{Provider: "dummy+auth's source", UserID: "dummy-user"}, nil
		})()
		mockOpt := contexttest.MockContextOption{SessionStore: session.NewMockMemStore("dummy-sid")}
		ctx, resp := contexttest.MockContext(t, "/user/oauth2/..../callback?code=dummy-code", mockOpt)
		ctx.SetPathParamRaw("provider", "dummy+auth%27s%20source")
		SignInOAuthCallback(ctx)
		assert.Equal(t, http.StatusSeeOther, resp.Code)
		assert.Equal(t, "/user/link_account", test.RedirectURL(resp))

		// then the user will be redirected to the link account page, and see a message about the missing fields
		ctx, _ = contexttest.MockContext(t, "/user/link_account", mockOpt)
		LinkAccount(ctx)
		assert.Equal(t, template.HTML("auth.oauth_callback_unable_auto_reg:dummy+auth&#39;s source,email"), ctx.Data["AutoRegistrationFailedPrompt"])
	})

	t.Run("OAuth2CallbackError", func(t *testing.T) {
		mockOpt := contexttest.MockContextOption{SessionStore: session.NewMockMemStore("dummy-sid")}
		ctx, resp := contexttest.MockContext(t, "/user/oauth2/...../callback", mockOpt)
		ctx.SetPathParamRaw("provider", "dummy+auth%27s%20source")
		SignInOAuthCallback(ctx)
		assert.Equal(t, http.StatusSeeOther, resp.Code)
		assert.Equal(t, "/user/login", test.RedirectURL(resp))
		assert.Contains(t, ctx.Flash.ErrorMsg, "auth.oauth.signin.error.general")
	})

	t.Run("RedirectSingleProvider", func(t *testing.T) {
		enablePassword := &setting.Service.EnablePasswordSignInForm
		enableOpenID := &setting.Service.EnableOpenIDSignIn
		enablePasskey := &setting.Service.EnablePasskeyAuth
		defer test.MockVariableValue(enablePassword, false)()
		defer test.MockVariableValue(enableOpenID, false)()
		defer test.MockVariableValue(enablePasskey, false)()

		testSignIn := func(t *testing.T, link string, expectedCode int, expectedRedirect string) {
			ctx, resp := contexttest.MockContext(t, link)
			SignIn(ctx)
			assert.Equal(t, expectedCode, resp.Code)
			if expectedCode == http.StatusSeeOther {
				assert.Equal(t, expectedRedirect, test.RedirectURL(resp))
			}
		}
		testSignIn(t, "/user/login", http.StatusSeeOther, "/user/oauth2/dummy+auth%27s%20source")
		testSignIn(t, "/user/login?redirect_to=/", http.StatusSeeOther, "/user/oauth2/dummy+auth%27s%20source?redirect_to=%2F")

		*enablePassword, *enableOpenID, *enablePasskey = true, false, false
		testSignIn(t, "/user/login", http.StatusOK, "")
		*enablePassword, *enableOpenID, *enablePasskey = false, true, false
		testSignIn(t, "/user/login", http.StatusOK, "")
		*enablePassword, *enableOpenID, *enablePasskey = false, false, true
		testSignIn(t, "/user/login", http.StatusOK, "")

		*enablePassword, *enableOpenID, *enablePasskey = false, false, false
		addOAuth2Source(t, "dummy-auth-source-2", oauth2.Source{})
		testSignIn(t, "/user/login", http.StatusOK, "")
	})

	t.Run("OIDCLogout", func(t *testing.T) {
		var mockServer *httptest.Server
		mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				_, _ = w.Write([]byte(`{
				"issuer": "` + mockServer.URL + `",
				"authorization_endpoint": "` + mockServer.URL + `/authorize",
				"token_endpoint": "` + mockServer.URL + `/token",
				"userinfo_endpoint": "` + mockServer.URL + `/userinfo",
				"end_session_endpoint": "https://example.com/oidc-logout?oidc-key=oidc-val"
			}`))
			default:
				http.NotFound(w, r)
			}
		}))
		defer mockServer.Close()

		addOAuth2Source(t, "oidc-auth-source", oauth2.Source{
			Provider:                      "openidConnect",
			ClientID:                      "mock-client-id",
			OpenIDConnectAutoDiscoveryURL: mockServer.URL + "/.well-known/openid-configuration",
		})
		authSource, err := auth_model.GetActiveOAuth2SourceByAuthName(t.Context(), "oidc-auth-source")
		require.NoError(t, err)

		oauthUser := &user_model.User{ID: 1, LoginType: auth_model.OAuth2, LoginSource: authSource.ID}

		t.Run("OAuth2SignInRedirectsToOIDC", func(t *testing.T) {
			mockOpt := contexttest.MockContextOption{SessionStore: session.NewMockMemStore("dummy-sid-oauth")}
			ctx, resp := contexttest.MockContext(t, "/user/logout", mockOpt)
			ctx.Doer = oauthUser
			require.NoError(t, ctx.Session.Set(session.KeySignInMethod, session.SignInMethodOAuth2))
			SignOut(ctx)
			assert.Equal(t, http.StatusSeeOther, resp.Code)
			u, err := url.Parse(test.RedirectURL(resp))
			require.NoError(t, err)
			expectedValues := url.Values{"oidc-key": []string{"oidc-val"}, "post_logout_redirect_uri": []string{setting.AppURL}, "client_id": []string{"mock-client-id"}}
			assert.Equal(t, expectedValues, u.Query())
			u.RawQuery = ""
			assert.Equal(t, "https://example.com/oidc-logout", u.String())
		})

		t.Run("PasswordSignInSkipsOIDC", func(t *testing.T) {
			// OAuth2-linked account signed in via password form must not hit end_session_endpoint.
			mockOpt := contexttest.MockContextOption{SessionStore: session.NewMockMemStore("dummy-sid-password")}
			ctx, resp := contexttest.MockContext(t, "/user/logout", mockOpt)
			ctx.Doer = oauthUser
			SignOut(ctx)
			assert.Equal(t, http.StatusSeeOther, resp.Code)
			assert.Equal(t, "/", test.RedirectURL(resp))
		})
	})
}

func deleteWeComAuditEvents(t *testing.T) {
	t.Helper()
	_, err := db.GetEngine(t.Context()).Where("action LIKE ?", "enterprise:wecom:%").Delete(new(audit_model.Event))
	require.NoError(t, err)
}

func weComAuditEvents(t *testing.T) []*audit_model.Event {
	t.Helper()
	events, _, err := audit_model.FindEvents(t.Context(), &audit_model.EventSearchOptions{
		ActionPrefix: audit_model.Action("enterprise:wecom"),
		Sort:         audit_model.SortTimestampAsc,
	})
	require.NoError(t, err)
	require.NotEmpty(t, events)
	return events
}

func eventActions(events []*audit_model.Event) []audit_model.Action {
	actions := make([]audit_model.Action, 0, len(events))
	for _, event := range events {
		actions = append(actions, event.Action)
	}
	return actions
}

func TestOpenIDRequireTwoFactor(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockOpt := contexttest.MockContextOption{SessionStore: session.NewMockMemStore("dummy-sid-openid")}

	user32 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 32}) // has a webauthn credential
	ctx, resp := contexttest.MockContext(t, "/user/openid/connect", mockOpt)
	openIDRequireTwoFactor(ctx, user32, false, "https://example.com/id")
	assert.Equal(t, "/user/webauthn", test.RedirectURL(resp))
	unittest.AssertNotExistsBean(t, &user_model.UserOpenID{UID: user32.ID}) // not attached before the key answered

	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	ctx, _ = contexttest.MockContext(t, "/user/openid/connect", mockOpt)
	openIDRequireTwoFactor(ctx, user2, false, "https://example.com/id")
	assert.False(t, ctx.Written())
}
