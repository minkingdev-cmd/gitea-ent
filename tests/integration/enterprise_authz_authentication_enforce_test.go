// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	actions_model "gitea.dev/models/actions"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	deploykey_model "gitea.dev/models/deploykey"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/perm"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/git"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func authzAuthenticationModes(t *testing.T, cases map[string]func(*testing.T)) {
	t.Helper()
	for _, mode := range []struct {
		name             string
		enabled, enforce bool
	}{{"disabled", false, false}, {"shadow", true, false}, {"enforce", true, true}} {
		t.Run(mode.name, func(t *testing.T) {
			defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, mode.enabled)()
			defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, mode.enforce)()
			defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
			defer test.MockVariableValue(&setting.EnterpriseWeCom.AdminCallbackEnabled, false)()
			for _, name := range slices.Sorted(maps.Keys(cases)) {
				t.Run(name, cases[name])
			}
			require.False(t, setting.EnterpriseWeCom.AdminCallbackEnabled)
		})
	}
}

func TestEnterpriseAuthzAuthenticationWebRegression(t *testing.T) {
	authzAuthenticationModes(t, map[string]func(*testing.T){
		"forbidden_and_legal_MFA": TestEnterpriseWeComLoginOnlyIntegration,
		"live_HTTP_and_SSH":       TestEnterpriseWeComLoginOnlySmoke,
		"callback_closed":         authzCallbackAndForbiddenAuthClosed,
	})
}

func authzCallbackAndForbiddenAuthClosed(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer provider.Close()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, LoginOnly: true, LoginSourceName: "wecom-auth-compat", CorpID: "auth-compat", APIBaseURL: provider.URL, OAuthBaseURL: provider.URL})()
	defer test.MockVariableValue(&setting.Service.EnableReverseProxyAuth, true)()
	defer test.MockVariableValue(&setting.ReverseProxyAuthUser, "X-WEBAUTH-USER")()
	for _, path := range []string{"/enterprise/wecom/callback/admin-authority", "/api/v1/enterprise/wecom/callback/admin-authority"} {
		for _, method := range []string{"GET", "POST"} {
			response := MakeRequest(t, NewRequest(t, method, path), 404)
			require.Empty(t, response.Header().Values("Set-Cookie"))
		}
	}
	for _, route := range []struct {
		method, path string
		status       int
	}{{"POST", "/user/login/openid", 403}, {"POST", "/user/webauthn/passkey/assertion", 405}, {"GET", "/user/oauth2/non-wecom/callback", 404}, {"POST", "/user/two_factor", 403}} {
		MakeRequest(t, NewRequest(t, route.method, route.path), route.status)
	}
	session := emptyTestSession(t)
	session.MakeRequest(t, NewRequest(t, "GET", "/user/settings").SetHeader(setting.ReverseProxyAuthUser, "user2"), 303)
	session.MakeRequest(t, NewRequest(t, "GET", "/user/settings"), 303)
	require.Zero(t, calls.Load())
	unittest.AssertCount(t, &wecom_model.CallbackReceipt{}, 0)
}

func TestEnterpriseAuthzAuthenticationTokenAndSSHRegression(t *testing.T) {
	authzAuthenticationModes(t, map[string]func(*testing.T){
		"api_token_metadata":      TestAPIGetCurrentToken,
		"api_token_revocation":    TestAPITokenSelfService,
		"repository_scope":        TestAPIRepositoryCreationTokenScopes,
		"ssh_create_state_revoke": TestEnterpriseWeComNativeSSHAccountStateParity,
		"PAT_GitHTTP_states":      authzProtocolCredentialStateParity,
	})
}

func authzProtocolCredentialStateParity(t *testing.T) {
	for _, state := range []struct {
		name                         string
		active, prohibit, restricted bool
		status                       int
	}{{"normal", true, false, false, 200}, {"inactive", false, false, false, 403}, {"prohibited", true, true, false, 403}, {"restricted", true, false, true, 200}} {
		t.Run(state.name, func(t *testing.T) {
			defer tests.PrepareTestEnv(t)()
			var calls atomic.Int32
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer provider.Close()
			user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			master := getUserToken(t, user.Name, auth_model.AccessTokenScopeWriteUser, auth_model.AccessTokenScopeReadRepository)
			narrow := getUserToken(t, user.Name, auth_model.AccessTokenScopeReadUser)
			defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, LoginOnly: true, CorpID: "credential-compat", APIBaseURL: provider.URL, OAuthBaseURL: provider.URL})()
			user.IsActive, user.ProhibitLogin, user.IsRestricted = state.active, state.prohibit, state.restricted
			require.NoError(t, user_model.UpdateUserCols(t.Context(), user, "is_active", "prohibit_login", "is_restricted"))
			MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(master), state.status)
			MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo2").AddTokenAuth(master), state.status)
			MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo2").AddTokenAuth(narrow), 403)
			gitRead := MakeRequest(t, NewRequest(t, "GET", "/user2/repo2/info/refs?service=git-upload-pack").AddBasicAuth(user.Name, master), 200)
			require.Equal(t, state.status == 200, strings.Contains(gitRead.Header().Get("Content-Type"), "application/x-git-upload-pack-advertisement"))
			request := NewRequestWithJSON(t, "POST", "/api/v1/users/user2/tokens", api.CreateAccessTokenOption{Name: "auth-compat-child", Scopes: []string{"read:repository"}}).AddBasicAuth(user.Name, master)
			if state.status == 200 {
				child := DecodeJSON(t, MakeRequest(t, request, 201), &api.AccessToken{})
				MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo2").AddTokenAuth(child.Token), 200)
				MakeRequest(t, NewRequest(t, "GET", "/api/v1/user").AddTokenAuth(child.Token), 403)
				MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/users/user2/tokens/"+strconv.FormatInt(child.ID, 10)).AddBasicAuth(user.Name, master), 204)
				MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo2").AddTokenAuth(child.Token), 401)
				MakeRequest(t, NewRequest(t, "GET", "/user2/repo2/info/refs?service=git-upload-pack").AddBasicAuth(user.Name, child.Token), 401)
				unittest.AssertNotExistsBean(t, &auth_model.AccessToken{ID: child.ID})
			} else {
				MakeRequest(t, request, 403)
			}
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/users/user2/tokens", api.CreateAccessTokenOption{Name: "auth-compat-escalation", Scopes: []string{"all"}}).AddBasicAuth(user.Name, master), 403)
			var tokens []auth_model.AccessToken
			require.NoError(t, db.GetEngine(t.Context()).Find(&tokens))
			require.NotEmpty(t, tokens)
			require.Zero(t, calls.Load())
			require.False(t, setting.EnterpriseWeCom.AdminCallbackEnabled)
		})
	}
}

func TestEnterpriseAuthzAuthenticationSyntheticRegression(t *testing.T) {
	authzAuthenticationModes(t, map[string]func(*testing.T){
		"actions_read_write_ceiling": TestActionsJobTokenPermissiveAccess,
		"actions_declared_scopes":    TestActionsJobTokenPermissions,
		"actions_current_task_state": authzActionsCurrentTaskState,
		"actions_cross_repository": func(t *testing.T) {
			testActionsCrossRepoAccess(t, !setting.EnterpriseAuthz.Enforce)
		},
		"deploy_read_only":           TestCreateReadOnlyDeployKey,
		"deploy_write":               TestCreateReadWriteDeployKey,
		"deploy_revoke":              TestCreateDeployToken,
		"deploy_scope_and_read_only": TestDeployTokenGitHTTP,
		"deploy_rotation_revocation": authzDeployCurrentCredential,
	})
}

func authzActionsCurrentTaskState(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	assertNativeCredentialsWithoutOAuth(t)
	task := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
	task.Status = actions_model.StatusRunning
	task.GenerateAndFillToken()
	require.NoError(t, actions_model.UpdateTask(t.Context(), task, "token_hash", "token_salt", "token_last_eight", "status"))
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: task.RepoID})
	request := func(token string, status int) {
		MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/"+repo.FullName()).AddTokenAuth(token), status)
	}
	request(task.Token, 200)
	task.Status = actions_model.StatusCancelling
	require.NoError(t, actions_model.UpdateTask(t.Context(), task, "status"))
	request(task.Token, 200)
	oldToken := task.Token
	task.GenerateAndFillToken()
	require.NoError(t, actions_model.UpdateTask(t.Context(), task, "token_hash", "token_salt", "token_last_eight"))
	request(oldToken, 401)
	request(task.Token, 200)
	task.Status = actions_model.StatusSuccess
	require.NoError(t, actions_model.UpdateTask(t.Context(), task, "status"))
	request(task.Token, 401)
}

func authzDeployCurrentCredential(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&git.DefaultFeatures().SupportProcReceive, false)()
	ownerToken := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
	assertNativeCredentialsWithoutOAuth(t)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	key, err := deploykey_model.AddDeployKeyToken(t.Context(), repo.ID, "auth-compat-current", perm.AccessModeWrite)
	require.NoError(t, err)
	request := func(token, service string, status int) {
		MakeRequest(t, NewRequest(t, "GET", "/"+repo.FullName()+"/info/refs?service="+service).AddBasicAuth("deploy-token", token), status)
	}
	request(key.Token, "git-upload-pack", 200)
	rotated, err := deploykey_model.RegenerateDeployKeyToken(t.Context(), repo.ID, key.ID)
	require.NoError(t, err)
	request(key.Token, "git-upload-pack", 401)
	request(rotated.Token, "git-upload-pack", 200)
	_, err = db.GetEngine(t.Context()).ID(key.ID).Cols("mode").Update(&deploykey_model.DeployKey{Mode: perm.AccessModeRead})
	require.NoError(t, err)
	request(rotated.Token, "git-receive-pack", 404)
	request(rotated.Token, "git-upload-pack", 200)
	MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/"+repo.FullName()+"/keys/"+strconv.FormatInt(key.ID, 10)).AddTokenAuth(ownerToken), 204)
	request(rotated.Token, "git-upload-pack", 401)
}

func assertNativeCredentialsWithoutOAuth(t *testing.T) {
	t.Helper()
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(provider.Close)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, LoginOnly: true, CorpID: "machine-compat", APIBaseURL: provider.URL, OAuthBaseURL: provider.URL}))
	t.Cleanup(func() {
		require.Zero(t, calls.Load())
		require.False(t, setting.EnterpriseWeCom.AdminCallbackEnabled)
	})
}
