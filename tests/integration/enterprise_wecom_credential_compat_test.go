// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"gitea.dev/models/asymkey"
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

type credentialCompatFailedAuthority struct{}

func (credentialCompatFailedAuthority) ListAppAdmins(context.Context) ([]wecom_service.AppAdminInfo, error) {
	return nil, errors.New("access_token=private-provider-token user@example.org")
}

func TestEnterpriseWeComNativeCredentialAccountStateParity(t *testing.T) {
	for _, state := range []struct {
		name                         string
		active, prohibit, restricted bool
		status                       int
	}{
		{name: "normal", active: true, status: http.StatusOK},
		{name: "inactive", status: http.StatusForbidden},
		{name: "prohibit_login", active: true, prohibit: true, status: http.StatusForbidden},
		{name: "restricted", active: true, restricted: true, status: http.StatusOK},
	} {
		t.Run(state.name, func(t *testing.T) {
			defer tests.PrepareTestEnv(t)()
			defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{CorpID: "credential-corp", AgentID: "1000002", LoginOnly: true, AdminCallbackEnabled: true, AdminCallbackToken: "credential-callback-token", AdminCallbackAESKey: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", AdminCallbackReceiverID: "credential-receiver"})()
			user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			master := getUserToken(t, user.Name, auth_model.AccessTokenScopeWriteUser, auth_model.AccessTokenScopeReadRepository)
			narrow := getUserToken(t, user.Name, auth_model.AccessTokenScopeReadUser)
			user.IsActive, user.ProhibitLogin, user.IsRestricted = state.active, state.prohibit, state.restricted
			require.NoError(t, user_model.UpdateUserCols(t.Context(), user, "is_active", "prohibit_login", "is_restricted"))
			var baseline []int
			for _, enterprise := range []bool{false, true} {
				setting.EnterpriseWeCom.Enabled = enterprise
				mode := "baseline"
				if enterprise {
					mode = "enterprise"
				}
				reads := []*RequestWrapper{
					NewRequest(t, http.MethodGet, "/api/v1/user").AddTokenAuth(master),
					NewRequest(t, http.MethodGet, "/api/v1/repos/user2/repo2").AddTokenAuth(master),
					NewRequest(t, http.MethodGet, "/user2/repo2/info/refs?service=git-upload-pack").AddBasicAuth(user.Name, master),
					NewRequest(t, http.MethodGet, "/api/v1/repos/user2/repo2").AddTokenAuth(narrow),
					NewRequest(t, http.MethodGet, "/user2/repo2/info/refs?service=git-upload-pack").AddBasicAuth(user.Name, narrow),
				}
				statuses := make([]int, 0, 8)
				for i, req := range reads {
					resp := MakeRequest(t, req, NoExpectedStatus)
					statuses = append(statuses, resp.Code)
					if i < 2 {
						require.Equal(t, state.status, resp.Code, mode)
					} else if i == 2 {
						require.Equal(t, http.StatusOK, resp.Code, mode)
						require.Equal(t, state.status == http.StatusOK, strings.Contains(resp.Header().Get("Content-Type"), "application/x-git-upload-pack-advertisement"), mode)
					} else if i == 3 || state.status == http.StatusOK {
						require.Equal(t, http.StatusForbidden, resp.Code, mode)
					} else {
						require.Equal(t, http.StatusOK, resp.Code, mode)
						require.Contains(t, resp.Header().Get("Content-Type"), "text/html")
					}
					if i == 1 && resp.Code == http.StatusOK {
						repo := DecodeJSON(t, resp, &api.Repository{})
						require.EqualValues(t, 2, repo.ID)
						require.True(t, repo.Private)
					}
					if i == 2 && state.status == http.StatusOK {
						require.Contains(t, resp.Header().Get("Content-Type"), "application/x-git-upload-pack-advertisement")
					}
				}
				create := MakeRequest(t, NewRequestWithJSON(t, http.MethodPost, "/api/v1/users/user2/tokens", api.CreateAccessTokenOption{Name: "credential-child-" + mode, Scopes: []string{"read:repository"}}).AddBasicAuth(user.Name, master), NoExpectedStatus)
				statuses = append(statuses, create.Code)
				escalation := MakeRequest(t, NewRequestWithJSON(t, http.MethodPost, "/api/v1/users/user2/tokens", api.CreateAccessTokenOption{Name: "credential-escalation-" + mode, Scopes: []string{"all"}}).AddBasicAuth(user.Name, master), http.StatusForbidden)
				statuses = append(statuses, escalation.Code)
				revocable := &auth_model.AccessToken{UID: user.ID, Name: "credential-revocable-" + mode, Scope: auth_model.AccessTokenScopeReadRepository}
				require.NoError(t, auth_model.NewAccessToken(t.Context(), revocable))
				MakeRequest(t, NewRequest(t, http.MethodGet, "/api/v1/repos/user2/repo2").AddTokenAuth(revocable.Token), state.status)
				gitBeforeRevoke := MakeRequest(t, NewRequest(t, http.MethodGet, "/user2/repo2/info/refs?service=git-upload-pack").AddBasicAuth(user.Name, revocable.Token), http.StatusOK)
				require.Equal(t, state.status == http.StatusOK, strings.Contains(gitBeforeRevoke.Header().Get("Content-Type"), "application/x-git-upload-pack-advertisement"))
				revoke := MakeRequest(t, NewRequest(t, http.MethodDelete, "/api/v1/users/user2/tokens/"+strconv.FormatInt(revocable.ID, 10)).AddBasicAuth(user.Name, master), NoExpectedStatus)
				statuses = append(statuses, revoke.Code)
				if state.status == http.StatusOK {
					require.Equal(t, http.StatusCreated, create.Code)
					child := DecodeJSON(t, create, &api.AccessToken{})
					require.Equal(t, []string{"read:repository"}, child.Scopes)
					MakeRequest(t, NewRequest(t, http.MethodGet, "/api/v1/repos/user2/repo2").AddTokenAuth(child.Token), http.StatusOK)
					MakeRequest(t, NewRequest(t, http.MethodGet, "/api/v1/user").AddTokenAuth(child.Token), http.StatusForbidden)
					MakeRequest(t, NewRequest(t, http.MethodDelete, "/api/v1/users/user2/tokens/"+strconv.FormatInt(child.ID, 10)).AddBasicAuth(user.Name, master), http.StatusNoContent)
					require.Equal(t, http.StatusNoContent, revoke.Code)
					MakeRequest(t, NewRequest(t, http.MethodGet, "/api/v1/repos/user2/repo2").AddTokenAuth(revocable.Token), http.StatusUnauthorized)
					MakeRequest(t, NewRequest(t, http.MethodGet, "/user2/repo2/info/refs?service=git-upload-pack").AddBasicAuth(user.Name, revocable.Token), http.StatusUnauthorized)
					unittest.AssertNotExistsBean(t, &auth_model.AccessToken{ID: revocable.ID})
				} else {
					require.Equal(t, http.StatusForbidden, create.Code)
					require.Equal(t, http.StatusForbidden, revoke.Code)
					unittest.AssertExistsAndLoadBean(t, &auth_model.AccessToken{ID: revocable.ID})
				}
				if !enterprise {
					baseline = statuses
				} else {
					require.Equal(t, baseline, statuses)
				}
			}
			var tokensBefore, tokensAfter []auth_model.AccessToken
			var keysBefore, keysAfter []asymkey.PublicKey
			require.NoError(t, db.GetEngine(t.Context()).OrderBy("id").Find(&tokensBefore))
			require.NoError(t, db.GetEngine(t.Context()).OrderBy("id").Find(&keysBefore))
			require.NotEmpty(t, tokensBefore)
			require.NotEmpty(t, keysBefore)
			now := time.Now().Unix()
			event := `<xml><AuthCorpId>credential-corp</AuthCorpId><AgentID>1000002</AgentID><InfoType>change_app_admin</InfoType><TimeStamp>` + strconv.FormatInt(now, 10) + `</TimeStamp><NewAdminUserID>untrusted-admin</NewAdminUserID></xml>`
			query, encrypted := encryptedAdminCallbackRequest(t, event, "1234567890123456", now)
			receipt := MakeRequest(t, NewRequestWithBody(t, http.MethodPost, "/enterprise/wecom/callback/admin-authority?"+query, strings.NewReader(`<xml><Encrypt>`+encrypted+`</Encrypt></xml>`)), http.StatusOK)
			require.Equal(t, "success", receipt.Body.String())
			require.Empty(t, receipt.Header().Values("Set-Cookie"))
			_, err := wecom_service.RefreshAdminAuthoritySnapshot(t.Context(), credentialCompatFailedAuthority{}, wecom_service.AdminAuthorityRefreshOptions{RunID: "credential-failed-" + state.name, Trigger: "callback"})
			require.Error(t, err)
			require.NotContains(t, err.Error(), "private-provider-token")
			run := unittest.AssertExistsAndLoadBean(t, &wecom_model.ReconcileRun{RunID: "credential-failed-" + state.name})
			require.Equal(t, wecom_model.ReconcileRunStatusFailed, run.Status)
			require.NoError(t, db.GetEngine(t.Context()).OrderBy("id").Find(&tokensAfter))
			require.NoError(t, db.GetEngine(t.Context()).OrderBy("id").Find(&keysAfter))
			require.Equal(t, tokensBefore, tokensAfter)
			require.Equal(t, keysBefore, keysAfter)
		})
	}
}
