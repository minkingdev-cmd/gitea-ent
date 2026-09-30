// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"bytes"
	"net"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"gitea.dev/models/asymkey"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
)

func TestEnterpriseWeComNativeSSHAccountStateParity(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{LoginOnly: true, CorpID: "ssh-compat-corp", AgentID: "1000002"})()
		ctx := NewAPITestContext(t, "user2", "repo1", auth_model.AccessTokenScopeWriteUser)
		user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		original := *user
		defer func() {
			require.NoError(t, user_model.UpdateUserCols(t.Context(), &original, "is_active", "prohibit_login", "is_restricted"))
		}()

		const keyName = "wecom-ssh-account-parity"
		withKeyFile(t, keyName, func(keyFile string) {
			var keyID int64
			doAPICreateUserKey(ctx, keyName, keyFile, func(t *testing.T, key api.PublicKey) { keyID = key.ID })(t)
			require.Positive(t, keyID)
			privateKey, err := os.ReadFile(keyFile)
			require.NoError(t, err)
			signer, err := gossh.ParsePrivateKey(privateKey)
			require.NoError(t, err)
			address := net.JoinHostPort(setting.SSH.ListenHost, strconv.Itoa(setting.SSH.ListenPort))
			sshConfig := &gossh.ClientConfig{
				User: setting.SSH.BuiltinServerUser, Auth: []gossh.AuthMethod{gossh.PublicKeys(signer)},
				HostKeyCallback: gossh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
			}
			shell := func(t *testing.T, allowed bool) string {
				t.Helper()
				client, err := gossh.Dial("tcp", address, sshConfig)
				require.NoError(t, err)
				defer client.Close()
				session, err := client.NewSession()
				require.NoError(t, err)
				defer session.Close()
				var stderr bytes.Buffer
				session.Stderr = &stderr
				require.NoError(t, session.Shell())
				err = session.Wait()
				if allowed {
					require.NoError(t, err)
					require.Contains(t, stderr.String(), "You've successfully authenticated with the SSH key named "+keyName+".")
				} else {
					var exit *gossh.ExitError
					require.ErrorAs(t, err, &exit)
					require.Equal(t, 1, exit.ExitStatus())
					require.Contains(t, stderr.String(), "Key check failed")
					require.NotContains(t, stderr.String(), "You've successfully authenticated")
				}
				return stderr.String()
			}
			for _, state := range []struct {
				name                                  string
				active, prohibit, restricted, allowed bool
			}{
				{name: "normal", active: true, allowed: true},
				{name: "inactive"},
				{name: "prohibit_login", active: true, prohibit: true},
				{name: "restricted", active: true, restricted: true, allowed: true},
			} {
				t.Run(state.name, func(t *testing.T) {
					user.IsActive, user.ProhibitLogin, user.IsRestricted = state.active, state.prohibit, state.restricted
					require.NoError(t, user_model.UpdateUserCols(t.Context(), user, "is_active", "prohibit_login", "is_restricted"))
					setting.EnterpriseWeCom.Enabled = false
					baseline := shell(t, state.allowed)
					setting.EnterpriseWeCom.Enabled = true
					enterprise := shell(t, state.allowed)
					require.Equal(t, baseline, enterprise)
				})
			}

			user.IsActive, user.ProhibitLogin, user.IsRestricted = true, false, false
			require.NoError(t, user_model.UpdateUserCols(t.Context(), user, "is_active", "prohibit_login", "is_restricted"))
			shell(t, true)
			doAPIDeleteUserKey(ctx, keyID)(t)
			unittest.AssertNotExistsBean(t, &asymkey.PublicKey{ID: keyID})
			for _, enterprise := range []bool{false, true} {
				setting.EnterpriseWeCom.Enabled = enterprise
				client, err := gossh.Dial("tcp", address, sshConfig)
				if client != nil {
					_ = client.Close()
				}
				require.ErrorContains(t, err, "unable to authenticate")
			}
		})
	})
}
