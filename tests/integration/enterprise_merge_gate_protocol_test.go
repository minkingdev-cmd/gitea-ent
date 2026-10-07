// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"net/url"
	"path/filepath"
	"testing"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	api "gitea.dev/modules/structs"

	"github.com/stretchr/testify/require"
)

func mergeGateNativeProtocolCompatibility(t *testing.T) {
	for _, ssh := range []bool{false, true} {
		t.Run(map[bool]string{false: "Git_HTTP_token", true: "SSH_key"}[ssh], func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, u *url.URL) {
				repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
				repo.IsPrivate = true
				_, err := db.GetEngine(t.Context()).ID(repo.ID).Cols("is_private").Update(repo)
				require.NoError(t, err)
				require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: repo.ID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["security/direct-push-is-not-a-PR"]}`}))
				run := func(cloneURL, readonly *url.URL, revoke func()) {
					assertNativeCredentialsWithoutOAuth(t)
					work := filepath.Join(t.TempDir(), "protocol")
					doGitClone(work, cloneURL)(t)
					var err error
					_, _, err = gitcmd.NewCommand("fetch", "origin").WithDir(work).RunStdString(t.Context())
					require.NoError(t, err)
					commit := func() {
						_, _, err := gitcmd.NewCommand().AddOptionValues("-c", "user.name=Gate Protocol").AddOptionValues("-c", "user.email=gate@example.invalid").AddArguments("commit", "--allow-empty", "-m", "native protocol parity").WithDir(work).RunStdString(t.Context())
						require.NoError(t, err)
					}
					commit()
					_, _, err = gitcmd.NewCommand("push", "origin", "HEAD:refs/heads/gate-protocol").WithDir(work).RunStdString(t.Context())
					require.NoError(t, err)
					before, err := git.GetFullCommitID(t.Context(), repo, "refs/heads/gate-protocol")
					require.NoError(t, err)
					if readonly != nil {
						_, _, err = gitcmd.NewCommand("fetch").AddDynamicArguments(readonly.String()).WithDir(work).RunStdString(t.Context())
						require.NoError(t, err)
						_, _, err = gitcmd.NewCommand("push").AddDynamicArguments(readonly.String(), "HEAD:refs/heads/readonly-must-not-write").WithDir(work).RunStdString(t.Context())
						require.Error(t, err)
						_, err = git.GetFullCommitID(t.Context(), repo, "refs/heads/readonly-must-not-write")
						require.Error(t, err)
					}
					require.NoError(t, git_model.UpdateProtectBranch(t.Context(), repo, &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "gate-protocol", CanPush: false}, git_model.WhitelistOptions{}))
					commit()
					_, _, err = gitcmd.NewCommand("push", "origin", "HEAD:refs/heads/gate-protocol").WithDir(work).RunStdString(t.Context())
					require.Error(t, err)
					after, err := git.GetFullCommitID(t.Context(), repo, "refs/heads/gate-protocol")
					require.NoError(t, err)
					require.Equal(t, before, after)
					revoke()
					_, _, err = gitcmd.NewCommand("fetch", "origin").WithDir(work).RunStdString(t.Context())
					require.Error(t, err)
					unittest.AssertCount(t, &authz_model.MergeGateEvaluation{}, 0)
				}
				if ssh {
					withKeyFile(t, "gate-protocol-key", func(keyFile string) {
						apiContext := NewAPITestContext(t, "user2", "repo1", auth_model.AccessTokenScopeWriteUser)
						var keyID int64
						doAPICreateUserKey(apiContext, "gate-protocol-key", keyFile, func(_ *testing.T, key api.PublicKey) { keyID = key.ID })(t)
						run(createSSHUrl("user2/repo1.git", u), nil, func() { doAPIDeleteUserKey(apiContext, keyID)(t) })
					})
				} else {
					write := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
					read := getUserToken(t, "user2", auth_model.AccessTokenScopeReadRepository)
					token, err := auth_model.GetAccessTokenBySHA(t.Context(), write)
					require.NoError(t, err)
					cloneURL := u.JoinPath("user2", "repo1.git")
					cloneURL.User = url.UserPassword("user2", write)
					readonly := *cloneURL
					readonly.User = url.UserPassword("user2", read)
					run(cloneURL, &readonly, func() { require.NoError(t, auth_model.DeleteAccessTokenByID(t.Context(), token.ID, 2)) })
				}
			})
		})
	}
}
