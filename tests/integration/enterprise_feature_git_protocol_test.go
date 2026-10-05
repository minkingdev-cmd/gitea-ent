// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func useEnterpriseFeatureGitTestBinary(t *testing.T, repo *repo_model.Repository) {
	t.Helper()
	binary := os.Getenv("GITEA_TEST_FEATURE_BINARY")
	require.NotEmpty(t, binary, "GITEA_TEST_FEATURE_BINARY must point to a freshly built test Gitea binary")
	binary, err := filepath.Abs(binary)
	require.NoError(t, err)
	info, err := os.Stat(binary)
	require.NoError(t, err)
	require.False(t, info.IsDir())
	t.Cleanup(test.MockVariableValue(&setting.AppPath, binary))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	t.Setenv("GITEA__enterprise_0x2E_authz__ENABLED", "true")
	t.Setenv("GITEA__enterprise_0x2E_authz__ENFORCE", "true")
	t.Setenv("GITEA__enterprise_0x2E_authz__FAIL_CLOSED_ON_ERROR", "true")
	t.Setenv("GITEA__audit__RECORD_OUTPUT", "database")
	require.NoError(t, git.CreateDelegateHooks(t.Context(), repo))
	require.NoError(t, git.CreateDelegateHooks(t.Context(), repo.WikiStorageRepo()))
}

func createEnterpriseFeatureGitCommit(t *testing.T, local string) {
	t.Helper()
	_, _, err := gitcmd.NewCommand("fast-import").WithDir(local).WithStdinBytes([]byte(`commit refs/heads/master
committer feature-test <user2@example.com> 1714310400 +0000
data <<EOM
feature protocol verification
EOM
from refs/heads/master^0
M 100644 inline feature-test.txt
data <<EOM
feature protocol content
EOM
`)).RunStdString(t.Context())
	require.NoError(t, err)
}

func TestEnterpriseFeatureAGitActualPush(t *testing.T) {
	require.True(t, git.DefaultFeatures().SupportProcReceive)
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		useEnterpriseFeatureGitTestBinary(t, repo)
		remote := *u
		remote.Path, remote.User = "/user2/repo1.git", url.UserPassword("user2", userPassword)
		local := t.TempDir()
		require.NoError(t, git.Clone(t.Context(), remote.String(), local, git.CloneRepoOptions{}))
		createEnterpriseFeatureGitCommit(t, local)
		require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePullRequests, ScopeType: authz_model.ScopeRepo, ScopeID: repo.ID, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
		_, _, pushErr := gitcmd.NewCommand("push", "origin", "refs/heads/master:refs/heads/feature-code-allowed").WithDir(local).RunStdString(t.Context())
		require.NoError(t, pushErr)
		localRepo, err := git.OpenRepositoryLocal(t.Context(), local)
		require.NoError(t, err)
		defer localRepo.Close()
		localCommit, err := localRepo.GetRefCommitID(t.Context(), "refs/heads/master")
		require.NoError(t, err)
		remoteCommit, err := git.GetFullCommitID(t.Context(), repo, "refs/heads/feature-code-allowed")
		require.NoError(t, err)
		require.Equal(t, localCommit, remoteCommit)
		count := unittest.GetCount(t, &issues_model.PullRequest{})
		_, _, pushErr = gitcmd.NewCommand("push", "origin", "refs/heads/master:refs/for/master", "-o", "topic=feature-denied").WithDir(local).RunStdString(t.Context())
		require.Error(t, pushErr)
		unittest.AssertCount(t, &issues_model.PullRequest{}, count)
		unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseFeatureDecision}, unittest.Cond("metadata LIKE ? AND metadata LIKE ?", `%"feature_key":"feature.pull_requests"%`, `%"actual_decision":"deny"%`))
	})
}

func TestEnterpriseFeatureWikiActualGitTransports(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		useEnterpriseFeatureGitTestBinary(t, repo)
		before, err := git.GetFullCommitID(t.Context(), repo.WikiStorageRepo(), "refs/heads/master")
		require.NoError(t, err)
		httpWiki := *u
		httpWiki.Path, httpWiki.User = "/user2/repo1.wiki.git", url.UserPassword("user2", userPassword)
		sshWiki := createSSHUrl("/user2/repo1.wiki.git", u)
		withKeyFile(t, "feature-wiki-key", func(keyFile string) {
			apiContext := NewAPITestContext(t, "user2", "repo1", auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteUser)
			doAPICreateUserKey(apiContext, "feature-wiki-key", keyFile)(t)
			remotes := []*url.URL{&httpWiki, sshWiki}
			locals := make([]string, len(remotes))
			for i, remote := range remotes {
				locals[i] = t.TempDir()
				require.NoError(t, git.Clone(t.Context(), remote.String(), locals[i], git.CloneRepoOptions{}))
				createEnterpriseFeatureGitCommit(t, locals[i])
			}
			require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureWiki, ScopeType: authz_model.ScopeRepo, ScopeID: repo.ID, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
			for i, remote := range remotes {
				require.Error(t, git.Clone(t.Context(), remote.String(), t.TempDir(), git.CloneRepoOptions{}))
				_, _, err := gitcmd.NewCommand("push", "origin", "refs/heads/master").WithDir(locals[i]).RunStdString(t.Context())
				require.Error(t, err)
				code := *remote
				code.Path = "/user2/repo1.git"
				ordinary := t.TempDir()
				require.NoError(t, git.Clone(t.Context(), code.String(), ordinary, git.CloneRepoOptions{}))
				createEnterpriseFeatureGitCommit(t, ordinary)
				branch := []string{"refs/heads/feature-wiki-http-code", "refs/heads/feature-wiki-ssh-code"}[i]
				_, _, err = gitcmd.NewCommand("push", "origin").AddDynamicArguments("refs/heads/master:" + branch).WithDir(ordinary).RunStdString(t.Context())
				require.NoError(t, err)
			}
			after, err := git.GetFullCommitID(t.Context(), repo.WikiStorageRepo(), "refs/heads/master")
			require.NoError(t, err)
			require.Equal(t, before, after)
			unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseFeatureDecision}, unittest.Cond("metadata LIKE ? AND metadata LIKE ?", `%"feature_key":"feature.wiki"%`, `%"actual_decision":"deny"%`))
		})
	})
}
