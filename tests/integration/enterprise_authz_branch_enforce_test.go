// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/git/gitrepo"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzBranchDeleteBeforeAnyMutation(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	enableLifecycleEnforcement(t)
	repo, gitRepo, old := controlledBranchFixture(t)
	session := loginUser(t, "user4")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	session.MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/branches/controlled").AddTokenAuth(token), 403)
	current, err := gitRepo.GetBranchCommitID(t.Context(), "controlled")
	require.NoError(t, err)
	require.Equal(t, old, current)
	unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: repo.ID, Name: "controlled", IsDeleted: false})
}

func controlledBranchFixture(t *testing.T) (*repo_model.Repository, *git.Repository, string) {
	t.Helper()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	require.NoError(t, repo.LoadOwner(t.Context()))
	work := filepath.Join(t.TempDir(), "branch-fixture")
	require.NoError(t, gitcmd.NewCommand("clone").AddDynamicArguments(gitrepo.RepoLocalPath(repo), work).RunWithStderr(t.Context()))
	for _, args := range [][]string{{"config", "user.name", "Fixture"}, {"config", "user.email", "fixture@example.com"}} {
		require.NoError(t, gitcmd.NewCommand("config").AddDynamicArguments(args[1:]...).WithDir(work).RunWithStderr(t.Context()))
	}
	require.NoError(t, os.WriteFile(filepath.Join(work, "CODEOWNERS"), []byte("* @user2\n"), 0o600))
	require.NoError(t, gitcmd.NewCommand("add", "CODEOWNERS").WithDir(work).RunWithStderr(t.Context()))
	require.NoError(t, gitcmd.NewCommand("commit", "-m", "controlled fixture").WithDir(work).RunWithStderr(t.Context()))
	require.NoError(t, gitcmd.NewCommand("fetch").AddDynamicArguments(work, "HEAD:refs/heads/controlled").WithRepo(repo).RunWithStderr(t.Context()))
	gitRepo, err := git.OpenRepository(t.Context(), repo)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, gitRepo.Close()) })
	old, err := gitRepo.GetBranchCommitID(t.Context(), "controlled")
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &git_model.Branch{RepoID: repo.ID, Name: "controlled", CommitID: old}, &repo_model.Collaboration{RepoID: repo.ID, UserID: 4, Mode: perm.AccessModeWrite}, &access_model.Access{RepoID: repo.ID, UserID: 4, Mode: perm.AccessModeWrite}))
	return repo, gitRepo, old
}

func TestEnterpriseAuthzBranchWebDenialStatus(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	enableLifecycleEnforcement(t)
	_, gitRepo, old := controlledBranchFixture(t)
	session := loginUser(t, "user4")
	for _, request := range []struct {
		path   string
		values map[string]string
	}{
		{"/user2/repo1/branches/_new/branch/controlled", map[string]string{"new_branch_name": "created-controlled"}},
		{"/user2/repo1/branches/rename", map[string]string{"from": "controlled", "to": "renamed"}},
		{"/user2/repo1/branches/delete", map[string]string{"name": "controlled"}},
	} {
		session.MakeRequest(t, NewRequestWithValues(t, "POST", request.path, request.values), 403)
	}
	current, err := gitRepo.GetBranchCommitID(t.Context(), "controlled")
	require.NoError(t, err)
	require.Equal(t, old, current)
	require.False(t, gitRepo.IsBranchExist(t.Context(), "renamed"))
	require.False(t, gitRepo.IsBranchExist(t.Context(), "created-controlled"))
}

func TestEnterpriseAuthzBranchRestoreDenialStatus(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	enableLifecycleEnforcement(t)
	repo, gitRepo, _ := controlledBranchFixture(t)
	require.NoError(t, git.DeleteBranch(t.Context(), repo, "controlled", true))
	require.NoError(t, git_model.MarkBranchAsDeleted(t.Context(), repo.ID, "controlled", 2))
	branch := unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: repo.ID, Name: "controlled", IsDeleted: true})
	session := loginUser(t, "user4")
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/branches/restore", map[string]string{"branch_id": strconv.FormatInt(branch.ID, 10)}), 403)
	require.False(t, gitRepo.IsBranchExist(t.Context(), "controlled"))
	unittest.AssertExistsAndLoadBean(t, &git_model.Branch{ID: branch.ID, IsDeleted: true})
}

func TestEnterpriseAuthzForkSyncControlledBranch(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	ownerSession := loginUser(t, "user5")
	ownerToken := getTokenForLoggedInUser(t, ownerSession, auth_model.AccessTokenScopeWriteRepository)
	ownerSession.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/forks", api.CreateForkOption{Name: new("authz-controlled-fork")}).AddTokenAuth(ownerToken), 202)
	fork := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: 5, Name: "authz-controlled-fork"})
	require.NoError(t, fork.LoadOwner(t.Context()))
	enableLifecycleEnforcement(t)
	base, baseGit, commit := controlledBranchFixture(t)
	require.NoError(t, gitcmd.NewCommand("update-ref", "refs/heads/master").AddDynamicArguments(commit).WithRepo(base).Run(t.Context()))
	baseCommit, err := baseGit.GetCommit(t.Context(), commit)
	require.NoError(t, err)
	_, err = git_model.UpdateBranch(t.Context(), base.ID, 2, "master", baseCommit)
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: fork.ID, UserID: 4, Mode: perm.AccessModeWrite}, &access_model.Access{RepoID: fork.ID, UserID: 4, Mode: perm.AccessModeWrite}))
	forkGit, err := git.OpenRepository(t.Context(), fork)
	require.NoError(t, err)
	defer forkGit.Close()
	old, err := forkGit.GetBranchCommitID(t.Context(), "master")
	require.NoError(t, err)
	session := loginUser(t, "user4")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user5/authz-controlled-fork/merge-upstream", api.MergeUpstreamRequest{Branch: "master", FfOnly: true}).AddTokenAuth(token), 403)
	current, err := forkGit.GetBranchCommitID(t.Context(), "master")
	require.NoError(t, err)
	require.Equal(t, old, current)
}

func TestEnterpriseAuthzBranchAPICompoundExecution(t *testing.T) {
	onGiteaRun(t, func(_ *testing.T, _ *url.URL) {
		enableLifecycleEnforcement(t)
		repo, gitRepo, old := controlledBranchFixture(t)
		session := loginUser(t, "user4")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		path := "/api/v1/repos/user2/repo1/branches"
		create := func(status int) {
			session.MakeRequest(t, NewRequestWithJSON(t, "POST", path, api.CreateBranchRepoOption{BranchName: "copy-controlled", OldRefName: "controlled"}).AddTokenAuth(token), status)
		}
		create(403)
		session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", path+"/controlled", api.RenameBranchRepoOption{Name: "renamed"}).AddTokenAuth(token), 403)
		session.MakeRequest(t, NewRequestWithJSON(t, "PUT", path+"/controlled", api.UpdateBranchRepoOption{NewCommitID: "master", OldCommitID: old, Force: true}).AddTokenAuth(token), 403)
		binding := lifecycleRole(t, repo, 4, authz.ManageCodeowners)
		rule := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "copy-controlled", CanPush: true}
		require.NoError(t, db.Insert(t.Context(), rule))
		create(403)
		require.False(t, gitRepo.IsBranchExist(t.Context(), "copy-controlled"))
		_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
		require.NoError(t, err)
		require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: binding.RoleID, Action: authz.PushProtectedBranch, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
		create(201)
		session.MakeRequest(t, NewRequestWithJSON(t, "PUT", path+"/controlled", api.UpdateBranchRepoOption{NewCommitID: "master", OldCommitID: old, Force: true}).AddTokenAuth(token), 204)
		session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", path+"/copy-controlled", api.RenameBranchRepoOption{Name: "renamed"}).AddTokenAuth(token), 403)
		session.MakeRequest(t, NewRequest(t, "DELETE", path+"/copy-controlled").AddTokenAuth(token), 403)
		_, err = db.DeleteByID[git_model.ProtectedBranch](t.Context(), rule.ID)
		require.NoError(t, err)
		session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", path+"/copy-controlled", api.RenameBranchRepoOption{Name: "renamed"}).AddTokenAuth(token), 204)
		session.MakeRequest(t, NewRequest(t, "DELETE", path+"/renamed").AddTokenAuth(token), 204)
		require.False(t, gitRepo.IsBranchExist(t.Context(), "renamed"))
		rows := make([]*authz_model.DecisionRecord, 0)
		require.NoError(t, db.GetEngine(t.Context()).Where("repo_id = ? AND decision_mode = ? AND authorization_decision = ?", repo.ID, "enforce", "allow").Find(&rows))
		require.NotEmpty(t, rows)
		for _, row := range rows {
			require.True(t, row.ExecutionStarted)
			require.Equal(t, "success", row.NativeOutcome)
		}
	})
}

func TestEnterpriseAuthzBranchInitializationHTTP(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	enableLifecycleEnforcement(t)
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
	session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", api.CreateRepoOption{Name: "authz-initial-readme", AutoInit: true, Readme: "Default", DefaultBranch: "main"}).AddTokenAuth(token), 201)
	created := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: 3, Name: "authz-initial-readme"})
	require.Equal(t, "main", created.DefaultBranch)
	require.False(t, created.IsEmpty)
	require.True(t, git.IsBranchExist(t.Context(), created, "main"))
	initialEvent := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{ScopeID: created.ID, Origin: audit_model.OriginSystem, Action: audit_model.RepositoryCreate})
	require.NotEqual(t, int64(2), initialEvent.ActorID)
	require.Contains(t, initialEvent.Metadata, "repository-initial-git-create")
	base, _, _ := controlledBranchFixture(t)
	base.DefaultBranch, base.IsTemplate = "controlled", true
	require.NoError(t, repo_model.UpdateRepositoryColsNoAutoTime(t.Context(), base, "default_branch", "is_template"))
	session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/generate", api.GenerateRepoOption{Owner: "org3", Name: "authz-initial-codeowners", GitContent: true}).AddTokenAuth(token), 201)
	generated := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: 3, Name: "authz-initial-codeowners"})
	require.Equal(t, "controlled", generated.DefaultBranch)
	require.False(t, generated.IsEmpty)
	generatedGit, err := git.OpenRepository(t.Context(), generated)
	require.NoError(t, err)
	defer generatedGit.Close()
	commit, err := generatedGit.GetBranchCommit(t.Context(), generated.DefaultBranch)
	require.NoError(t, err)
	_, err = commit.GetTreeEntryByPath(t.Context(), generatedGit, "CODEOWNERS")
	require.NoError(t, err)
	initialEvent = unittest.AssertExistsAndLoadBean(t, &audit_model.Event{ScopeID: generated.ID, Origin: audit_model.OriginSystem, Action: audit_model.RepositoryCreate})
	require.NotEqual(t, int64(2), initialEvent.ActorID)
	require.Contains(t, initialEvent.Metadata, "repository-initial-git-generate")
	unittest.AssertNotExistsBean(t, &authz_model.DecisionRecord{RepoID: generated.ID})
}

func TestEnterpriseAuthzBranchInitializationAuditFailureHTTP(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	enableLifecycleEnforcement(t)
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization)
	base := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	base.IsTemplate = true
	require.NoError(t, repo_model.UpdateRepositoryColsNoAutoTime(t.Context(), base, "is_template"))
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDisabled)()
	for _, route := range []string{"api-create", "api-generate", "web-create", "web-generate"} {
		t.Run(route, func(t *testing.T) {
			name := "authz-no-audit-" + route
			switch route {
			case "api-create":
				session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/repos", api.CreateRepoOption{Name: name, AutoInit: true, Readme: "Default", DefaultBranch: "main"}).AddTokenAuth(token), 503)
			case "api-generate":
				session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/generate", api.GenerateRepoOption{Owner: "org3", Name: name, GitContent: true}).AddTokenAuth(token), 503)
			case "web-create":
				session.MakeRequest(t, NewRequestWithValues(t, "POST", "/repo/create", map[string]string{"uid": "3", "repo_name": name, "auto_init": "true", "readme": "Default", "default_branch": "main"}), 503)
			case "web-generate":
				session.MakeRequest(t, NewRequestWithValues(t, "POST", "/repo/create", map[string]string{"uid": "3", "repo_name": name, "repo_template": "1", "git_content": "true"}), 503)
			}
			unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: 3, Name: name})
			_, err := os.Stat(gitrepo.RepoLocalPath(&repo_model.Repository{OwnerName: "org3", Name: name, LowerName: name}))
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestEnterpriseAuthzBranchEnforcementEvidenceFailure(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	enableLifecycleEnforcement(t)
	repo, gitRepo, old := controlledBranchFixture(t)
	lifecycleRole(t, repo, 4, authz.ManageCodeowners)
	session := loginUser(t, "user4")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	for _, table := range []string{"enterprise_authz_decision", "audit_event"} {
		t.Run(table, func(t *testing.T) {
			_, err := db.Exec(t.Context(), "ALTER TABLE "+table+" RENAME TO authz_branch_execution_fault")
			require.NoError(t, err)
			defer func() {
				_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE authz_branch_execution_fault RENAME TO "+table)
				require.NoError(t, err)
			}()
			session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branches", api.CreateBranchRepoOption{BranchName: "evidence-failed", OldBranchName: "controlled"}).AddTokenAuth(token), 503)
			require.False(t, gitRepo.IsBranchExist(t.Context(), "evidence-failed"))
			unittest.AssertNotExistsBean(t, &git_model.Branch{RepoID: repo.ID, Name: "evidence-failed"})
			current, err := gitRepo.GetBranchCommitID(t.Context(), "controlled")
			require.NoError(t, err)
			require.Equal(t, old, current)
		})
	}
}
