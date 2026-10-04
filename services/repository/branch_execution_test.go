// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitrepo"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/audit"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func branchExecutionFixture(ctx context.Context, t *testing.T) (*repo_model.Repository, *user_model.User, *git.Repository, string) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.RepoRootPath, t.TempDir()))
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	require.NoError(t, repo.LoadOwner(ctx))
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	require.NoError(t, db.Insert(ctx, &repo_model.Collaboration{RepoID: repo.ID, UserID: actor.ID, Mode: perm.AccessModeWrite}, &access_model.Access{RepoID: repo.ID, UserID: actor.ID, Mode: perm.AccessModeWrite}))
	dir := gitrepo.RepoLocalPath(repo)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	command := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = dir
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, string(output))
		return strings.TrimSpace(string(output))
	}
	command("init", "--initial-branch=master")
	command("config", "user.name", "Fixture")
	command("config", "user.email", "fixture@example.com")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "CODEOWNERS"), []byte("* @user2\n"), 0o600))
	command("add", "CODEOWNERS")
	command("commit", "-m", "controlled fixture")
	commit := command("rev-parse", "HEAD")
	command("branch", "controlled")
	require.NoError(t, db.Insert(ctx, &git_model.Branch{RepoID: repo.ID, Name: "controlled", CommitID: commit}))
	gitRepo, err := git.OpenRepository(ctx, repo)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, gitRepo.Close()) })
	return repo, actor, gitRepo, commit
}

func TestBranchRenameRequiresCodeownersAdmission(t *testing.T) {
	ctx := enforceLifecycle(t)
	repo, actor, gitRepo, old := branchExecutionFixture(ctx, t)
	ctx = audit.WithDoer(ctx, actor)
	_, err := RenameBranch(ctx, repo, actor, "controlled", "renamed")
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, 403, rejection.Status)
	current, err := gitRepo.GetBranchCommitID(ctx, "controlled")
	require.NoError(t, err)
	require.Equal(t, old, current)
	require.False(t, gitRepo.IsBranchExist(ctx, "renamed"))
	unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: repo.ID, Name: "controlled", IsDeleted: false})
	unittest.AssertNotExistsBean(t, &git_model.RenamedBranch{RepoID: repo.ID, From: "controlled"})
	row := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repo.ID, Action: authz.ManageCodeowners})
	require.False(t, row.ExecutionStarted)
}

func TestBranchCreateRequiresCodeownersAdmission(t *testing.T) {
	ctx := enforceLifecycle(t)
	repo, actor, gitRepo, commit := branchExecutionFixture(ctx, t)
	ctx = audit.WithDoer(ctx, actor)
	err := CreateNewBranchFromCommit(ctx, actor, repo, gitRepo, commit, "created-controlled")
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, 403, rejection.Status)
	require.False(t, gitRepo.IsBranchExist(ctx, "created-controlled"))
	unittest.AssertNotExistsBean(t, &git_model.Branch{RepoID: repo.ID, Name: "created-controlled"})
}

func TestBranchUpdateRequiresCodeownersAdmission(t *testing.T) {
	ctx := enforceLifecycle(t)
	repo, actor, gitRepo, old := branchExecutionFixture(ctx, t)
	ctx = audit.WithDoer(ctx, actor)
	dir := gitrepo.RepoLocalPath(repo)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "CODEOWNERS"), []byte("* @user4\n"), 0o600))
	for _, args := range [][]string{{"add", "CODEOWNERS"}, {"commit", "-m", "changed controlled file"}} {
		cmd := exec.CommandContext(ctx, "git", args...)
		cmd.Dir = dir
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, string(output))
	}
	newCommit, err := gitRepo.GetBranchCommitID(ctx, "master")
	require.NoError(t, err)
	err = UpdateBranch(ctx, repo, gitRepo, actor, "controlled", newCommit, old, false)
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, 403, rejection.Status)
	current, err := gitRepo.GetBranchCommitID(ctx, "controlled")
	require.NoError(t, err)
	require.Equal(t, old, current)
}

func TestBranchRenameLeaseAndMetadata(t *testing.T) {
	for _, mutation := range []string{"source", "target", "metadata", "no-reflog"} {
		t.Run(mutation, func(t *testing.T) {
			ctx := enforceLifecycle(t)
			repo, _, gitRepo, old := branchExecutionFixture(ctx, t)
			dir := gitrepo.RepoLocalPath(repo)
			command := func(args ...string) string {
				t.Helper()
				cmd := exec.CommandContext(ctx, "git", args...)
				cmd.Dir = dir
				output, err := cmd.CombinedOutput()
				require.NoError(t, err, string(output))
				return strings.TrimSpace(string(output))
			}
			rename := func() error {
				return git_model.RenameBranch(ctx, repo, "controlled", "renamed", func(ctx context.Context, _ bool) error {
					return renameBranchWithLease(ctx, repo, "controlled", "renamed", old)
				})
			}
			if mutation == "source" {
				command("commit", "--allow-empty", "-m", "concurrent update")
				command("branch", "-f", "controlled", "master")
				current := command("rev-parse", "controlled")
				require.Error(t, rename())
				require.Equal(t, current, command("rev-parse", "controlled"))
				require.False(t, gitRepo.IsBranchExist(ctx, "renamed"))
				unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: repo.ID, Name: "controlled", CommitID: old})
				unittest.AssertNotExistsBean(t, &git_model.Branch{RepoID: repo.ID, Name: "renamed"})
				return
			}
			if mutation == "target" {
				command("branch", "renamed")
				require.Error(t, rename())
				require.Equal(t, old, command("rev-parse", "controlled"))
				require.Equal(t, old, command("rev-parse", "renamed"))
				unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: repo.ID, Name: "controlled", CommitID: old})
				unittest.AssertNotExistsBean(t, &git_model.Branch{RepoID: repo.ID, Name: "renamed"})
				return
			}
			if mutation == "no-reflog" {
				command("config", "core.logAllRefUpdates", "false")
				logs := command("rev-parse", "--git-path", "logs")
				if !filepath.IsAbs(logs) {
					logs = filepath.Join(dir, logs)
				}
				require.NoError(t, os.RemoveAll(logs))
				require.NoError(t, rename())
				_, err := os.Stat(filepath.Join(logs, "refs", "heads", "renamed"))
				require.ErrorIs(t, err, os.ErrNotExist)
				return
			}
			command("config", "branch.controlled.remote", "origin")
			command("symbolic-ref", "HEAD", "refs/heads/controlled")
			logBefore := command("reflog", "show", "--format=%gs", "controlled")
			require.NoError(t, rename())
			require.Equal(t, "origin", command("config", "branch.renamed.remote"))
			require.Contains(t, command("reflog", "show", "--format=%gs", "renamed"), logBefore)
			require.Equal(t, old, command("rev-parse", "renamed"))
			require.Equal(t, "refs/heads/renamed", command("symbolic-ref", "HEAD"))
			require.False(t, gitRepo.IsBranchExist(ctx, "controlled"))
		})
	}
}

func TestBranchRenameCustomRoleAndNativeGate(t *testing.T) {
	for _, mode := range []string{"writer", "reader", "system", "nil"} {
		t.Run(mode, func(t *testing.T) {
			ctx := enforceLifecycle(t)
			repo, actor, gitRepo, old := branchExecutionFixture(ctx, t)
			grantLifecycleAction(ctx, t, repo, actor.ID, authz.ManageCodeowners)
			ctx = audit.WithDoer(ctx, actor)
			if mode == "reader" {
				_, err := db.GetEngine(ctx).Where("repo_id = ? AND user_id = ?", repo.ID, actor.ID).Cols("mode").Update(&repo_model.Collaboration{Mode: perm.AccessModeRead})
				require.NoError(t, err)
				_, err = db.GetEngine(ctx).Where("repo_id = ? AND user_id = ?", repo.ID, actor.ID).Cols("mode").Update(&access_model.Access{Mode: perm.AccessModeRead})
				require.NoError(t, err)
			}
			if mode == "system" {
				ctx = audit.WithOrigin(ctx, audit_model.OriginSystem)
			}
			if mode == "nil" {
				actor = nil
			}
			_, err := RenameBranch(ctx, repo, actor, "controlled", "renamed")
			if mode == "writer" {
				require.NoError(t, err)
				require.False(t, gitRepo.IsBranchExist(ctx, "controlled"))
				current, err := gitRepo.GetBranchCommitID(ctx, "renamed")
				require.NoError(t, err)
				require.Equal(t, old, current)
				var rows []*authz_model.DecisionRecord
				err = db.GetEngine(ctx).Where("repo_id = ? AND decision_mode = ?", repo.ID, "enforce").Find(&rows)
				require.NoError(t, err)
				require.Len(t, rows, 2)
				for _, row := range rows {
					require.True(t, row.ExecutionStarted)
					require.Equal(t, "success", row.NativeOutcome)
					require.Equal(t, "allow", row.AuthorizationDecision)
				}
				return
			}
			var rejection *authz_service.ExecutionError
			require.ErrorAs(t, err, &rejection)
			require.Equal(t, 403, rejection.Status)
			current, err := gitRepo.GetBranchCommitID(ctx, "controlled")
			require.NoError(t, err)
			require.Equal(t, old, current)
			require.False(t, gitRepo.IsBranchExist(ctx, "renamed"))
		})
	}
}

func TestBranchInitializationRequiresExactMaintenance(t *testing.T) {
	for _, state := range []string{"valid", "missing", "wrong-owner", "wrong-actor", "wrong-branch", "wrong-caller", "initialized", "owner-changed", "branch-changed", "inactive", "archived", "audit-disabled"} {
		t.Run(state, func(t *testing.T) {
			ctx := enforceLifecycle(t)
			t.Cleanup(test.MockVariableValue(&setting.RepoRootPath, t.TempDir()))
			owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			repo := &repo_model.Repository{OwnerID: owner.ID, Owner: owner, OwnerName: owner.Name, Name: "initial-maintenance", LowerName: "initial-maintenance", DefaultBranch: "master", ObjectFormatName: "sha1", IsEmpty: true}
			require.NoError(t, db.Insert(ctx, repo))
			require.NoError(t, db.Insert(ctx, &repo_model.RepoUnit{RepoID: repo.ID, Type: unit.TypeCode}))
			require.NoError(t, git.InitRepository(ctx, repo, "sha1"))
			local := t.TempDir()
			require.NoError(t, git.InitRepositoryLocal(ctx, local, false, "sha1"))
			require.NoError(t, os.WriteFile(filepath.Join(local, "CODEOWNERS"), []byte("* @user2\n"), 0o600))
			marker := repositoryGitInitialization{repo.ID, repo.OwnerID, owner.ID, "master", "create"}
			switch state {
			case "wrong-owner":
				marker.ownerID++
			case "wrong-actor":
				marker.creatorID++
			case "wrong-branch":
				marker.branch = "other"
			case "wrong-caller":
				marker.caller = "generic-system"
			case "owner-changed":
				_, err := db.GetEngine(ctx).ID(repo.ID).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 5})
				require.NoError(t, err)
			case "branch-changed":
				_, err := db.GetEngine(ctx).ID(repo.ID).Cols("default_branch").Update(&repo_model.Repository{DefaultBranch: "other"})
				require.NoError(t, err)
			case "inactive":
				_, err := db.GetEngine(ctx).ID(owner.ID).Cols("is_active").Update(&user_model.User{IsActive: false})
				require.NoError(t, err)
			case "archived":
				_, err := db.GetEngine(ctx).ID(repo.ID).Cols("is_archived").Update(&repo_model.Repository{IsArchived: true})
				require.NoError(t, err)
			case "audit-disabled":
				setting.Audit.RecordOutput = setting.AuditRecordOutputDisabled
			}
			if state != "missing" {
				ctx = withRepositoryGitInitialization(ctx, marker)
			}
			if state == "initialized" {
				require.NoError(t, initRepoCommit(withRepositoryGitInitialization(ctx, repositoryGitInitialization{repo.ID, repo.OwnerID, owner.ID, "master", "create"}), local, repo, owner))
				require.NoError(t, os.WriteFile(filepath.Join(local, "README.md"), []byte("not an initialization"), 0o600))
			}
			err := initRepoCommit(ctx, local, repo, owner)
			if state == "valid" {
				require.NoError(t, err)
				row := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{ScopeID: repo.ID, Action: audit_model.RepositoryCreate, Origin: audit_model.OriginSystem})
				require.NotEqual(t, owner.ID, row.ActorID)
				require.Contains(t, row.Metadata, "repository-initial-git-create")
				require.True(t, git.IsBranchExist(ctx, repo, "master"))
				return
			}
			var rejection *authz_service.ExecutionError
			require.ErrorAs(t, err, &rejection)
			if state == "audit-disabled" {
				require.Equal(t, 503, rejection.Status)
			} else {
				require.Equal(t, 403, rejection.Status)
			}
			if state != "initialized" {
				require.False(t, git.IsBranchExist(ctx, repo, "master"))
			}
		})
	}
}

func TestBranchPreparationTimeoutCannotFailOpen(t *testing.T) {
	ctx := enforceLifecycle(t)
	setting.EnterpriseAuthz.FailClosedOnError = false
	repo, actor, _, _ := branchExecutionFixture(ctx, t)
	_, _, _, err := beginBranchGitExecution(ctx, actor, repo, authz.PushBranch, "controlled", func(bounded context.Context) ([]authz_service.GitExecutionInput, error) {
		<-bounded.Done()
		return nil, bounded.Err()
	})
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, "execution_timeout", rejection.Reason)
	require.Equal(t, 503, rejection.Status)
}

func TestBranchDeleteNativePolicyFailure(t *testing.T) {
	ctx := enforceLifecycle(t)
	repo, actor, _, _ := branchExecutionFixture(ctx, t)
	_, err := db.Exec(ctx, "ALTER TABLE protected_branch RENAME TO branch_native_policy_fault")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.Exec(context.WithoutCancel(ctx), "ALTER TABLE branch_native_policy_fault RENAME TO protected_branch")
		require.NoError(t, err)
	})
	err = checkBranchExecutionNative(ctx, actor, repo, "delete", "controlled", "", false)
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, 503, rejection.Status)
	require.Equal(t, "policy_read_failed", rejection.Reason)
}
