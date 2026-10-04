// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitrepo"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func gitExecutionFixture(t *testing.T) (GitExecutionInput, func(...string) string) {
	t.Helper()
	enableObservation(t)
	input := executionInput(t)
	dir := t.TempDir()
	command := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", args...)
		cmd.Dir = dir
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, string(output))
		return strings.TrimSpace(string(output))
	}
	command("init", "--initial-branch=main")
	command("config", "user.name", "Fixture")
	command("config", "user.email", "fixture@example.com")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "README"), []byte("initial"), 0o600))
	command("add", "README")
	command("commit", "-m", "initial")
	repository, err := git.OpenRepositoryLocal(t.Context(), dir)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	return GitExecutionInput{Actor: input.Actor, Repo: input.Repo, Credential: input.Credential, Source: "api", Ref: git.RefNameFromBranch("main"), GitRepo: repository}, command
}

func TestGitExecutionCodeownersActualAddRenameDeleteAndBinary(t *testing.T) {
	for _, path := range []string{"CODEOWNERS", "docs/CODEOWNERS", ".gitea/CODEOWNERS"} {
		t.Run(path, func(t *testing.T) {
			input, command := gitExecutionFixture(t)
			dir := gitrepo.RepoLocalPath(input.GitRepo)
			require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, path)), 0o700))
			old := command("rev-parse", "HEAD")
			require.NoError(t, os.WriteFile(filepath.Join(dir, path), []byte{0, 1, 2}, 0o600))
			command("add", ".")
			command("commit", "-m", "binary controlled file")
			input.OldCommitID, input.NewCommitID = old, command("rev-parse", "HEAD")
			actions, err := gitMutationActions(t.Context(), input)
			require.NoError(t, err)
			require.Len(t, actions, 1)
			require.Equal(t, authz.ManageCodeowners, actions[0].Action)
			require.False(t, actions[0].ConditionContext.PathsComplete)
			require.Contains(t, actions[0].ConditionContext.Paths, path)
			old = input.NewCommitID
			command("mv", path, "ordinary-file")
			command("commit", "-m", "rename away")
			input.OldCommitID, input.NewCommitID = old, command("rev-parse", "HEAD")
			actions, err = gitMutationActions(t.Context(), input)
			require.NoError(t, err)
			require.Len(t, actions, 1)
			require.Contains(t, actions[0].ConditionContext.Paths, path)
			command("mv", "ordinary-file", path)
			command("commit", "-m", "rename into")
			old = command("rev-parse", "HEAD")
			command("rm", path)
			command("commit", "-m", "delete")
			input.OldCommitID, input.NewCommitID = old, command("rev-parse", "HEAD")
			actions, err = gitMutationActions(t.Context(), input)
			require.NoError(t, err)
			require.Len(t, actions, 1)
			require.Contains(t, actions[0].ConditionContext.Paths, path)
		})
	}
}

func TestGitExecutionOrdinaryLargeDiffAndZeroRefs(t *testing.T) {
	input, command := gitExecutionFixture(t)
	dir := gitrepo.RepoLocalPath(input.GitRepo)
	old := command("rev-parse", "HEAD")
	for i := range authz.MaxContextPaths + 1 {
		require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("file-%d", i)), []byte("value"), 0o600))
	}
	command("add", ".")
	command("commit", "-m", "large ordinary diff")
	input.OldCommitID, input.NewCommitID = old, command("rev-parse", "HEAD")
	entries, err := gitMutationActions(t.Context(), input)
	require.NoError(t, err)
	require.Empty(t, entries)
	input.OldCommitID = git.Sha1ObjectFormat.EmptyObjectID().String()
	entries, err = gitMutationActions(t.Context(), input)
	require.NoError(t, err)
	require.Empty(t, entries)
	input.OldCommitID, input.NewCommitID = input.NewCommitID, git.Sha1ObjectFormat.EmptyObjectID().String()
	entries, err = gitMutationActions(t.Context(), input)
	require.NoError(t, err)
	require.Empty(t, entries)
}

func TestGitExecutionIncompleteAndOverLimitControlledDiff(t *testing.T) {
	input, command := gitExecutionFixture(t)
	input.Actor = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: input.Repo.ID, Name: "path-role", LowerName: "path-role", Revision: 1}
	require.NoError(t, db.Insert(t.Context(), role))
	_, condition, hash, err := authz.ParseCondition([]byte(`{"path_pattern":["**"]}`))
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.ManageCodeowners, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
	require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{RoleID: role.ID, SubjectType: authz_model.SubjectUser, SubjectID: input.Actor.ID, ScopeType: authz_model.ScopeRepo, ScopeID: input.Repo.ID, ScopeOwnerID: input.Repo.OwnerID}))
	dir := gitrepo.RepoLocalPath(input.GitRepo)
	old := command("rev-parse", "HEAD")
	for i := range authz.MaxContextPaths + 1 {
		require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("file-%d", i)), []byte("value"), 0o600))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "CODEOWNERS"), []byte("* @private-owner"), 0o600))
	command("add", ".")
	command("commit", "-m", "large controlled diff")
	input.OldCommitID, input.NewCommitID = old, command("rev-parse", "HEAD")
	_, err = gitMutationActions(t.Context(), input)
	var failure *ExecutionError
	require.ErrorAs(t, err, &failure)
	require.Equal(t, "context_limit_exceeded", failure.Reason)
	input.NewCommitID = strings.Repeat("f", 40)
	_, err = gitMutationActions(t.Context(), input)
	require.ErrorAs(t, err, &failure)
	require.Equal(t, "invalid_execution_context", failure.Reason)
}

func TestGitExecutionLargeControlledDiffWithoutPathConditions(t *testing.T) {
	input, command := gitExecutionFixture(t)
	dir := gitrepo.RepoLocalPath(input.GitRepo)
	old := command("rev-parse", "HEAD")
	for i := range authz.MaxContextPaths + 1 {
		require.NoError(t, os.WriteFile(filepath.Join(dir, fmt.Sprintf("file-%d", i)), []byte("value"), 0o600))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "CODEOWNERS"), []byte("* @owner"), 0o600))
	command("add", ".")
	command("commit", "-m", "large native controlled diff")
	input.OldCommitID, input.NewCommitID = old, command("rev-parse", "HEAD")
	entries, err := gitMutationActions(t.Context(), input)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, authz.ManageCodeowners, entries[0].Action)
	require.False(t, entries[0].ConditionContext.PathsComplete)
}

func TestGitExecutionNativeBranchRuleFailureCannotFallback(t *testing.T) {
	input, command := gitExecutionFixture(t)
	setting.EnterpriseAuthz.Enforce = true
	setting.EnterpriseAuthz.FailClosedOnError = false
	input.OldCommitID = command("rev-parse", "HEAD")
	require.NoError(t, os.WriteFile(filepath.Join(gitrepo.RepoLocalPath(input.GitRepo), "CODEOWNERS"), []byte("* @user2\n"), 0o600))
	command("add", ".")
	command("commit", "-m", "controlled fixture")
	input.NewCommitID = command("rev-parse", "HEAD")
	_, err := db.GetEngine(t.Context()).Exec("ALTER TABLE protected_branch RENAME TO protected_branch_authz_unavailable")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.GetEngine(context.WithoutCancel(t.Context())).Exec("ALTER TABLE protected_branch_authz_unavailable RENAME TO protected_branch")
		require.NoError(t, err)
	})
	_, admission, err := BeginGitExecution(t.Context(), []GitExecutionInput{input})
	var rejection *ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, 503, rejection.Status)
	require.Equal(t, "policy_read_failed", rejection.Reason)
	require.Nil(t, admission)
}

func TestGitExecutionNativeIdentityFailureCannotFallback(t *testing.T) {
	for _, table := range []string{"user", "repository", "repo_unit", "wecom_identity", "missing_actor", "missing_repo"} {
		t.Run(table, func(t *testing.T) {
			input, command := gitExecutionFixture(t)
			setting.EnterpriseAuthz.Enforce = true
			setting.EnterpriseAuthz.FailClosedOnError = false
			input.OldCommitID = command("rev-parse", "HEAD")
			require.NoError(t, os.WriteFile(filepath.Join(gitrepo.RepoLocalPath(input.GitRepo), "CODEOWNERS"), []byte("* @user2\n"), 0o600))
			command("add", ".")
			command("commit", "-m", "controlled native identity fixture")
			input.NewCommitID = command("rev-parse", "HEAD")
			status := 503
			switch table {
			case "missing_actor":
				input.Actor.ID, status = 999999, 403
			case "missing_repo":
				input.Repo.ID, status = 999999, 403
			default:
				if table == "wecom_identity" {
					input.Actor = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
					t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom))
					setting.EnterpriseWeCom.Enabled = true
					setting.EnterpriseWeCom.CorpID, setting.EnterpriseWeCom.AgentID = "test-corp", "test-agent"
				}
				_, err := db.GetEngine(t.Context()).Exec("ALTER TABLE `" + table + "` RENAME TO " + table + "_authz_unavailable")
				require.NoError(t, err)
				t.Cleanup(func() {
					_, err := db.GetEngine(context.WithoutCancel(t.Context())).Exec("ALTER TABLE " + table + "_authz_unavailable RENAME TO `" + table + "`")
					require.NoError(t, err)
				})
			}
			_, admission, err := BeginGitExecution(t.Context(), []GitExecutionInput{input})
			var rejection *ExecutionError
			require.ErrorAs(t, err, &rejection)
			require.Equal(t, status, rejection.Status)
			require.Nil(t, admission)
		})
	}
}

func TestGitExecutionNativeGuardFailureCannotFallback(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(strconv.FormatBool(timeout), func(t *testing.T) {
			input, command := gitExecutionFixture(t)
			setting.EnterpriseAuthz.Enforce = true
			setting.EnterpriseAuthz.FailClosedOnError = false
			input.OldCommitID = command("rev-parse", "HEAD")
			require.NoError(t, os.WriteFile(filepath.Join(gitrepo.RepoLocalPath(input.GitRepo), "CODEOWNERS"), []byte("* @user2\n"), 0o600))
			command("add", ".")
			command("commit", "-m", "native guard fixture")
			input.NewCommitID = command("rev-parse", "HEAD")
			input.NativeGuard = func(ctx context.Context, _ *user_model.User, _ *repo_model.Repository) error {
				if timeout {
					<-ctx.Done()
				}
				return errors.New("policy_read_failed")
			}
			_, admission, err := BeginGitExecution(t.Context(), []GitExecutionInput{input})
			var rejection *ExecutionError
			require.ErrorAs(t, err, &rejection)
			require.Equal(t, 503, rejection.Status)
			require.Nil(t, admission)
		})
	}
}
