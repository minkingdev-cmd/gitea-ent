// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"os"
	"path/filepath"
	"testing"

	authz_model "gitea.dev/models/enterpriseauthz"
	packages_model "gitea.dev/models/packages"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/git/gitrepo"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestGitExecutionActiveProofIsExactOneShotAndNotTicketPermission(t *testing.T) {
	input, command := gitExecutionFixture(t)
	setting.EnterpriseAuthz.Enforce = true
	defer test.MockVariableValue(&setting.InternalToken, "active-test-secret")()
	input.OldCommitID, input.NewCommitID = command("rev-parse", "HEAD"), command("rev-parse", "HEAD")
	input.Merge = true
	ctx, admission, err := BeginGitExecution(t.Context(), []GitExecutionInput{input})
	require.NoError(t, err)
	ticket := NewHookOperationTicket(ctx, EvaluateInput{Actor: input.Actor, Repo: input.Repo, Credential: input.Credential, ConditionContext: executionInput(t).ConditionContext}, nil)
	restored, operation := RestoreHookOperation(t.Context(), ticket, input.Repo.ID, input.Actor.ID, "")
	require.NotNil(t, operation)
	require.False(t, ReuseActiveGitExecution(restored, operation, []GitExecutionInput{input}))
	_, err = RegisterGitExecution(ctx, admission, []GitExecutionInput{input})
	require.Error(t, err)
	require.NoError(t, admission.Start(ctx))
	release, err := RegisterGitExecution(ctx, admission, []GitExecutionInput{input})
	require.NoError(t, err)
	defer release()
	changed := input
	changed.NewCommitID = "1111111111111111111111111111111111111111"
	require.False(t, ReuseActiveGitExecution(restored, operation, []GitExecutionInput{changed}))
	input.Merge = false
	require.True(t, ReuseActiveGitExecution(restored, operation, []GitExecutionInput{input}))
	require.False(t, ReuseActiveGitExecution(restored, operation, []GitExecutionInput{input}))
	release()
	require.False(t, ReuseActiveGitExecution(restored, operation, []GitExecutionInput{input}))
}

func TestGitExecutionTerminalRequiresExactIntentAndUnambiguousAttempt(t *testing.T) {
	input, command := gitExecutionFixture(t)
	setting.EnterpriseAuthz.Enforce = true
	defer test.MockVariableValue(&setting.InternalToken, "terminal-test-secret")()
	input.OldCommitID = command("rev-parse", "HEAD")
	require.NoError(t, os.WriteFile(filepath.Join(gitrepo.RepoLocalPath(input.GitRepo), "CODEOWNERS"), []byte("* @fixture"), 0o600))
	command("add", ".")
	command("commit", "-m", "controlled")
	input.NewCommitID = command("rev-parse", "HEAD")
	ctx, admission, err := BeginGitExecution(t.Context(), []GitExecutionInput{input})
	require.NoError(t, err)
	require.NoError(t, admission.Start(ctx))
	ticket := NewHookOperationTicket(ctx, EvaluateInput{Actor: input.Actor, Repo: input.Repo, Credential: input.Credential, ConditionContext: executionInput(t).ConditionContext}, nil)
	restored, operation := RestoreHookOperation(t.Context(), ticket, input.Repo.ID, input.Actor.ID, "")
	changed := input
	changed.NewCommitID = "1111111111111111111111111111111111111111"
	CompleteGitExecution(restored, operation, changed)
	unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{NativeOutcome: "unknown"})
	command("reset", "--hard", input.OldCommitID)
	CompleteGitExecution(restored, operation, input)
	unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{NativeOutcome: "unknown"})
	command("reset", "--hard", input.NewCommitID)
	CompleteGitExecution(restored, operation, input)
	unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{NativeOutcome: "success", NativeStage: "transport"})
	CompleteGitExecution(restored, operation, input)
	for range 2 {
		ctx, admission, err = BeginGitExecution(restored, []GitExecutionInput{input})
		require.NoError(t, err)
		require.NoError(t, admission.Start(ctx))
	}
	CompleteGitExecution(restored, operation, input)
	require.Equal(t, 2, unittest.GetCount(t, &authz_model.DecisionRecord{NativeOutcome: "unknown"}))
}

func TestGitExecutionPostReceiveRequiresActualRefAndSingleClaim(t *testing.T) {
	input, command := gitExecutionFixture(t)
	setting.EnterpriseAuthz.Enforce = true
	defer test.MockVariableValue(&setting.InternalToken, "post-test-secret")()
	input.OldCommitID, input.NewCommitID = command("rev-parse", "HEAD"), command("rev-parse", "HEAD")
	input.Merge = true
	ctx, admission, err := BeginGitExecution(t.Context(), []GitExecutionInput{input})
	require.NoError(t, err)
	require.NoError(t, admission.Start(ctx))
	release, err := RegisterGitExecution(ctx, admission, []GitExecutionInput{input})
	require.NoError(t, err)
	defer release()
	ticket := NewHookOperationTicket(ctx, EvaluateInput{Actor: input.Actor, Repo: input.Repo, Credential: input.Credential, ConditionContext: executionInput(t).ConditionContext}, nil)
	restored, operation := RestoreHookOperation(t.Context(), ticket, input.Repo.ID, input.Actor.ID, "")
	_, attached := AttachActiveGitExecution(restored, operation, []GitExecutionInput{input})
	require.False(t, attached)
	require.True(t, ReuseActiveGitExecution(restored, operation, []GitExecutionInput{input}))
	command("branch", "-m", "different")
	_, attached = AttachActiveGitExecution(restored, operation, []GitExecutionInput{input})
	require.False(t, attached)
	command("branch", "-m", "main")
	post, attached := AttachActiveGitExecution(restored, operation, []GitExecutionInput{input})
	require.True(t, attached)
	require.NoError(t, RequireGitMergeExecution(post, input.Actor.ID, input.Repo.ID, "main", input.NewCommitID))
	require.Error(t, RequireGitMergeExecution(post, input.Actor.ID, input.Repo.ID, "different", input.NewCommitID))
	_, attached = AttachActiveGitExecution(restored, operation, []GitExecutionInput{input})
	require.False(t, attached)
	admission.Finish(ctx, NativeSuccess, StageOperation)
	require.Error(t, RequireGitMergeExecution(post, input.Actor.ID, input.Repo.ID, "main", input.NewCommitID))
}

func TestCargoCleanupExecutionProofIsNarrowAndOneShot(t *testing.T) {
	input, command := gitExecutionFixture(t)
	setting.EnterpriseAuthz.Enforce = true
	defer test.MockVariableValue(&setting.InternalToken, "cargo-cleanup-test-secret")()
	input.OldCommitID, input.NewCommitID = command("rev-parse", "HEAD"), command("rev-parse", "HEAD")
	input.Repo.InternalUsage = repo_model.InternalUsageCargoIndex
	ctx, admission, err := BeginGitExecution(t.Context(), []GitExecutionInput{input})
	require.NoError(t, err)
	require.NoError(t, admission.Start(ctx))
	ticket := NewHookOperationTicket(ctx, EvaluateInput{Actor: input.Actor, Repo: input.Repo, Credential: input.Credential, ConditionContext: executionInput(t).ConditionContext}, nil)
	restored, operation := RestoreHookOperation(t.Context(), ticket, input.Repo.ID, input.Actor.ID, "")
	require.NotNil(t, operation)
	require.False(t, ReuseCargoIndexCleanupExecution(restored, operation, []GitExecutionInput{input}))
	release, err := RegisterGitExecution(ctx, admission, []GitExecutionInput{input})
	require.NoError(t, err)
	require.False(t, ReuseCargoIndexCleanupExecution(restored, operation, []GitExecutionInput{input}))
	release()
	ctx = packages_model.WithCleanupIndexMaintenance(ctx, input.Repo.OwnerID, packages_model.TypeCargo)
	release, err = RegisterGitExecution(ctx, admission, []GitExecutionInput{input})
	require.NoError(t, err)
	defer release()
	changed := input
	changed.NewCommitID = "1111111111111111111111111111111111111111"
	require.False(t, ReuseCargoIndexCleanupExecution(restored, operation, []GitExecutionInput{changed}))
	alteredRepo := *input.Repo
	alteredRepo.OwnerID++
	changed = input
	changed.Repo = &alteredRepo
	require.False(t, ReuseCargoIndexCleanupExecution(restored, operation, []GitExecutionInput{changed}))
	require.True(t, ReuseCargoIndexCleanupExecution(restored, operation, []GitExecutionInput{input}))
	require.False(t, ReuseCargoIndexCleanupExecution(restored, operation, []GitExecutionInput{input}))
	require.True(t, ReuseActiveGitExecution(restored, operation, []GitExecutionInput{input}))
}
