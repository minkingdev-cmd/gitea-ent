// Copyright 2025 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package asymkey

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gitea.dev/models/db"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/git"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

func TestUserHasPubkeys(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())
	test := func(t *testing.T, userID int64, expectedHasGPG, expectedHasSSH bool) {
		ctx := t.Context()
		hasGPG, err := userHasPubkeysGPG(ctx, userID)
		require.NoError(t, err)
		hasSSH, err := userHasPubkeysSSH(ctx, userID)
		require.NoError(t, err)
		hasPubkeys, err := userHasPubkeys(ctx, userID)
		require.NoError(t, err)
		assert.Equal(t, expectedHasGPG, hasGPG)
		assert.Equal(t, expectedHasSSH, hasSSH)
		assert.Equal(t, expectedHasGPG || expectedHasSSH, hasPubkeys)
	}

	t.Run("AllowUserWithGPGKey", func(t *testing.T) {
		test(t, 36, true, false) // has gpg
	})
	t.Run("AllowUserWithSSHKey", func(t *testing.T) {
		test(t, 2, false, true) // has ssh
	})
	t.Run("DenyUserWithNoKeys", func(t *testing.T) {
		test(t, 1, false, false) // no pubkey
	})
}

func TestSignMergeApprovalReadFailureIsNotMissingApproval(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.Repository.Signing.SigningKey, "test-signing-key"))
	t.Cleanup(test.MockVariableValue(&setting.Repository.Signing.Merges, []string{"approved"}))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(t.Context()))
	require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: pr.BaseRepoID, RuleName: pr.BaseBranch}))
	require.NoError(t, db.Insert(t.Context(), &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 4, Type: issues_model.ReviewTypeApprove, Official: true, Stale: true}))
	repo, err := git.OpenRepository(t.Context(), pr.BaseRepo)
	require.NoError(t, err)
	defer repo.Close()
	check := func() error {
		_, _, _, err := SignMerge(t.Context(), pr, actor, repo, git.BranchPrefix+pr.BaseBranch, git.BranchPrefix+pr.HeadBranch)
		return err
	}
	require.NoError(t, check())
	hook := &mergeSigningApprovalReadFailure{enabled: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	t.Cleanup(func() { hook.enabled = false })
	err = check()
	require.ErrorContains(t, err, "injected_signing_approval_read_failure")
	require.False(t, IsErrWontSign(err))
}

type mergeSigningApprovalReadFailure struct{ enabled bool }

func (h *mergeSigningApprovalReadFailure) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.enabled && strings.HasPrefix(c.SQL, "SELECT") && strings.Contains(strings.ToUpper(c.SQL), "COUNT") && strings.Contains(c.SQL, "review") {
		return c.Ctx, errors.New("injected_signing_approval_read_failure")
	}
	return c.Ctx, nil
}

func (*mergeSigningApprovalReadFailure) AfterProcess(*contexts.ContextHook) error { return nil }
