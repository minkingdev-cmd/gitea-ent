// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"testing"

	"gitea.dev/models/db"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"

	"github.com/stretchr/testify/require"
)

func TestCargoIndexCannotTransferOwner(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	repo.InternalUsage = repo_model.InternalUsageCargoIndex
	require.NoError(t, repo_model.UpdateRepositoryColsWithAutoTime(t.Context(), repo, "internal_usage"))
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	target := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
	require.ErrorContains(t, StartRepositoryTransfer(t.Context(), owner, target, repo, nil), "internal_repository_transfer_forbidden")
	require.Equal(t, owner.ID, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}).OwnerID)
	var transfers []*repo_model.RepoTransfer
	require.NoError(t, db.GetEngine(t.Context()).Where("repo_id=?", repo.ID).Find(&transfers))
	require.Empty(t, transfers)
}
