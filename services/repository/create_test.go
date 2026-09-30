// Copyright 2025 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"os"
	"testing"

	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitrepo"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateRepositoryDirectly(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())

	// a successful creating repository
	user2 := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	count, err := repo_model.CountRepositories(t.Context(), repo_model.CountRepositoryOptions{OwnerID: user2.ID})
	require.NoError(t, err)
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, PersonalRepoQuota: int(count) + 1})()
	testRepoName := "created-repo"
	t.Run("Success", func(t *testing.T) {
		createdRepo, err := CreateRepositoryDirectly(t.Context(), user2, user2, CreateRepoOptions{
			Name: testRepoName,
		}, true)
		assert.NoError(t, err)
		assert.NotNil(t, createdRepo)
		assert.True(t, createdRepo.IsPrivate)

		exist, err := git.IsRepositoryExist(t.Context(), gitrepo.CodeRepoByName(user2.Name, createdRepo.Name))
		assert.NoError(t, err)
		assert.True(t, exist)

		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerName: user2.Name, Name: createdRepo.Name})

		err = DeleteRepositoryDirectly(t.Context(), createdRepo.ID)
		assert.NoError(t, err)
	})

	t.Run("Failure", func(t *testing.T) {
		// a failed creating because some mock data
		// create the repository directory so that the creation will fail after database record created.
		testFailureRepoName := testRepoName
		testFailureRepo := gitrepo.CodeRepoByName(user2.Name, testFailureRepoName)
		testFailurePath := gitrepo.RepoLocalPath(testFailureRepo)
		assert.NoError(t, os.MkdirAll(testFailurePath, os.ModePerm))

		createdRepo2, err := CreateRepositoryDirectly(t.Context(), user2, user2, CreateRepoOptions{
			Name: testFailureRepoName,
		}, true)
		assert.Nil(t, createdRepo2)
		assert.Error(t, err)

		// assert the cleanup is successful
		unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerName: user2.Name, Name: testFailureRepoName})

		exist, err := git.IsRepositoryExist(t.Context(), testFailureRepo)
		assert.NoError(t, err)
		assert.False(t, exist)
		unittest.AssertCount(t, &repo_model.Repository{OwnerID: user2.ID}, count)
		restoredOwner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: user2.ID})
		retry, err := CreateRepositoryDirectly(t.Context(), restoredOwner, restoredOwner, CreateRepoOptions{Name: testFailureRepoName}, true)
		require.NoError(t, err)
		require.NoError(t, DeleteRepositoryDirectly(t.Context(), retry.ID))
		unittest.AssertCount(t, &repo_model.Repository{OwnerID: user2.ID}, count)
	})
}
