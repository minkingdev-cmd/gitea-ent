// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"testing"

	"gitea.dev/modelmigration/migrationtest"

	"github.com/stretchr/testify/require"
)

type legacyEnterpriseRepoGovernanceRepository struct {
	ID          int64  `xorm:"pk autoincr"`
	OwnerID     int64  `xorm:"INDEX"`
	OwnerName   string `xorm:"INDEX"`
	Name        string
	LowerName   string `xorm:"INDEX"`
	IsPrivate   bool
	Description string
}

func (*legacyEnterpriseRepoGovernanceRepository) TableName() string {
	return "repository"
}

func TestAddEnterpriseWeComRepositoryGovernanceTablesDoesNotMutateExistingRepositories(t *testing.T) {
	x, deferable := migrationtest.PrepareTestEnv(t, 0,
		new(legacyWeComMigrationUser),
		new(legacyEnterpriseRepoGovernanceRepository),
	)
	defer deferable()
	if x == nil || t.Failed() {
		return
	}

	user := &legacyWeComMigrationUser{ID: 1301, Name: "repo-governance-user", Email: "repo-governance@example.com", Passwd: "hashed-password"}
	repo := &legacyEnterpriseRepoGovernanceRepository{ID: 2301, OwnerID: user.ID, OwnerName: user.Name, Name: "existing-repo", LowerName: "existing-repo", IsPrivate: false, Description: "keep"}
	_, err := x.Insert(user, repo)
	require.NoError(t, err)

	require.NoError(t, AddEnterpriseWeComRepositoryGovernanceTables(t.Context(), x))

	for _, table := range []string{"enterprise_wecom_org_repo_request", "enterprise_wecom_repository_governance"} {
		exists, err := x.IsTableExist(table)
		require.NoError(t, err)
		require.True(t, exists, "missing table %s", table)
	}

	repoAfter := &legacyEnterpriseRepoGovernanceRepository{ID: repo.ID}
	has, err := x.Get(repoAfter)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, repo.IsPrivate, repoAfter.IsPrivate)
	require.Equal(t, repo.Description, repoAfter.Description)
}
