// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"testing"

	"gitea.dev/modelmigration/migrationtest"

	"github.com/stretchr/testify/require"
)

func TestAddEnterpriseWeComSyncVersionColumns(t *testing.T) {
	x, deferable := migrationtest.PrepareTestEnv(t, 0)
	defer deferable()
	if x == nil || t.Failed() {
		return
	}

	require.NoError(t, AddWeComIdentityAndDirectoryTables(t.Context(), x))
	_, err := x.Insert(
		&WeComIdentity{ID: 1, UserID: 1, CorpID: "corp-1", WeComUserID: "user-1", ExternalID: "corp-1:user-1", LoginSourceID: 1},
		&WeComDepartment{ID: 1, CorpID: "corp-1", DepartmentID: 1, Name: "Department"},
		&WeComTag{ID: 1, CorpID: "corp-1", TagID: 1, Name: "Tag"},
		&WeComMembership{ID: 1, CorpID: "corp-1", WeComUserID: "user-1", Kind: "department", TargetID: 1},
	)
	require.NoError(t, err)

	require.NoError(t, AddEnterpriseWeComSyncVersionColumns(t.Context(), x))

	for _, record := range []any{
		&weComIdentitySyncVersion{ID: 1},
		&weComDepartmentSyncVersion{ID: 1},
		&weComTagSyncVersion{ID: 1},
		&weComMembershipSyncVersion{ID: 1},
	} {
		has, err := x.Get(record)
		require.NoError(t, err)
		require.True(t, has)
	}
}
