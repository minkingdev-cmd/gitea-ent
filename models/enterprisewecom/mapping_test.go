// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"testing"

	"gitea.dev/models/db"
	"gitea.dev/models/unittest"

	"github.com/stretchr/testify/require"
)

func TestAuthzMappingAndManagedMembershipPersistOutsideNativeMembershipTables(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	mapping := &AuthzMapping{
		CorpID:     "corp-1",
		SourceType: AuthzSourceDepartment,
		SourceID:   "100",
		TargetType: AuthzTargetTeam,
		OrgID:      3,
		TeamID:     5,
		IsActive:   true,
		CreatedBy:  1,
	}
	require.NoError(t, db.Insert(t.Context(), mapping))
	require.NotZero(t, mapping.ID)

	managed := &ManagedMembership{
		MappingID:       mapping.ID,
		UserID:          2,
		TargetType:      AuthzTargetTeam,
		OrgID:           3,
		TeamID:          5,
		LastSeenApplyID: "apply-1",
	}
	require.NoError(t, db.Insert(t.Context(), managed))

	var mappings []AuthzMapping
	require.NoError(t, db.GetEngine(t.Context()).Where("corp_id = ?", "corp-1").Find(&mappings))
	require.Len(t, mappings, 1)
	require.Equal(t, AuthzSourceDepartment, mappings[0].SourceType)

	var managedRows []ManagedMembership
	require.NoError(t, db.GetEngine(t.Context()).Where("mapping_id = ?", mapping.ID).Find(&managedRows))
	require.Len(t, managedRows, 1)
	require.Equal(t, int64(2), managedRows[0].UserID)
}
