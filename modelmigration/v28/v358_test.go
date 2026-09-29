// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"testing"

	"gitea.dev/modelmigration/migrationtest"

	"github.com/stretchr/testify/require"
)

func TestAddEnterpriseWeComDirectoryLeadershipMetadataDoesNotMutateExistingDirectoryData(t *testing.T) {
	x, deferable := migrationtest.PrepareTestEnv(t, 0,
		new(WeComIdentity),
		new(WeComDepartment),
		new(WeComMembership),
	)
	defer deferable()
	if x == nil || t.Failed() {
		return
	}

	identity := &WeComIdentity{ID: 4301, UserID: 1, CorpID: "corp-1", WeComUserID: "u-1", ExternalID: "wecom:corp-1:u-1", LoginSourceID: 1, Status: "active"}
	department := &WeComDepartment{ID: 5301, CorpID: "corp-1", DepartmentID: 42, ParentID: 1, Name: "Backend"}
	membership := &WeComMembership{ID: 6301, CorpID: "corp-1", WeComUserID: "u-1", Kind: "department", TargetID: 42}
	_, err := x.Insert(identity, department, membership)
	require.NoError(t, err)

	require.NoError(t, AddEnterpriseWeComDirectoryLeadershipMetadata(t.Context(), x))

	identityAfter := &WeComIdentity{ID: identity.ID}
	has, err := x.Get(identityAfter)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, identity.WeComUserID, identityAfter.WeComUserID)

	departmentAfter := &WeComDepartment{ID: department.ID}
	has, err = x.Get(departmentAfter)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, department.Name, departmentAfter.Name)

	membershipAfter := &WeComMembership{ID: membership.ID}
	has, err = x.Get(membershipAfter)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, membership.TargetID, membershipAfter.TargetID)
}
