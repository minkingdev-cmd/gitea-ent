// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"testing"

	"gitea.dev/models/db"
	"gitea.dev/models/unittest"

	"github.com/stretchr/testify/require"
)

func TestBindIdentityToUserKeepsCorpUserIDUnique(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	identity, created, err := BindIdentityToUser(t.Context(), BindIdentityOptions{
		UserID:        1,
		CorpID:        "corp-1",
		WeComUserID:   "zhangsan",
		LoginSourceID: 10,
		Status:        IdentityStatusActive,
		Name:          "Zhang San",
		Email:         "zhangsan@example.com",
	})
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, MakeExternalID("corp-1", "zhangsan"), identity.ExternalID)

	identity, created, err = BindIdentityToUser(t.Context(), BindIdentityOptions{
		UserID:        1,
		CorpID:        "corp-1",
		WeComUserID:   "zhangsan",
		LoginSourceID: 10,
		Status:        IdentityStatusActive,
		Name:          "张三",
		Email:         "zhangsan-renamed@example.com",
	})
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, "张三", identity.Name)
	require.Equal(t, "zhangsan-renamed@example.com", identity.Email)

	_, _, err = BindIdentityToUser(t.Context(), BindIdentityOptions{
		UserID:        2,
		CorpID:        "corp-1",
		WeComUserID:   "zhangsan",
		LoginSourceID: 10,
		Status:        IdentityStatusActive,
	})
	require.ErrorIs(t, err, ErrIdentityAlreadyBound)

	count, err := db.GetEngine(t.Context()).Where("corp_id = ? AND wecom_userid = ?", "corp-1", "zhangsan").Count(new(Identity))
	require.NoError(t, err)
	require.Equal(t, int64(1), count)
}
