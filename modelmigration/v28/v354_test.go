// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"testing"

	"gitea.dev/modelmigration/migrationtest"
	"gitea.dev/modules/timeutil"

	"github.com/stretchr/testify/require"
)

type legacyWeComMigrationUser struct {
	ID          int64  `xorm:"pk autoincr"`
	Name        string `xorm:"UNIQUE NOT NULL"`
	Email       string `xorm:"NOT NULL"`
	Passwd      string
	LoginType   int
	LoginSource int64
}

func (*legacyWeComMigrationUser) TableName() string {
	return "user"
}

type legacyWeComMigrationPublicKey struct {
	ID          int64  `xorm:"pk autoincr"`
	OwnerID     int64  `xorm:"INDEX NOT NULL"`
	Name        string `xorm:"NOT NULL"`
	Fingerprint string `xorm:"INDEX NOT NULL"`
	Content     string `xorm:"MEDIUMTEXT NOT NULL"`
}

func (*legacyWeComMigrationPublicKey) TableName() string {
	return "public_key"
}

type legacyWeComMigrationAccessToken struct {
	ID             int64 `xorm:"pk autoincr"`
	UID            int64 `xorm:"INDEX"`
	Name           string
	TokenHash      string `xorm:"UNIQUE"`
	TokenSalt      string
	TokenLastEight string `xorm:"INDEX token_last_eight"`
	Scope          string
}

func (*legacyWeComMigrationAccessToken) TableName() string {
	return "access_token"
}

type legacyWeComMigrationAuthToken struct {
	ID          string `xorm:"pk"`
	TokenHash   string
	UserID      int64              `xorm:"INDEX"`
	ExpiresUnix timeutil.TimeStamp `xorm:"INDEX"`
}

func (*legacyWeComMigrationAuthToken) TableName() string {
	return "auth_token"
}

func TestAddWeComIdentityAndDirectoryTablesDoesNotMutateExistingAuthData(t *testing.T) {
	x, deferable := migrationtest.PrepareTestEnv(t, 0,
		new(legacyWeComMigrationUser),
		new(legacyWeComMigrationPublicKey),
		new(legacyWeComMigrationAccessToken),
		new(legacyWeComMigrationAuthToken),
	)
	defer deferable()
	if x == nil || t.Failed() {
		return
	}

	legacyUser := &legacyWeComMigrationUser{ID: 1001, Name: "legacy-user", Email: "legacy@example.com", Passwd: "hashed-password"}
	legacyKey := &legacyWeComMigrationPublicKey{ID: 2001, OwnerID: legacyUser.ID, Name: "deploy", Fingerprint: "SHA256:legacy", Content: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILegacy legacy@example.com"}
	legacyPAT := &legacyWeComMigrationAccessToken{ID: 3001, UID: legacyUser.ID, Name: "automation", TokenHash: "pat-hash", TokenSalt: "pat-salt", TokenLastEight: "last8pat", Scope: "all"}
	legacyGitHTTPToken := &legacyWeComMigrationAuthToken{ID: "git-http-token", TokenHash: "git-http-hash", UserID: legacyUser.ID, ExpiresUnix: 1893456000}
	_, err := x.Insert(legacyUser, legacyKey, legacyPAT, legacyGitHTTPToken)
	require.NoError(t, err)

	require.NoError(t, AddWeComIdentityAndDirectoryTables(t.Context(), x))

	for _, table := range []string{"wecom_identity", "wecom_department", "wecom_tag", "wecom_membership"} {
		exists, err := x.IsTableExist(table)
		require.NoError(t, err)
		require.True(t, exists, "missing table %s", table)
	}

	userAfter := &legacyWeComMigrationUser{ID: legacyUser.ID}
	has, err := x.Get(userAfter)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, legacyUser.Passwd, userAfter.Passwd)

	keyAfter := &legacyWeComMigrationPublicKey{ID: legacyKey.ID}
	has, err = x.Get(keyAfter)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, legacyKey.Fingerprint, keyAfter.Fingerprint)
	require.Equal(t, legacyKey.Content, keyAfter.Content)

	patAfter := &legacyWeComMigrationAccessToken{ID: legacyPAT.ID}
	has, err = x.Get(patAfter)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, legacyPAT.TokenHash, patAfter.TokenHash)
	require.Equal(t, legacyPAT.TokenSalt, patAfter.TokenSalt)
	require.Equal(t, legacyPAT.TokenLastEight, patAfter.TokenLastEight)

	gitHTTPTokenAfter := &legacyWeComMigrationAuthToken{ID: legacyGitHTTPToken.ID}
	has, err = x.Get(gitHTTPTokenAfter)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, legacyGitHTTPToken.TokenHash, gitHTTPTokenAfter.TokenHash)
	require.Equal(t, legacyGitHTTPToken.ExpiresUnix, gitHTTPTokenAfter.ExpiresUnix)
}
