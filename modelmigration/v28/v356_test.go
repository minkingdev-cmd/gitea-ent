// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"testing"

	"gitea.dev/modelmigration/migrationtest"

	"github.com/stretchr/testify/require"
)

type legacyWeComMappingOrgUser struct {
	ID       int64 `xorm:"pk autoincr"`
	UID      int64 `xorm:"INDEX UNIQUE(s)"`
	OrgID    int64 `xorm:"INDEX UNIQUE(s)"`
	IsPublic bool  `xorm:"INDEX"`
}

func (*legacyWeComMappingOrgUser) TableName() string {
	return "org_user"
}

type legacyWeComMappingTeamUser struct {
	ID     int64 `xorm:"pk autoincr"`
	OrgID  int64 `xorm:"INDEX"`
	TeamID int64 `xorm:"UNIQUE(s)"`
	UID    int64 `xorm:"UNIQUE(s)"`
}

func (*legacyWeComMappingTeamUser) TableName() string {
	return "team_user"
}

func TestAddEnterpriseWeComAuthzMappingTablesDoesNotMutateExistingMembershipOrAuthData(t *testing.T) {
	x, deferable := migrationtest.PrepareTestEnv(t, 0,
		new(legacyWeComMigrationUser),
		new(legacyWeComMigrationPublicKey),
		new(legacyWeComMigrationAccessToken),
		new(legacyWeComMigrationAuthToken),
		new(WeComIdentity),
		new(WeComDepartment),
		new(WeComTag),
		new(WeComMembership),
		new(legacyWeComMappingOrgUser),
		new(legacyWeComMappingTeamUser),
	)
	defer deferable()
	if x == nil || t.Failed() {
		return
	}

	legacyUser := &legacyWeComMigrationUser{ID: 1101, Name: "mapping-user", Email: "mapping@example.com", Passwd: "hashed-password"}
	legacyKey := &legacyWeComMigrationPublicKey{ID: 2101, OwnerID: legacyUser.ID, Name: "ssh", Fingerprint: "SHA256:mapping", Content: "ssh-ed25519 AAAAC3 mapping@example.com"}
	legacyPAT := &legacyWeComMigrationAccessToken{ID: 3101, UID: legacyUser.ID, Name: "pat", TokenHash: "pat-hash", TokenSalt: "pat-salt", TokenLastEight: "last8pat", Scope: "all"}
	legacyGitHTTPToken := &legacyWeComMigrationAuthToken{ID: "mapping-git-http", TokenHash: "git-http-hash", UserID: legacyUser.ID, ExpiresUnix: 1893456000}
	identity := &WeComIdentity{ID: 4101, UserID: legacyUser.ID, CorpID: "corp-1", WeComUserID: "u-1", ExternalID: "wecom:corp-1:u-1", LoginSourceID: 1, Status: "active"}
	orgUser := &legacyWeComMappingOrgUser{ID: 5101, UID: legacyUser.ID, OrgID: 42, IsPublic: true}
	teamUser := &legacyWeComMappingTeamUser{ID: 6101, UID: legacyUser.ID, OrgID: 42, TeamID: 84}
	_, err := x.Insert(legacyUser, legacyKey, legacyPAT, legacyGitHTTPToken, identity, orgUser, teamUser)
	require.NoError(t, err)

	require.NoError(t, AddEnterpriseWeComAuthzMappingTables(t.Context(), x))

	for _, table := range []string{"enterprise_wecom_authz_mapping", "enterprise_wecom_managed_membership"} {
		exists, err := x.IsTableExist(table)
		require.NoError(t, err)
		require.True(t, exists, "missing table %s", table)
	}

	userAfter := &legacyWeComMigrationUser{ID: legacyUser.ID}
	has, err := x.Get(userAfter)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, legacyUser.Passwd, userAfter.Passwd)

	patAfter := &legacyWeComMigrationAccessToken{ID: legacyPAT.ID}
	has, err = x.Get(patAfter)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, legacyPAT.TokenHash, patAfter.TokenHash)

	gitHTTPTokenAfter := &legacyWeComMigrationAuthToken{ID: legacyGitHTTPToken.ID}
	has, err = x.Get(gitHTTPTokenAfter)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, legacyGitHTTPToken.TokenHash, gitHTTPTokenAfter.TokenHash)

	identityAfter := &WeComIdentity{ID: identity.ID}
	has, err = x.Get(identityAfter)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, identity.WeComUserID, identityAfter.WeComUserID)

	orgUserAfter := &legacyWeComMappingOrgUser{ID: orgUser.ID}
	has, err = x.Get(orgUserAfter)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, orgUser.IsPublic, orgUserAfter.IsPublic)

	teamUserAfter := &legacyWeComMappingTeamUser{ID: teamUser.ID}
	has, err = x.Get(teamUserAfter)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, teamUser.TeamID, teamUserAfter.TeamID)
}
