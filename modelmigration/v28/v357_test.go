// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"testing"

	"gitea.dev/modelmigration/migrationtest"

	"github.com/stretchr/testify/require"
)

func TestAddEnterpriseWeComAutomationStateTablesDoesNotMutateExistingAuthMembershipOrMappingData(t *testing.T) {
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
		new(EnterpriseWeComAuthzMapping),
		new(EnterpriseWeComManagedMembership),
	)
	defer deferable()
	if x == nil || t.Failed() {
		return
	}

	legacyUser := &legacyWeComMigrationUser{ID: 1201, Name: "automation-user", Email: "automation@example.com", Passwd: "hashed-password"}
	legacyKey := &legacyWeComMigrationPublicKey{ID: 2201, OwnerID: legacyUser.ID, Name: "ssh", Fingerprint: "SHA256:automation", Content: "ssh-ed25519 AAAAC3 automation@example.com"}
	legacyPAT := &legacyWeComMigrationAccessToken{ID: 3201, UID: legacyUser.ID, Name: "pat", TokenHash: "pat-hash", TokenSalt: "pat-salt", TokenLastEight: "last8pat", Scope: "all"}
	legacyGitHTTPToken := &legacyWeComMigrationAuthToken{ID: "automation-git-http", TokenHash: "git-http-hash", UserID: legacyUser.ID, ExpiresUnix: 1893456000}
	identity := &WeComIdentity{ID: 4201, UserID: legacyUser.ID, CorpID: "corp-1", WeComUserID: "u-1", ExternalID: "wecom:corp-1:u-1", LoginSourceID: 1, Status: "active"}
	orgUser := &legacyWeComMappingOrgUser{ID: 5201, UID: legacyUser.ID, OrgID: 42, IsPublic: true}
	teamUser := &legacyWeComMappingTeamUser{ID: 6201, UID: legacyUser.ID, OrgID: 42, TeamID: 84}
	mapping := &EnterpriseWeComAuthzMapping{
		ID:         7201,
		CorpID:     "corp-1",
		SourceType: "department",
		SourceID:   "42",
		TargetType: "team",
		OrgID:      42,
		TeamID:     84,
		IsActive:   true,
		CreatedBy:  legacyUser.ID,
	}
	managedMembership := &EnterpriseWeComManagedMembership{
		ID:              8201,
		MappingID:       mapping.ID,
		UserID:          legacyUser.ID,
		TargetType:      "team",
		OrgID:           42,
		TeamID:          84,
		LastSeenApplyID: "apply-existing",
	}
	_, err := x.Insert(legacyUser, legacyKey, legacyPAT, legacyGitHTTPToken, identity, orgUser, teamUser, mapping, managedMembership)
	require.NoError(t, err)

	require.NoError(t, AddEnterpriseWeComAutomationStateTables(t.Context(), x))

	for _, table := range []string{
		"wecom_admin_authority",
		"enterprise_wecom_generated_mapping",
		"enterprise_wecom_generated_team",
		"enterprise_wecom_generated_team_admin",
		"enterprise_wecom_reconcile_run",
	} {
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

	mappingAfter := &EnterpriseWeComAuthzMapping{ID: mapping.ID}
	has, err = x.Get(mappingAfter)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, mapping.SourceID, mappingAfter.SourceID)
	require.True(t, mappingAfter.IsActive)

	managedMembershipAfter := &EnterpriseWeComManagedMembership{ID: managedMembership.ID}
	has, err = x.Get(managedMembershipAfter)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, managedMembership.LastSeenApplyID, managedMembershipAfter.LastSeenApplyID)
}
