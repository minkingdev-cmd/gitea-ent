// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"testing"

	"gitea.dev/modelmigration/migrationtest"

	"github.com/stretchr/testify/require"
)

func TestHardenEnterpriseWeComGovernanceConservativeMigration(t *testing.T) {
	x, cleanup := migrationtest.PrepareTestEnv(t, 0, new(EnterpriseWeComAuthzMapping), new(EnterpriseWeComManagedMembership), new(EnterpriseWeComGeneratedTeam), new(EnterpriseWeComGeneratedMapping), new(EnterpriseWeComReconcileRun), new(WeComAdminAuthority), new(governanceAuditEvent), new(governanceLegacyUser), new(governanceLegacyTeamUser))
	defer cleanup()
	if x == nil || t.Failed() {
		return
	}
	for i := int64(1); i <= 4; i++ {
		_, err := x.Insert(&EnterpriseWeComAuthzMapping{CorpID: "corp", SourceType: "department", SourceID: string(rune('0' + i)), TargetType: "team", OrgID: 7, TeamID: i + 10, IsActive: true})
		require.NoError(t, err)
	}
	_, err := x.Insert(&EnterpriseWeComManagedMembership{MappingID: 1, UserID: 2, TargetType: "team", OrgID: 7, TeamID: 11})
	require.NoError(t, err)
	for _, agent := range []string{"app", "other"} {
		for _, source := range []string{"1", "3", "4"} {
			if source != "3" && agent == "other" {
				continue
			}
			teamID := int64(11)
			if source == "3" {
				teamID = 13
			} else if source == "4" {
				teamID = 14
			}
			_, err := x.Insert(&EnterpriseWeComGeneratedTeam{CorpID: "corp", AgentID: agent, SourceType: "department", SourceID: source, OrgID: 7, TeamID: teamID, Status: "applied", RunID: agent + source})
			require.NoError(t, err)
			_, err = x.Insert(&EnterpriseWeComGeneratedMapping{CorpID: "corp", AgentID: agent, SourceType: "department", SourceID: source, TargetType: "team", OrgID: 7, TeamID: teamID, Status: "applied", RunID: agent + source, ErrorMessage: "access_token=secret email=private@example.com"})
			require.NoError(t, err)
			if source == "4" {
				_, err = x.Insert(&EnterpriseWeComGeneratedMapping{CorpID: "corp", AgentID: agent, SourceType: "department", SourceID: source, TargetType: "team", OrgID: 7, TeamID: teamID, Status: "applied", RunID: agent + source})
				require.NoError(t, err)
			}
			_, err = x.Insert(&EnterpriseWeComReconcileRun{CorpID: "corp", AgentID: agent, RunID: agent + source, Trigger: "cron", Status: "success", AddedMemberships: 1, ErrorMessage: "oauth_code=private"})
			require.NoError(t, err)
		}
	}
	_, err = x.Insert(&WeComAdminAuthority{CorpID: "corp", AgentID: "app", WeComUserID: "admin", IsActive: true, IsManagement: true, LastError: "corp_secret=private"}, &governanceAuditEvent{Action: "enterprise:wecom:automation:finish", Metadata: `{"token":"private","error":"private","org_id":7}`, Message: "private"})
	require.NoError(t, err)
	nativeAdmin := &governanceLegacyUser{IsAdmin: true}
	nativeMembership := &governanceLegacyTeamUser{UID: 2, OrgID: 7, TeamID: 11}
	_, err = x.Insert(nativeAdmin, nativeMembership)
	require.NoError(t, err)
	require.NoError(t, HardenEnterpriseWeComGovernance(t.Context(), x))
	require.NoError(t, HardenEnterpriseWeComGovernance(t.Context(), x))
	for _, id := range []int64{1, 2, 3, 4} {
		row := &GovernanceAuthzMapping{ID: id}
		has, err := x.Get(row)
		require.NoError(t, err)
		require.True(t, has)
		if id == 1 {
			require.Equal(t, "generated", row.Origin)
			require.Equal(t, "app", row.AgentID)
		} else {
			require.Equal(t, "legacy", row.Origin)
			require.Empty(t, row.AgentID)
		}
	}
	_, err = x.Insert(&GovernanceAuthzMapping{CorpID: "corp", AgentID: "other", Origin: "generated", SourceType: "department", SourceID: "1", TargetType: "team", OrgID: 7, TeamID: 11})
	require.NoError(t, err)
	member := new(EnterpriseWeComManagedMembership)
	has, err := x.Get(member)
	require.NoError(t, err)
	require.True(t, has)
	require.EqualValues(t, 1, member.MappingID)
	admin := new(WeComAdminAuthority)
	has, err = x.Get(admin)
	require.NoError(t, err)
	require.True(t, has)
	require.True(t, admin.IsActive)
	require.True(t, admin.IsManagement)
	require.Equal(t, "legacy_error_redacted", admin.LastError)
	var runs []GovernanceReconcileRun
	require.NoError(t, x.Find(&runs))
	for _, run := range runs {
		require.Equal(t, 1, run.AddedMemberships)
		require.Equal(t, "success", run.Status)
		require.Equal(t, "legacy_error_redacted", run.ErrorMessage)
	}
	event := new(governanceAuditEvent)
	_, err = x.Get(event)
	require.NoError(t, err)
	require.NotContains(t, event.Metadata, "private")
	require.NotContains(t, event.Message, "private")
	require.Contains(t, event.Metadata, `"org_id":7`)
	storedAdmin := &governanceLegacyUser{ID: nativeAdmin.ID}
	has, err = x.Get(storedAdmin)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, *nativeAdmin, *storedAdmin)
	storedMembership := &governanceLegacyTeamUser{ID: nativeMembership.ID}
	has, err = x.Get(storedMembership)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, *nativeMembership, *storedMembership)
	for _, table := range []string{"enterprise_wecom_callback_receipt", "enterprise_wecom_governance_coordinator"} {
		has, err := x.IsTableExist(table)
		require.NoError(t, err)
		require.True(t, has)
	}
}

type governanceLegacyUser struct {
	ID      int64 `xorm:"pk autoincr"`
	IsAdmin bool
}

func (*governanceLegacyUser) TableName() string { return "user" }

type governanceLegacyTeamUser struct {
	ID     int64 `xorm:"pk autoincr"`
	UID    int64
	OrgID  int64
	TeamID int64
}

func (*governanceLegacyTeamUser) TableName() string { return "team_user" }
