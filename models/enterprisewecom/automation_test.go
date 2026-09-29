// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"testing"

	"gitea.dev/models/db"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/timeutil"

	"github.com/stretchr/testify/require"
)

func TestAutomationStateModelsPersistAuthorityGeneratedStateAndRuns(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	authority := &AdminAuthority{
		CorpID:          "corp-1",
		AgentID:         "1000002",
		WeComUserID:     "zhang.super",
		OpenUserID:      "open-zhang",
		AuthType:        AdminAuthorityAuthTypeManagement,
		IsManagement:    true,
		IsActive:        true,
		RefreshID:       "refresh-1",
		RefreshTrigger:  "cron",
		LastRefreshUnix: timeutil.TimeStamp(1780000000),
		LastSeenUnix:    timeutil.TimeStamp(1780000000),
	}
	require.NoError(t, db.Insert(t.Context(), authority))
	require.NotZero(t, authority.ID)

	run := &ReconcileRun{
		RunID:                  "sync-20260929-1620",
		CorpID:                 "corp-1",
		AgentID:                "1000002",
		Trigger:                "cron",
		Status:                 ReconcileRunStatusSuccess,
		DirectorySyncStatus:    "success",
		AuthorityRefreshStatus: "success",
		GeneratedMappings:      1,
		GeneratedTeams:         1,
		AddedMemberships:       2,
		ProtectedCount:         1,
	}
	require.NoError(t, db.Insert(t.Context(), run))

	generatedMapping := &GeneratedMapping{
		RunID:          run.RunID,
		CorpID:         "corp-1",
		AgentID:        "1000002",
		SourceType:     AuthzSourceDepartment,
		SourceID:       "42",
		SourceName:     "研发中心 / 后端组",
		TargetType:     AuthzTargetTeam,
		OrgID:          3,
		TeamID:         5,
		DerivationRule: "department_path_to_team",
		Status:         GeneratedStateApplied,
		MemberCount:    14,
		AdminCount:     1,
	}
	require.NoError(t, db.Insert(t.Context(), generatedMapping))

	generatedTeam := &GeneratedTeam{
		RunID:          run.RunID,
		CorpID:         "corp-1",
		AgentID:        "1000002",
		SourceType:     AuthzSourceDepartment,
		SourceID:       "42",
		SourceName:     "研发中心 / 后端组",
		OrgID:          3,
		TeamID:         5,
		TeamName:       "backend",
		DerivationRule: "department_path_to_team",
		Status:         GeneratedStateApplied,
		AdminStatus:    GeneratedStateApplied,
		MemberCount:    14,
		AdminCount:     1,
	}
	require.NoError(t, db.Insert(t.Context(), generatedTeam))

	generatedTeamAdmin := &GeneratedTeamAdmin{
		RunID:       run.RunID,
		CorpID:      "corp-1",
		AgentID:     "1000002",
		SourceType:  AuthzSourceDepartment,
		SourceID:    "42",
		TeamID:      5,
		UserID:      2,
		WeComUserID: "zhang.super",
		AdminSource: "department_leader",
		Status:      GeneratedStateApplied,
	}
	require.NoError(t, db.Insert(t.Context(), generatedTeamAdmin))

	storedAuthority := &AdminAuthority{CorpID: "corp-1", AgentID: "1000002", WeComUserID: "zhang.super"}
	has, err := db.GetEngine(t.Context()).Get(storedAuthority)
	require.NoError(t, err)
	require.True(t, has)
	require.True(t, storedAuthority.IsManagement)

	var generatedTeams []GeneratedTeam
	require.NoError(t, db.GetEngine(t.Context()).Where("run_id = ?", run.RunID).Find(&generatedTeams))
	require.Len(t, generatedTeams, 1)
	require.Equal(t, GeneratedStateApplied, generatedTeams[0].AdminStatus)

	var generatedAdmins []GeneratedTeamAdmin
	require.NoError(t, db.GetEngine(t.Context()).Where("team_id = ?", int64(5)).Find(&generatedAdmins))
	require.Len(t, generatedAdmins, 1)
	require.Equal(t, "department_leader", generatedAdmins[0].AdminSource)

	var runs []ReconcileRun
	require.NoError(t, db.GetEngine(t.Context()).Where("corp_id = ?", "corp-1").Find(&runs))
	require.Len(t, runs, 1)
	require.Equal(t, 1, runs[0].ProtectedCount)
}
