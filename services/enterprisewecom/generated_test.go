// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"testing"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/timeutil"

	"github.com/stretchr/testify/require"
)

func mockGeneratedSettings(t *testing.T) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:    true,
		CorpID:     "corp-generated",
		AgentID:    "1000002",
		CorpSecret: "secret",
	}))
}

func TestDeriveGeneratedAuthorizationStateFromDepartmentsTagsAndWeComLeaders(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockGeneratedSettings(t)

	baseTeam := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	deptTeamName := generatedTeamName("dept", "Backend", 42)
	require.NoError(t, db.Insert(t.Context(), &organization.Team{OrgID: baseTeam.OrgID, Name: deptTeamName, LowerName: deptTeamName}))

	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 1, CorpID: "corp-generated", WeComUserID: "leader.department", LoginSourceID: 1, Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	_, _, err = wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 2, CorpID: "corp-generated", WeComUserID: "leader.member", LoginSourceID: 1, Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	require.NoError(t, wecom_model.UpsertDepartment(t.Context(), &wecom_model.Department{CorpID: "corp-generated", DepartmentID: 42, Name: "Backend", LeaderUserIDs: wecom_model.EncodeLeaderUserIDs([]string{"leader.department"})}))
	require.NoError(t, wecom_model.UpsertMembership(t.Context(), &wecom_model.Membership{CorpID: "corp-generated", WeComUserID: "leader.department", Kind: wecom_model.MembershipDepartment, TargetID: 42}))
	require.NoError(t, wecom_model.UpsertMembership(t.Context(), &wecom_model.Membership{CorpID: "corp-generated", WeComUserID: "leader.member", Kind: wecom_model.MembershipDepartment, TargetID: 42, IsLeader: true}))
	require.NoError(t, wecom_model.UpsertTag(t.Context(), &wecom_model.Tag{CorpID: "corp-generated", TagID: 8, Name: "Reviewers"}))
	require.NoError(t, wecom_model.UpsertMembership(t.Context(), &wecom_model.Membership{CorpID: "corp-generated", WeComUserID: "leader.department", Kind: wecom_model.MembershipTag, TargetID: 8}))

	result, err := DeriveGeneratedAuthorizationState(t.Context(), GeneratedDerivationOptions{OrgID: baseTeam.OrgID, RunID: "generated-run", Now: timeutil.TimeStamp(1780000000)})
	require.NoError(t, err)
	require.Equal(t, "generated-run", result.RunID)
	require.Equal(t, 2, result.GeneratedMappings)
	require.Equal(t, 2, result.GeneratedTeams)
	require.Equal(t, 2, result.GeneratedTeamAdmins)
	require.Equal(t, 1, result.Skipped)
	require.Equal(t, 1, result.UnresolvedAdmins)

	var deptTeam wecom_model.GeneratedTeam
	has, err := db.GetEngine(t.Context()).Where("corp_id = ? AND source_type = ? AND source_id = ?", "corp-generated", wecom_model.AuthzSourceDepartment, "42").Get(&deptTeam)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, wecom_model.GeneratedStateApplied, deptTeam.Status)
	require.Equal(t, wecom_model.GeneratedStateApplied, deptTeam.AdminStatus)
	require.Equal(t, 2, deptTeam.AdminCount)

	var admins []wecom_model.GeneratedTeamAdmin
	require.NoError(t, db.GetEngine(t.Context()).Where("team_id = ?", deptTeam.TeamID).Find(&admins))
	require.Len(t, admins, 2)

	var tagTeam wecom_model.GeneratedTeam
	has, err = db.GetEngine(t.Context()).Where("corp_id = ? AND source_type = ? AND source_id = ?", "corp-generated", wecom_model.AuthzSourceTag, "8").Get(&tagTeam)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, wecom_model.GeneratedStateSkipped, tagTeam.Status)
	require.Equal(t, wecom_model.GeneratedStateUnresolved, tagTeam.AdminStatus)
	require.Equal(t, "tag_has_no_admin_metadata", tagTeam.UnresolvedReason)

	var skippedMapping wecom_model.GeneratedMapping
	has, err = db.GetEngine(t.Context()).Where("corp_id = ? AND source_type = ? AND source_id = ?", "corp-generated", wecom_model.AuthzSourceTag, "8").Get(&skippedMapping)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, wecom_model.GeneratedStateSkipped, skippedMapping.Status)
	require.Equal(t, "missing_team", skippedMapping.SkipReason)
}

func TestDeriveGeneratedAuthorizationStateRecordsUnresolvedDepartmentAdminMetadata(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockGeneratedSettings(t)

	baseTeam := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	deptTeamName := generatedTeamName("dept", "QA", 43)
	require.NoError(t, db.Insert(t.Context(), &organization.Team{OrgID: baseTeam.OrgID, Name: deptTeamName, LowerName: deptTeamName}))
	require.NoError(t, wecom_model.UpsertDepartment(t.Context(), &wecom_model.Department{CorpID: "corp-generated", DepartmentID: 43, Name: "QA"}))
	require.NoError(t, wecom_model.UpsertMembership(t.Context(), &wecom_model.Membership{CorpID: "corp-generated", WeComUserID: "qa.member", Kind: wecom_model.MembershipDepartment, TargetID: 43}))

	result, err := DeriveGeneratedAuthorizationState(t.Context(), GeneratedDerivationOptions{OrgID: baseTeam.OrgID, RunID: "generated-run-unresolved"})
	require.NoError(t, err)
	require.Equal(t, 1, result.UnresolvedAdmins)

	var deptTeam wecom_model.GeneratedTeam
	has, err := db.GetEngine(t.Context()).Where("corp_id = ? AND source_type = ? AND source_id = ?", "corp-generated", wecom_model.AuthzSourceDepartment, "43").Get(&deptTeam)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, wecom_model.GeneratedStateApplied, deptTeam.Status)
	require.Equal(t, wecom_model.GeneratedStateUnresolved, deptTeam.AdminStatus)
	require.Equal(t, "no_admin_metadata", deptTeam.UnresolvedReason)
}

func TestDeriveGeneratedAuthorizationStateSkipsAmbiguousGeneratedTeamTarget(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockGeneratedSettings(t)

	baseTeam := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	deptTeamName := generatedTeamName("dept", "Ambiguous", 44)
	require.NoError(t, db.Insert(t.Context(),
		&organization.Team{OrgID: baseTeam.OrgID, Name: deptTeamName, LowerName: deptTeamName},
		&organization.Team{OrgID: baseTeam.OrgID, Name: deptTeamName, LowerName: deptTeamName},
	))
	require.NoError(t, wecom_model.UpsertDepartment(t.Context(), &wecom_model.Department{CorpID: "corp-generated", DepartmentID: 44, Name: "Ambiguous"}))

	result, err := DeriveGeneratedAuthorizationState(t.Context(), GeneratedDerivationOptions{OrgID: baseTeam.OrgID, RunID: "generated-run-ambiguous"})
	require.NoError(t, err)
	require.Equal(t, 1, result.Skipped)

	var mapping wecom_model.GeneratedMapping
	has, err := db.GetEngine(t.Context()).Where("corp_id = ? AND source_type = ? AND source_id = ?", "corp-generated", wecom_model.AuthzSourceDepartment, "44").Get(&mapping)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, wecom_model.GeneratedStateSkipped, mapping.Status)
	require.Equal(t, "ambiguous_team", mapping.SkipReason)
}
