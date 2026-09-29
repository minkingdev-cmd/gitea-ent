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

func mockTeamGovernanceSettings(t *testing.T) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:    true,
		CorpID:     "corp-team-gov",
		AgentID:    "1000002",
		CorpSecret: "secret",
	}))
}

func TestReconcileGeneratedTeamsCreatesMissingDepartmentTeamAndMembership(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockTeamGovernanceSettings(t)
	baseTeam := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	teamName := generatedTeamName("dept", "Platform", 900)
	unittest.AssertNotExistsBean(t, &organization.Team{OrgID: baseTeam.OrgID, LowerName: teamName})

	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 2, CorpID: "corp-team-gov", WeComUserID: "platform.member", LoginSourceID: 1, Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	require.NoError(t, wecom_model.UpsertDepartment(t.Context(), &wecom_model.Department{CorpID: "corp-team-gov", DepartmentID: 900, Name: "Platform", LeaderUserIDs: wecom_model.EncodeLeaderUserIDs([]string{"platform.member"})}))
	require.NoError(t, wecom_model.UpsertMembership(t.Context(), &wecom_model.Membership{CorpID: "corp-team-gov", WeComUserID: "platform.member", Kind: wecom_model.MembershipDepartment, TargetID: 900, IsLeader: true}))

	_, err = DeriveGeneratedAuthorizationState(t.Context(), GeneratedDerivationOptions{OrgID: baseTeam.OrgID, RunID: "team-gov-run", Now: timeutil.TimeStamp(1780000000)})
	require.NoError(t, err)
	result, err := ReconcileGeneratedTeams(t.Context(), GeneratedTeamReconcileOptions{RunID: "team-gov-run"})
	require.NoError(t, err)
	require.Equal(t, 1, result.CreatedTeams)
	require.Equal(t, 1, result.AddedMemberships)
	require.Equal(t, 1, result.GeneratedTeamAdmins)

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{OrgID: baseTeam.OrgID, LowerName: teamName})
	isMember, err := organization.IsTeamMember(t.Context(), team.OrgID, team.ID, 2)
	require.NoError(t, err)
	require.True(t, isMember)

	var generatedTeam wecom_model.GeneratedTeam
	has, err := db.GetEngine(t.Context()).Where("corp_id = ? AND source_type = ? AND source_id = ?", "corp-team-gov", wecom_model.AuthzSourceDepartment, "900").Get(&generatedTeam)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, team.ID, generatedTeam.TeamID)
	require.Equal(t, wecom_model.GeneratedStateApplied, generatedTeam.Status)
	require.Equal(t, wecom_model.GeneratedStateApplied, generatedTeam.AdminStatus)

	var mapping wecom_model.AuthzMapping
	has, err = db.GetEngine(t.Context()).Where("corp_id = ? AND source_type = ? AND source_id = ? AND target_type = ?", "corp-team-gov", wecom_model.AuthzSourceDepartment, "900", wecom_model.AuthzTargetTeam).Get(&mapping)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, team.ID, mapping.TeamID)
}

func TestReconcileGeneratedTeamsCreatesMissingTagTeamAndMembership(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockTeamGovernanceSettings(t)
	baseTeam := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	teamName := generatedTeamName("tag", "Reviewers", 990)
	unittest.AssertNotExistsBean(t, &organization.Team{OrgID: baseTeam.OrgID, LowerName: teamName})

	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 4, CorpID: "corp-team-gov", WeComUserID: "review.member", LoginSourceID: 1, Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	require.NoError(t, wecom_model.UpsertTag(t.Context(), &wecom_model.Tag{CorpID: "corp-team-gov", TagID: 990, Name: "Reviewers"}))
	require.NoError(t, wecom_model.UpsertMembership(t.Context(), &wecom_model.Membership{CorpID: "corp-team-gov", WeComUserID: "review.member", Kind: wecom_model.MembershipTag, TargetID: 990}))

	_, err = DeriveGeneratedAuthorizationState(t.Context(), GeneratedDerivationOptions{OrgID: baseTeam.OrgID, RunID: "team-gov-tag"})
	require.NoError(t, err)
	result, err := ReconcileGeneratedTeams(t.Context(), GeneratedTeamReconcileOptions{RunID: "team-gov-tag"})
	require.NoError(t, err)
	require.Equal(t, 1, result.CreatedTeams)
	require.Equal(t, 1, result.AddedMemberships)
	require.Equal(t, 1, result.UnresolvedAdmins)

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{OrgID: baseTeam.OrgID, LowerName: teamName})
	isMember, err := organization.IsTeamMember(t.Context(), team.OrgID, team.ID, 4)
	require.NoError(t, err)
	require.True(t, isMember)

	generatedTeam := unittest.AssertExistsAndLoadBean(t, &wecom_model.GeneratedTeam{CorpID: "corp-team-gov", SourceType: wecom_model.AuthzSourceTag, SourceID: "990"})
	require.Equal(t, wecom_model.GeneratedStateUnresolved, generatedTeam.AdminStatus)
	require.Equal(t, "tag_has_no_admin_metadata", generatedTeam.UnresolvedReason)
}

func TestReconcileGeneratedTeamsIsIdempotentAndSkipsAmbiguousTargets(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockTeamGovernanceSettings(t)
	baseTeam := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	teamName := generatedTeamName("dept", "Ambiguous", 901)
	require.NoError(t, db.Insert(t.Context(),
		&organization.Team{OrgID: baseTeam.OrgID, Name: teamName, LowerName: teamName},
		&organization.Team{OrgID: baseTeam.OrgID, Name: teamName, LowerName: teamName},
	))
	require.NoError(t, wecom_model.UpsertDepartment(t.Context(), &wecom_model.Department{CorpID: "corp-team-gov", DepartmentID: 901, Name: "Ambiguous"}))

	_, err := DeriveGeneratedAuthorizationState(t.Context(), GeneratedDerivationOptions{OrgID: baseTeam.OrgID, RunID: "team-gov-ambiguous"})
	require.NoError(t, err)
	result, err := ReconcileGeneratedTeams(t.Context(), GeneratedTeamReconcileOptions{RunID: "team-gov-ambiguous"})
	require.NoError(t, err)
	require.Zero(t, result.CreatedTeams)
	require.Equal(t, 1, result.Skipped)

	result, err = ReconcileGeneratedTeams(t.Context(), GeneratedTeamReconcileOptions{RunID: "team-gov-ambiguous"})
	require.NoError(t, err)
	require.Zero(t, result.CreatedTeams)
}

func TestReconcileGeneratedTeamsRemovesStaleGeneratedMembership(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockTeamGovernanceSettings(t)
	baseTeam := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})

	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 2, CorpID: "corp-team-gov", WeComUserID: "stale.member", LoginSourceID: 1, Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	require.NoError(t, wecom_model.UpsertDepartment(t.Context(), &wecom_model.Department{CorpID: "corp-team-gov", DepartmentID: 902, Name: "Stale", LeaderUserIDs: wecom_model.EncodeLeaderUserIDs([]string{"stale.member"})}))
	require.NoError(t, wecom_model.UpsertMembership(t.Context(), &wecom_model.Membership{CorpID: "corp-team-gov", WeComUserID: "stale.member", Kind: wecom_model.MembershipDepartment, TargetID: 902, IsLeader: true}))

	_, err = DeriveGeneratedAuthorizationState(t.Context(), GeneratedDerivationOptions{OrgID: baseTeam.OrgID, RunID: "team-gov-stale-1"})
	require.NoError(t, err)
	_, err = ReconcileGeneratedTeams(t.Context(), GeneratedTeamReconcileOptions{RunID: "team-gov-stale-1"})
	require.NoError(t, err)

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{OrgID: baseTeam.OrgID, LowerName: generatedTeamName("dept", "Stale", 902)})
	isMember, err := organization.IsTeamMember(t.Context(), team.OrgID, team.ID, 2)
	require.NoError(t, err)
	require.True(t, isMember)

	_, err = db.GetEngine(t.Context()).Where("corp_id = ? AND kind = ? AND target_id = ?", "corp-team-gov", wecom_model.MembershipDepartment, 902).Delete(new(wecom_model.Membership))
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Where("corp_id = ? AND department_id = ?", "corp-team-gov", 902).Delete(new(wecom_model.Department))
	require.NoError(t, err)

	_, err = DeriveGeneratedAuthorizationState(t.Context(), GeneratedDerivationOptions{OrgID: baseTeam.OrgID, RunID: "team-gov-stale-2"})
	require.NoError(t, err)
	result, err := ReconcileGeneratedTeams(t.Context(), GeneratedTeamReconcileOptions{RunID: "team-gov-stale-2"})
	require.NoError(t, err)
	require.Equal(t, 1, result.RemovedMemberships)

	isMember, err = organization.IsTeamMember(t.Context(), team.OrgID, team.ID, 2)
	require.NoError(t, err)
	require.False(t, isMember)

	mapping := unittest.AssertExistsAndLoadBean(t, &wecom_model.AuthzMapping{CorpID: "corp-team-gov", SourceType: wecom_model.AuthzSourceDepartment, SourceID: "902", TargetType: wecom_model.AuthzTargetTeam})
	require.False(t, mapping.IsActive)
}

func TestReconcileGeneratedTeamsGrantsAndRemovesDepartmentLeaderAdminMembership(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockTeamGovernanceSettings(t)
	baseTeam := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})

	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 5, CorpID: "corp-team-gov", WeComUserID: "dept.leader", LoginSourceID: 1, Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	require.NoError(t, wecom_model.UpsertDepartment(t.Context(), &wecom_model.Department{CorpID: "corp-team-gov", DepartmentID: 903, Name: "LeaderOnly", LeaderUserIDs: wecom_model.EncodeLeaderUserIDs([]string{"dept.leader"})}))

	_, err = DeriveGeneratedAuthorizationState(t.Context(), GeneratedDerivationOptions{OrgID: baseTeam.OrgID, RunID: "team-gov-leader-1"})
	require.NoError(t, err)
	result, err := ReconcileGeneratedTeams(t.Context(), GeneratedTeamReconcileOptions{RunID: "team-gov-leader-1"})
	require.NoError(t, err)
	require.Equal(t, 1, result.GeneratedTeamAdmins)
	require.Equal(t, 1, result.AddedMemberships)

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{OrgID: baseTeam.OrgID, LowerName: generatedTeamName("dept", "LeaderOnly", 903)})
	isMember, err := organization.IsTeamMember(t.Context(), team.OrgID, team.ID, 5)
	require.NoError(t, err)
	require.True(t, isMember)

	admin := unittest.AssertExistsAndLoadBean(t, &wecom_model.GeneratedTeamAdmin{CorpID: "corp-team-gov", SourceType: wecom_model.AuthzSourceDepartment, SourceID: "903", UserID: 5})
	require.Equal(t, wecom_model.GeneratedStateApplied, admin.Status)
	require.Equal(t, team.ID, admin.TeamID)

	require.NoError(t, wecom_model.UpsertDepartment(t.Context(), &wecom_model.Department{CorpID: "corp-team-gov", DepartmentID: 903, Name: "LeaderOnly"}))
	_, err = DeriveGeneratedAuthorizationState(t.Context(), GeneratedDerivationOptions{OrgID: baseTeam.OrgID, RunID: "team-gov-leader-2"})
	require.NoError(t, err)
	result, err = ReconcileGeneratedTeams(t.Context(), GeneratedTeamReconcileOptions{RunID: "team-gov-leader-2"})
	require.NoError(t, err)
	require.Equal(t, 1, result.UnresolvedAdmins)
	require.Equal(t, 1, result.RemovedMemberships)

	isMember, err = organization.IsTeamMember(t.Context(), team.OrgID, team.ID, 5)
	require.NoError(t, err)
	require.False(t, isMember)

	admin = unittest.AssertExistsAndLoadBean(t, &wecom_model.GeneratedTeamAdmin{CorpID: "corp-team-gov", SourceType: wecom_model.AuthzSourceDepartment, SourceID: "903", UserID: 5})
	require.Equal(t, wecom_model.GeneratedStateSkipped, admin.Status)
	require.Equal(t, "admin_metadata_removed", admin.Reason)
}

func TestCanLocallyMaintainGeneratedTeam(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})

	require.NoError(t, CanLocallyMaintainTeam(t.Context(), 0, TeamLocalMaintenanceCreate))

	mockTeamGovernanceSettings(t)
	require.ErrorIs(t, CanLocallyMaintainTeam(t.Context(), 0, TeamLocalMaintenanceCreate), ErrManagedTeamLocalMaintenanceDenied)
	require.NoError(t, CanLocallyMaintainTeam(t.Context(), team.ID, TeamLocalMaintenanceEdit))

	require.NoError(t, db.Insert(t.Context(), &wecom_model.GeneratedTeam{
		CorpID:     "corp-team-gov",
		AgentID:    "1000002",
		SourceType: wecom_model.AuthzSourceDepartment,
		SourceID:   "local-deny",
		OrgID:      team.OrgID,
		TeamID:     team.ID,
		TeamName:   team.Name,
		Status:     wecom_model.GeneratedStateApplied,
	}))
	require.ErrorIs(t, CanLocallyMaintainTeam(t.Context(), team.ID, TeamLocalMaintenanceEdit), ErrManagedTeamLocalMaintenanceDenied)
}
