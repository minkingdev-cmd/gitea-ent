// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"testing"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	"gitea.dev/models/unittest"

	"github.com/stretchr/testify/require"
)

func TestPlanAuthzMappingsDryRunDoesNotMutateMembership(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockMappingSettings(t)
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	seedReconcileUser(t, "dept-user", 1, wecom_model.IdentityStatusActive)
	seedDepartmentMembership(t, "dept-user", 100)
	_, err := CreateAuthzMapping(t.Context(), AuthzMappingOptions{SourceType: wecom_model.AuthzSourceDepartment, SourceID: "100", TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID, ActorID: 1})
	require.NoError(t, err)

	result, err := PlanAuthzMappings(t.Context(), AuthzReconcileOptions{})
	require.NoError(t, err)
	require.Len(t, result.Additions, 1)
	require.Empty(t, result.Removals)
	require.Empty(t, result.Errors)

	isMember, err := organization.IsTeamMember(t.Context(), team.OrgID, team.ID, 1)
	require.NoError(t, err)
	require.False(t, isMember)
}

func TestApplyAuthzMappingsAddsTeamMembershipAndIsIdempotent(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockMappingSettings(t)
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	seedReconcileUser(t, "team-user", 1, wecom_model.IdentityStatusActive)
	_, err := CreateAuthzMapping(t.Context(), AuthzMappingOptions{SourceType: wecom_model.AuthzSourceUser, SourceID: "team-user", TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID, ActorID: 1})
	require.NoError(t, err)

	result, err := ApplyAuthzMappings(t.Context(), AuthzReconcileOptions{ActorID: 1, ApplyID: "apply-1"})
	require.NoError(t, err)
	require.Len(t, result.Additions, 1)
	isMember, err := organization.IsTeamMember(t.Context(), team.OrgID, team.ID, 1)
	require.NoError(t, err)
	require.True(t, isMember)

	managedCount, err := db.GetEngine(t.Context()).Count(new(wecom_model.ManagedMembership))
	require.NoError(t, err)
	require.Equal(t, int64(1), managedCount)

	result, err = ApplyAuthzMappings(t.Context(), AuthzReconcileOptions{ActorID: 1, ApplyID: "apply-2"})
	require.NoError(t, err)
	require.Empty(t, result.Additions)
	require.Empty(t, result.Removals)
	managedCount, err = db.GetEngine(t.Context()).Count(new(wecom_model.ManagedMembership))
	require.NoError(t, err)
	require.Equal(t, int64(1), managedCount)
}

func TestApplyAuthzMappingsAddsOrgMembershipConservatively(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockMappingSettings(t)
	seedReconcileUser(t, "org-user", 1, wecom_model.IdentityStatusActive)
	_, err := CreateAuthzMapping(t.Context(), AuthzMappingOptions{SourceType: wecom_model.AuthzSourceUser, SourceID: "org-user", TargetType: wecom_model.AuthzTargetOrg, OrgID: 7, ActorID: 1})
	require.NoError(t, err)

	result, err := ApplyAuthzMappings(t.Context(), AuthzReconcileOptions{ActorID: 1, ApplyID: "apply-org"})
	require.NoError(t, err)
	require.Len(t, result.Additions, 1)
	isMember, err := organization.IsOrganizationMember(t.Context(), 7, 1)
	require.NoError(t, err)
	require.True(t, isMember)
}

func TestApplyAuthzMappingsSkipsInactiveOutOfScopeAndUnboundIdentities(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockMappingSettings(t)
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	seedReconcileUser(t, "inactive-user", 1, wecom_model.IdentityStatusInactive)
	seedReconcileUser(t, "out-user", 31, wecom_model.IdentityStatusOutOfScope)
	_, _, err := wecom_model.UpsertIdentitySnapshot(t.Context(), wecom_model.BindIdentityOptions{CorpID: "corp-map", WeComUserID: "unbound-user", Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	for _, userID := range []string{"inactive-user", "out-user", "unbound-user"} {
		_, err := CreateAuthzMapping(t.Context(), AuthzMappingOptions{SourceType: wecom_model.AuthzSourceUser, SourceID: userID, TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID, ActorID: 1})
		require.NoError(t, err)
	}

	result, err := PlanAuthzMappings(t.Context(), AuthzReconcileOptions{})
	require.NoError(t, err)
	require.Empty(t, result.Additions)
	require.Len(t, result.Skipped, 3)
}

func TestApplyAuthzMappingsRemovesStaleManagedMembershipAndPreservesManualMembership(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockMappingSettings(t)
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	seedReconcileUser(t, "mapped-user", 1, wecom_model.IdentityStatusActive)
	mapping, err := CreateAuthzMapping(t.Context(), AuthzMappingOptions{SourceType: wecom_model.AuthzSourceUser, SourceID: "mapped-user", TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID, ActorID: 1})
	require.NoError(t, err)
	_, err = ApplyAuthzMappings(t.Context(), AuthzReconcileOptions{ActorID: 1, ApplyID: "initial"})
	require.NoError(t, err)

	_, _, err = wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 1, CorpID: "corp-map", WeComUserID: "mapped-user", LoginSourceID: 1, Status: wecom_model.IdentityStatusOutOfScope})
	require.NoError(t, err)
	result, err := ApplyAuthzMappings(t.Context(), AuthzReconcileOptions{ActorID: 1, ApplyID: "stale"})
	require.NoError(t, err)
	require.Len(t, result.Removals, 1)
	isMember, err := organization.IsTeamMember(t.Context(), team.OrgID, team.ID, 1)
	require.NoError(t, err)
	require.False(t, isMember)
	managed := &wecom_model.ManagedMembership{MappingID: mapping.ID, UserID: 1, TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID}
	has, err := db.GetEngine(t.Context()).Get(managed)
	require.NoError(t, err)
	require.False(t, has)

	seedReconcileUser(t, "manual-user", 4, wecom_model.IdentityStatusActive)
	_, err = CreateAuthzMapping(t.Context(), AuthzMappingOptions{SourceType: wecom_model.AuthzSourceUser, SourceID: "manual-user", TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID, ActorID: 1})
	require.NoError(t, err)
	_, err = ApplyAuthzMappings(t.Context(), AuthzReconcileOptions{ActorID: 1, ApplyID: "manual"})
	require.NoError(t, err)
	_, _, err = wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 4, CorpID: "corp-map", WeComUserID: "manual-user", LoginSourceID: 1, Status: wecom_model.IdentityStatusOutOfScope})
	require.NoError(t, err)
	_, err = ApplyAuthzMappings(t.Context(), AuthzReconcileOptions{ActorID: 1, ApplyID: "manual-stale"})
	require.NoError(t, err)
	isMember, err = organization.IsTeamMember(t.Context(), team.OrgID, team.ID, 4)
	require.NoError(t, err)
	require.True(t, isMember)
}

func TestApplyAuthzMappingsPreservesSharedManagedMembership(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockMappingSettings(t)
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	seedReconcileUser(t, "shared-user", 1, wecom_model.IdentityStatusActive)
	seedTagMembership(t, "shared-user", 8)
	first, err := CreateAuthzMapping(t.Context(), AuthzMappingOptions{SourceType: wecom_model.AuthzSourceUser, SourceID: "shared-user", TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID, ActorID: 1})
	require.NoError(t, err)
	_, err = CreateAuthzMapping(t.Context(), AuthzMappingOptions{SourceType: wecom_model.AuthzSourceTag, SourceID: "8", TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID, ActorID: 1})
	require.NoError(t, err)
	_, err = ApplyAuthzMappings(t.Context(), AuthzReconcileOptions{ActorID: 1, ApplyID: "shared-initial"})
	require.NoError(t, err)
	require.NoError(t, DisableAuthzMapping(t.Context(), first.ID, 1))

	result, err := ApplyAuthzMappings(t.Context(), AuthzReconcileOptions{ActorID: 1, ApplyID: "shared-second"})
	require.NoError(t, err)
	require.Empty(t, result.Removals)
	isMember, err := organization.IsTeamMember(t.Context(), team.OrgID, team.ID, 1)
	require.NoError(t, err)
	require.True(t, isMember)
}

func TestApplyAuthzMappingsDoesNotCommitPartialResultsWhenPlanHasErrors(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockMappingSettings(t)
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	seedReconcileUser(t, "valid-user", 1, wecom_model.IdentityStatusActive)
	_, err := CreateAuthzMapping(t.Context(), AuthzMappingOptions{SourceType: wecom_model.AuthzSourceUser, SourceID: "valid-user", TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID, ActorID: 1})
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &wecom_model.AuthzMapping{CorpID: "corp-map", SourceType: wecom_model.AuthzSourceUser, SourceID: "valid-user", TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: 999999, IsActive: true}))

	_, err = ApplyAuthzMappings(t.Context(), AuthzReconcileOptions{ActorID: 1, ApplyID: "broken"})
	require.ErrorIs(t, err, ErrInvalidAuthzMapping)
	isMember, err := organization.IsTeamMember(t.Context(), team.OrgID, team.ID, 1)
	require.NoError(t, err)
	require.False(t, isMember)
}

func seedReconcileUser(t *testing.T, wecomUserID string, userID int64, status wecom_model.IdentityStatus) {
	t.Helper()
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: userID, CorpID: "corp-map", WeComUserID: wecomUserID, LoginSourceID: 1, Status: status})
	require.NoError(t, err)
}

func seedDepartmentMembership(t *testing.T, wecomUserID string, departmentID int64) {
	t.Helper()
	require.NoError(t, wecom_model.UpsertDepartment(t.Context(), &wecom_model.Department{CorpID: "corp-map", DepartmentID: departmentID, Name: "Department"}))
	require.NoError(t, wecom_model.UpsertMembership(t.Context(), &wecom_model.Membership{CorpID: "corp-map", WeComUserID: wecomUserID, Kind: wecom_model.MembershipDepartment, TargetID: departmentID}))
}

func seedTagMembership(t *testing.T, wecomUserID string, tagID int64) {
	t.Helper()
	require.NoError(t, wecom_model.UpsertTag(t.Context(), &wecom_model.Tag{CorpID: "corp-map", TagID: tagID, Name: "Tag"}))
	require.NoError(t, wecom_model.UpsertMembership(t.Context(), &wecom_model.Membership{CorpID: "corp-map", WeComUserID: wecomUserID, Kind: wecom_model.MembershipTag, TargetID: tagID}))
}
