// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"errors"
	"testing"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"

	"github.com/stretchr/testify/require"
)

func TestAutomationAuthorityFailurePreservesProtectedIdentity(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockAutomationSettings(t)
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 1, CorpID: "corp-auto", WeComUserID: "protected-user", LoginSourceID: 1, Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &wecom_model.AdminAuthority{CorpID: "corp-auto", AgentID: "1000002", WeComUserID: "protected-user", IsManagement: true, IsActive: true}))
	before, ok, err := wecom_model.GetIdentityByCorpAndUserID(t.Context(), "corp-auto", "protected-user")
	require.NoError(t, err)
	require.True(t, ok)
	run, err := RunAutomationPipeline(t.Context(), fakeAutomationClient{fakeDirectoryClient: fakeDirectoryClient{departments: []DepartmentInfo{{ID: 42, Name: "Changed"}}, members: map[int64][]MemberInfo{42: {}}}, adminErr: errors.New("secret=do-not-store&access_token=private")}, AutomationRunOptions{RunID: "ops-authority-failure", OrgID: team.OrgID})
	require.Error(t, err)
	require.Equal(t, "failed", run.AuthorityRefreshStatus)
	after, ok, err := wecom_model.GetIdentityByCorpAndUserID(t.Context(), "corp-auto", "protected-user")
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, before.Status, after.Status)
	require.Equal(t, before.SyncVersion, after.SyncVersion)
	protected, err := wecom_model.IsActiveManagementAuthorityBoundUser(t.Context(), "corp-auto", "1000002", 1)
	require.NoError(t, err)
	require.True(t, protected)
	require.NotContains(t, run.ErrorMessage, "do-not-store")
	require.NotContains(t, run.ErrorMessage, "private")
}

func TestAutomationUnsupportedAuthorityDoesNotPublish(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockAutomationSettings(t)
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	run, err := RunAutomationPipeline(t.Context(), fakeAutomationClient{fakeDirectoryClient: fakeDirectoryClient{departments: []DepartmentInfo{{ID: 42, Name: "Changed"}}, members: map[int64][]MemberInfo{42: {}}}, adminErr: ErrWeComAuthorityUnsupported}, AutomationRunOptions{RunID: "ops-unsupported", OrgID: team.OrgID})
	require.Error(t, err)
	require.Equal(t, wecom_model.ReconcileRunStatusFailed, run.Status)
	unittest.AssertNotExistsBean(t, &wecom_model.Department{CorpID: setting.EnterpriseWeCom.CorpID, DepartmentID: 42})
	unittest.AssertNotExistsBean(t, &wecom_model.GeneratedTeam{CorpID: setting.EnterpriseWeCom.CorpID})
}

func TestGeneratedPlannerDoesNotUseOtherAppTeamAdmins(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockMappingSettings(t)
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	require.NoError(t, wecom_model.UpsertDepartment(t.Context(), &wecom_model.Department{CorpID: setting.EnterpriseWeCom.CorpID, DepartmentID: 42, Name: "team"}))
	_, err := createGeneratedMappingForTest(t, AuthzMappingOptions{SourceType: wecom_model.AuthzSourceDepartment, SourceID: "42", TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID})
	require.NoError(t, err)
	seedReconcileUser(t, "other-admin", 1, wecom_model.IdentityStatusActive)
	require.NoError(t, db.Insert(t.Context(), &wecom_model.GeneratedTeamAdmin{CorpID: setting.EnterpriseWeCom.CorpID, AgentID: "other", SourceType: wecom_model.AuthzSourceDepartment, SourceID: "42", TeamID: team.ID, UserID: 1, Status: wecom_model.GeneratedStateApplied}))
	plan, err := PlanAuthzMappings(t.Context(), AuthzReconcileOptions{})
	require.NoError(t, err)
	require.Empty(t, plan.Additions)
}

func TestGeneratedRemovalPreservesOtherMappingOwnership(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockMappingSettings(t)
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	seedReconcileUser(t, "shared-ops", 1, wecom_model.IdentityStatusActive)
	mapping, err := createGeneratedMappingForTest(t, AuthzMappingOptions{SourceType: wecom_model.AuthzSourceUser, SourceID: "shared-ops", TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID})
	require.NoError(t, err)
	_, err = ApplyAuthzMappings(t.Context(), AuthzReconcileOptions{})
	require.NoError(t, err)
	other := &wecom_model.AuthzMapping{CorpID: setting.EnterpriseWeCom.CorpID, AgentID: "other", Origin: wecom_model.AuthzMappingOriginGenerated, SourceType: wecom_model.AuthzSourceUser, SourceID: "shared-ops", TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID, IsActive: true}
	require.NoError(t, db.Insert(t.Context(), other))
	require.NoError(t, db.Insert(t.Context(), &wecom_model.ManagedMembership{MappingID: other.ID, UserID: 1, TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID}))
	require.NoError(t, DisableAuthzMapping(t.Context(), mapping.ID, 1))
	_, err = ApplyAuthzMappings(t.Context(), AuthzReconcileOptions{})
	require.NoError(t, err)
	member, err := organization.IsTeamMember(t.Context(), team.OrgID, team.ID, 1)
	require.NoError(t, err)
	require.True(t, member)
	unittest.AssertNotExistsBean(t, &wecom_model.ManagedMembership{MappingID: mapping.ID})
	unittest.AssertExistsAndLoadBean(t, &wecom_model.ManagedMembership{MappingID: other.ID})
}

func TestGovernanceTargetResolverRequiresExplicitConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name string
		keep []int64
	}{{"zero_organizations", nil}, {"single_organization", []int64{3}}, {"multiple_organizations", []int64{3, 7}}} {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, unittest.PrepareTestDatabase())
			mockAutomationSettings(t)
			setting.EnterpriseWeCom.ManagedOrgID = 0
			engine := db.GetEngine(t.Context()).Where("type = ?", user_model.UserTypeOrganization)
			if len(tt.keep) != 0 {
				engine = engine.NotIn("id", tt.keep)
			}
			_, err := engine.Delete(new(user_model.User))
			require.NoError(t, err)
			count, err := db.GetEngine(t.Context()).Where("type = ?", user_model.UserTypeOrganization).Count(new(user_model.User))
			require.NoError(t, err)
			require.EqualValues(t, len(tt.keep), count)
			for _, override := range []int64{0, 3} {
				orgID, err := resolveGeneratedTargetOrg(t.Context(), override)
				require.Zero(t, orgID)
				requireGovernanceTargetReason(t, err, "managed_org_unconfigured")
			}
		})
	}
}

func TestGovernanceTargetResolverValidatesImmutableID(t *testing.T) {
	for _, name := range []string{"personal_id", "deleted_target", "renamed_target", "override_mismatch"} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, unittest.PrepareTestDatabase())
			mockAutomationSettings(t)
			switch name {
			case "personal_id":
				setting.EnterpriseWeCom.ManagedOrgID = 1
			case "deleted_target":
				_, err := db.GetEngine(t.Context()).ID(setting.EnterpriseWeCom.ManagedOrgID).Delete(new(user_model.User))
				require.NoError(t, err)
			case "renamed_target":
				_, err := db.GetEngine(t.Context()).ID(setting.EnterpriseWeCom.ManagedOrgID).Cols("name", "lower_name").Update(&user_model.User{Name: "RenamedManagedOrg", LowerName: "renamedmanagedorg"})
				require.NoError(t, err)
			}
			override := int64(0)
			if name == "override_mismatch" {
				override = 7
			}
			orgID, err := resolveGeneratedTargetOrg(t.Context(), override)
			switch name {
			case "renamed_target":
				require.NoError(t, err)
				require.Equal(t, setting.EnterpriseWeCom.ManagedOrgID, orgID)
				orgID, err = resolveGeneratedTargetOrg(t.Context(), setting.EnterpriseWeCom.ManagedOrgID)
				require.NoError(t, err)
				require.Equal(t, setting.EnterpriseWeCom.ManagedOrgID, orgID)
			case "override_mismatch":
				require.Zero(t, orgID)
				requireGovernanceTargetReason(t, err, "managed_org_override")
			default:
				require.Zero(t, orgID)
				requireGovernanceTargetReason(t, err, "managed_org_invalid")
			}
		})
	}
}

func TestGovernanceTargetSwitchPreservesPublishedState(t *testing.T) {
	fixture := seedGovernanceFailureBaseline(t)
	before := snapshotGovernanceAuthorization(t)
	beforeAudit := latestGovernanceFailureAuditID(t)
	setting.EnterpriseWeCom.ManagedOrgID = 7
	orgID, err := resolveGeneratedTargetOrg(t.Context(), 0)
	require.Zero(t, orgID)
	requireGovernanceTargetReason(t, err, "managed_org_conflict")
	run, err := RunAutomationPipeline(t.Context(), fixture.candidate, AutomationRunOptions{RunID: "ops-target-switch"})
	assertGovernanceFailurePreserved(t, before, beforeAudit, run, err)
	require.Equal(t, "managed_org_conflict", run.Reason)
}

func requireGovernanceTargetReason(t *testing.T, err error, reason string) {
	t.Helper()
	require.Error(t, err)
	var targetErr *GovernanceError
	require.ErrorAs(t, err, &targetErr)
	require.Equal(t, "preflight", targetErr.Stage)
	require.Equal(t, reason, targetErr.Reason)
}

type governanceContextClient struct {
	fakeAutomationClient
	calls *int
}

func (c governanceContextClient) ListDepartments(context.Context) ([]DepartmentInfo, error) {
	*c.calls++
	return nil, nil
}

func (c governanceContextClient) ListAppAdmins(context.Context) ([]AppAdminInfo, error) {
	*c.calls++
	return nil, nil
}

func TestGovernanceRejectsExternalTransactionContext(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockAutomationSettings(t)
	calls := 0
	client := governanceContextClient{calls: &calls}
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		_, err := RunAutomationPipeline(ctx, client, AutomationRunOptions{})
		require.ErrorContains(t, err, "invalid_publish_context")
		_, err = RefreshAdminAuthoritySnapshot(ctx, client, AdminAuthorityRefreshOptions{})
		require.ErrorContains(t, err, "invalid_publish_context")
		_, err = DeriveGeneratedAuthorizationState(ctx, GeneratedDerivationOptions{})
		require.ErrorContains(t, err, "invalid_publish_context")
		return nil
	}))
	require.Zero(t, calls)
}
