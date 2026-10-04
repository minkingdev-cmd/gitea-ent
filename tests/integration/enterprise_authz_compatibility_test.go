// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"maps"
	"slices"
	"testing"

	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
)

func authzNativeCompatibility(t *testing.T, cases map[string]func(*testing.T)) {
	t.Helper()
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("shadow_%t", enabled), func(t *testing.T) {
			defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, enabled)()
			defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
			for _, name := range slices.Sorted(maps.Keys(cases)) {
				t.Run(name, cases[name])
			}
		})
	}
}

func TestEnterpriseAuthzLoginOnlyCompatibility(t *testing.T) {
	authzNativeCompatibility(t, map[string]func(*testing.T){
		"login_only": TestEnterpriseWeComLoginOnlyIntegration,
		"smoke":      TestEnterpriseWeComLoginOnlySmoke,
	})
}

func TestEnterpriseAuthzCredentialCompatibility(t *testing.T) {
	authzNativeCompatibility(t, map[string]func(*testing.T){
		"token_account_states": TestEnterpriseWeComNativeCredentialAccountStateParity,
		"ssh_account_states":   TestEnterpriseWeComNativeSSHAccountStateParity,
	})
}

func TestEnterpriseAuthzGovernanceCompatibility(t *testing.T) {
	authzNativeCompatibility(t, map[string]func(*testing.T){
		"api_admin_protection":  TestAPIProtectedWeComAdminMutationDeniedForOtherSiteAdmin,
		"api_admin_self":        TestAPIProtectedWeComAdminSelfUpdateBoundaries,
		"web_admin_protection":  TestWebProtectedWeComAdminMutationDeniedForOtherSiteAdmin,
		"web_admin_self":        TestWebProtectedWeComAdminSelfUpdateBoundaries,
		"read_only_ui":          TestEnterpriseWeComAdminUIReadOnlyVisibility,
		"repository_governance": TestAPIEnterpriseWeComRepositoryGovernance,
		"personal_quota":        TestEnterprisePersonalRepoWebQuota,
		"managed_team":          TestAPIEnterpriseWeComManagedTeamLocalMaintenanceDenied,
		"approval_form":         TestEnterpriseWeComOrganizationRepositoryRequestFromCreateForm,
		"nonmember_approval":    TestEnterpriseWeComOrganizationRepositoryRequestAvailableToNonOrgMember,
		"create_entry":          TestEnterpriseWeComOrganizationCreateEntryVisibility,
	})
}

func TestEnterpriseAuthzSyntheticCredentialCompatibility(t *testing.T) {
	authzNativeCompatibility(t, map[string]func(*testing.T){
		"actions_token_permissions": TestActionsJobTokenPermissiveAccess,
		"actions_scopes":            TestActionsJobTokenPermissions,
		"actions_cross_repo":        TestActionsCrossRepoAccess,
		"deploy_key_read":           TestCreateReadOnlyDeployKey,
		"deploy_key_write":          TestCreateReadWriteDeployKey,
		"deploy_token_revocation":   TestCreateDeployToken,
	})
}
