// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"net/http"
	"testing"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	secret_model "gitea.dev/models/secret"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseFeatureSecretManagementRoutes(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureCISecretManagement, ScopeType: authz_model.ScopeSystem, State: authz.FeatureDisabled, ConfigJSON: `{}`, Revision: 1}))
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteUser)
	for _, scope := range []struct {
		base, web   string
		owner, repo int64
	}{
		{"/api/v1/repos/user2/repo1/actions/secrets", "/user2/repo1/settings/actions/secrets", 0, 1},
		{"/api/v1/orgs/org3/actions/secrets", "/org/org3/settings/actions/secrets", 3, 0},
	} {
		t.Run(scope.base, func(t *testing.T) {
			existing, err := secret_model.InsertEncryptedSecret(t.Context(), scope.owner, scope.repo, "FEATURE_EXISTING", "runner-data", "")
			require.NoError(t, err)
			session.MakeRequest(t, NewRequest(t, "GET", scope.base).AddTokenAuth(token), http.StatusForbidden)
			session.MakeRequest(t, NewRequestWithJSON(t, "PUT", scope.base+"/NEW", api.CreateOrUpdateSecretOption{Data: "never-created"}).AddTokenAuth(token), http.StatusForbidden)
			session.MakeRequest(t, NewRequestWithJSON(t, "PUT", scope.base+"/FEATURE_EXISTING", api.CreateOrUpdateSecretOption{Data: "never-updated"}).AddTokenAuth(token), http.StatusForbidden)
			session.MakeRequest(t, NewRequest(t, "GET", scope.web), http.StatusForbidden)
			session.MakeRequest(t, NewRequestWithValues(t, "POST", scope.web, map[string]string{"name": "WEB_NEW", "data": "never-created"}), http.StatusForbidden)
			stored := unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{ID: existing.ID})
			require.Equal(t, existing.Data, stored.Data)
			session.MakeRequest(t, NewRequest(t, "DELETE", scope.base+"/FEATURE_EXISTING").AddTokenAuth(token), http.StatusNoContent)
			unittest.AssertNotExistsBean(t, &secret_model.Secret{ID: existing.ID})
		})
	}
	session.MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/user/actions/secrets/NEW", api.CreateOrUpdateSecretOption{Data: "never-created"}).AddTokenAuth(token), http.StatusForbidden)
}

func TestEnterpriseFeatureRequiredChecksRoutes(t *testing.T) {
	for _, state := range []authz.FeatureState{authz.FeatureDisabled, authz.FeatureRequired} {
		t.Run(string(state), func(t *testing.T) {
			defer tests.PrepareTestEnv(t)()
			defer test.MockVariableValue(&setting.EnterpriseAuthz)()
			defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
			setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
			require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureRequiredStatusChecks, ScopeType: authz_model.ScopeSystem, State: state, ConfigJSON: `{"check_contexts":["security/gitleaks"]}`, Revision: 1}))
			rule := &git_model.ProtectedBranch{RepoID: 1, RuleName: "feature-checks", Priority: 1, EnableStatusCheck: true, StatusCheckContexts: []string{"security/gitleaks"}}
			weak := &git_model.ProtectedBranch{RepoID: 1, RuleName: "**", Priority: 2}
			require.NoError(t, db.Insert(t.Context(), rule, weak))
			session := loginUser(t, "user2")
			token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
			base := "/api/v1/repos/user2/repo1/branch_protections"
			session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", base+"/feature-checks", api.EditBranchProtectionOption{RequiredApprovals: new(int64(2))}).AddTokenAuth(token), http.StatusOK)
			session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", base+"/feature-checks", api.EditBranchProtectionOption{EnableStatusCheck: new(false)}).AddTokenAuth(token), http.StatusForbidden)
			session.MakeRequest(t, NewRequest(t, "DELETE", base+"/feature-checks").AddTokenAuth(token), http.StatusForbidden)
			session.MakeRequest(t, NewRequestWithJSON(t, "POST", base+"/priority", api.UpdateBranchProtectionPriories{IDs: []int64{weak.ID, rule.ID}}).AddTokenAuth(token), http.StatusForbidden)
			session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/user2/repo1/settings/branches/priority", map[string]any{"ids": []int64{weak.ID, rule.ID}}), http.StatusForbidden)
			session.MakeRequest(t, NewRequest(t, "POST", fmt.Sprintf("/user2/repo1/settings/branches/%d/delete", rule.ID)), http.StatusForbidden)
			stored := unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: rule.ID})
			require.True(t, stored.EnableStatusCheck)
			require.Equal(t, []string{"security/gitleaks"}, stored.StatusCheckContexts)
			require.EqualValues(t, 1, stored.Priority)
		})
	}
}
