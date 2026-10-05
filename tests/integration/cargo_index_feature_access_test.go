// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"net/http"
	"testing"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestCargoIndexFeatureContentRoutes(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadRepository)
	contents := "/api/v1/repos/user2/repo1/contents/README.md"
	session.MakeRequest(t, NewRequest(t, "GET", contents).AddTokenAuth(token), http.StatusOK)
	_, err := db.GetEngine(t.Context()).ID(1).Cols("internal_usage").Update(&repo_model.Repository{InternalUsage: repo_model.InternalUsageCargoIndex})
	require.NoError(t, err)
	for _, path := range []string{
		contents,
		"/api/v1/repos/user2/repo1/git/blobs/4b4851ad51df6a7d9f25c979345979eaeb5b349f",
		"/api/v1/repos/user2/repo1/raw/README.md",
		"/api/v1/repos/user2/repo1/archive/master.zip",
		"/api/v1/repos/user2/repo2/compare/master...user2/repo1:master",
	} {
		session.MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), http.StatusForbidden)
	}
	for _, path := range []string{
		"/user2/repo1/src/branch/master/README.md",
		"/user2/repo1/raw/branch/master/README.md",
		"/user2/repo1/archive/master.zip",
		"/user2/repo1/compare/master...master",
		"/user2/repo2/compare/master...user2/repo1:master",
	} {
		session.MakeRequest(t, NewRequest(t, "GET", path), http.StatusForbidden)
	}
	session.MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1").AddTokenAuth(token), http.StatusOK)
	_, err = db.GetEngine(t.Context()).ID(1).Cols("internal_usage").Update(&repo_model.Repository{})
	require.NoError(t, err)
	session.MakeRequest(t, NewRequest(t, "GET", contents).AddTokenAuth(token), http.StatusOK)
}
