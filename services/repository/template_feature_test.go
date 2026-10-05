// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestTemplateRequiredChecksFeature(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureRequiredStatusChecks, ScopeType: authz_model.ScopeSystem, State: authz.FeatureDisabled, ConfigJSON: `{}`, Revision: 1}))
	require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: 1, RuleName: "feature-copy", EnableStatusCheck: true, StatusCheckContexts: []string{"ci/build"}}))
	template := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	target := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
	require.Error(t, GenerateProtectedBranch(t.Context(), template, target))
	unittest.AssertNotExistsBean(t, &git_model.ProtectedBranch{RepoID: 2, RuleName: "feature-copy"})
}
