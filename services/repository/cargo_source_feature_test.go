// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestCargoIndexBlocksSourceCopy(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	source := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	source.InternalUsage = repo_model.InternalUsageCargoIndex
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	_, err := ForkRepository(t.Context(), doer, doer, ForkRepoOptions{BaseRepo: source, Name: "blocked-index-fork"})
	require.ErrorContains(t, err, "feature_disabled")
	_, err = GenerateRepository(t.Context(), doer, doer, source, GenerateRepoOptions{Name: "blocked-index-template", GitContent: true})
	require.ErrorContains(t, err, "feature_disabled")
	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: doer.ID, Name: "blocked-index-fork"})
	unittest.AssertNotExistsBean(t, &repo_model.Repository{OwnerID: doer.ID, Name: "blocked-index-template"})
}
