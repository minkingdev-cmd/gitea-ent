// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package wiki

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

func TestWikiFeatureRejectsWrites(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureWiki, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	require.ErrorContains(t, InitWiki(t.Context(), repo), "feature_disabled")
	require.ErrorContains(t, AddWikiPage(t.Context(), doer, repo, "forbidden", "content", "message"), "feature_disabled")
	require.ErrorContains(t, EditWikiPage(t.Context(), doer, repo, "old", "new", "content", "message"), "feature_disabled")
	require.ErrorContains(t, DeleteWikiPage(t.Context(), doer, repo, "old"), "feature_disabled")
	require.ErrorContains(t, DeleteWiki(t.Context(), repo), "feature_disabled")
	require.ErrorContains(t, ChangeDefaultWikiBranch(t.Context(), repo, "other"), "feature_disabled")
}
