// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package private

import (
	"net/http"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/contexttest"

	"github.com/stretchr/testify/require"
)

func TestFeatureWikiAndCargoSSHProtocol(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	for _, key := range []authz.FeatureKey{authz.FeatureWiki, authz.FeaturePackages} {
		require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: key, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	}
	for _, tc := range []struct {
		name, repo, usage string
		status            int
	}{
		{"wiki", "repo1.wiki", "", http.StatusForbidden},
		{"marked-cargo", "repo1", repo_model.InternalUsageCargoIndex, http.StatusForbidden},
		{"ordinary-code", "repo1", "", http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := db.GetEngine(t.Context()).ID(1).Cols("internal_usage").Update(&repo_model.Repository{InternalUsage: tc.usage})
			require.NoError(t, err)
			ctx, resp := contexttest.MockPrivateContext(t, "/?mode=1&verb=git-upload-pack")
			ctx.SetPathParam("keyid", "1")
			ctx.SetPathParam("owner", "user2")
			ctx.SetPathParam("repo", tc.repo)
			ServCommand(ctx)
			require.Equal(t, tc.status, resp.Code, resp.Body.String())
		})
	}
}
