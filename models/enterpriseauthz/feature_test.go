// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"testing"

	"gitea.dev/models/db"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestFeatureModelConstraints(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	grant := &FeatureGrant{FeatureKey: authz.FeatureWiki, ScopeType: ScopeRepo, ScopeID: 1, State: authz.FeatureRequired, ConfigJSON: "{}", Revision: 1}
	require.NoError(t, grant.Validate())
	require.NoError(t, db.Insert(t.Context(), grant))
	duplicate := *grant
	duplicate.ID = 0
	require.Error(t, db.Insert(t.Context(), &duplicate))
	for _, change := range []func(*FeatureGrant){
		func(g *FeatureGrant) { g.State = "typo" },
		func(g *FeatureGrant) { g.ScopeID = 0 },
		func(g *FeatureGrant) { g.ScopeType = "user" },
		func(g *FeatureGrant) { g.ConfigJSON = `{"token":"secret"}` },
		func(g *FeatureGrant) { g.Revision = 0 },
		func(g *FeatureGrant) { g.FeatureKey = "feature.typo" },
	} {
		invalid := *grant
		change(&invalid)
		require.Error(t, invalid.Validate())
	}
}

func TestFeatureReadiness(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	setting.EnterpriseAuthz.Enabled = true
	seedBuiltinRoles(t)
	require.NoError(t, CheckReady(t.Context()))
	_, err := db.GetEngine(t.Context()).Where("`key` = ?", authz.FeatureAIReview).Delete(new(FeatureDefinition))
	require.NoError(t, err)
	require.EqualError(t, CheckReady(t.Context()), "authz_seed_incomplete")
	setting.EnterpriseAuthz.Enabled = false
	require.NoError(t, CheckReady(t.Context()))
}

func TestFeaturePreflightSchemaAndDrift(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	setting.EnterpriseAuthz.Enabled = true
	seedBuiltinRoles(t)
	x := db.GetXORMEngineForTesting()
	_, err := x.Where("`key` = ?", authz.FeatureWiki).Cols("catalog_version").Update(&FeatureDefinition{CatalogVersion: 99})
	require.NoError(t, err)
	require.EqualError(t, CheckReady(t.Context()), "authz_seed_incomplete")
	_, err = x.Where("`key` = ?", authz.FeatureWiki).Cols("catalog_version").Update(&FeatureDefinition{CatalogVersion: authz.FeatureCatalogVersion})
	require.NoError(t, err)
	_, err = x.Exec("DROP INDEX UQE_enterprise_feature_grant_feature_scope")
	require.NoError(t, err)
	defer func() { require.NoError(t, x.Sync(new(FeatureGrant))) }()
	require.EqualError(t, CheckReady(t.Context()), "authz_schema_missing")
	setting.EnterpriseAuthz.Enabled = false
	require.NoError(t, CheckReady(t.Context()))
}

func TestFeaturePreflightGrantColumns(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	setting.EnterpriseAuthz.Enabled = true
	seedBuiltinRoles(t)
	x := db.GetXORMEngineForTesting()
	_, err := x.Exec("ALTER TABLE enterprise_feature_grant RENAME COLUMN config_json TO missing_config")
	require.NoError(t, err)
	defer func() {
		_, err := x.Exec("ALTER TABLE enterprise_feature_grant RENAME COLUMN missing_config TO config_json")
		require.NoError(t, err)
	}()
	require.EqualError(t, CheckReady(t.Context()), "authz_schema_missing")
	setting.EnterpriseAuthz.Enabled = false
	require.NoError(t, CheckReady(t.Context()))
}
