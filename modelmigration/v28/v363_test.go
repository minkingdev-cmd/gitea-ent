// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"testing"

	"gitea.dev/modelmigration/migrationtest"
	feature_model "gitea.dev/models/enterpriseauthz" //nolint:depguard // 验证正式迁移后的真实存储合同。
	authz "gitea.dev/modules/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseFeatureMigration(t *testing.T) {
	x, cleanup := migrationtest.PrepareTestEnv(t, 0)
	defer cleanup()
	exists, err := x.IsTableExist("repository")
	require.NoError(t, err)
	if !exists {
		_, err = x.Exec("CREATE TABLE repository (id BIGINT PRIMARY KEY)")
		require.NoError(t, err)
	}
	_, err = x.Exec("INSERT INTO repository (id) VALUES (888)")
	require.NoError(t, err)
	require.NoError(t, AddEnterpriseFeatureGrants(t.Context(), x))
	legacy := new(FeatureRepositoryV363)
	found, err := x.ID(888).Get(legacy)
	require.NoError(t, err)
	require.True(t, found)
	require.Empty(t, legacy.InternalUsage)
	legacy.InternalUsage = "cargo-index"
	_, err = x.ID(888).Cols("internal_usage").Update(legacy)
	require.NoError(t, err)
	definitions := []*feature_model.FeatureDefinition{}
	require.NoError(t, x.Find(&definitions))
	require.Len(t, definitions, 13)
	for _, definition := range definitions {
		require.NoError(t, definition.Validate())
	}
	grant := &feature_model.FeatureGrant{FeatureKey: authz.FeatureWiki, ScopeType: feature_model.ScopeRepo, ScopeID: 1, State: authz.FeatureRequired, ConfigJSON: "{}", Revision: 7, CreatedBy: 2, UpdatedBy: 2}
	_, err = x.Insert(grant)
	require.NoError(t, err)
	before, err := x.Query("SELECT * FROM enterprise_feature_grant ORDER BY id")
	require.NoError(t, err)
	for range 2 {
		require.NoError(t, AddEnterpriseFeatureGrants(t.Context(), x))
		preserved := new(FeatureRepositoryV363)
		_, err := x.ID(888).Get(preserved)
		require.NoError(t, err)
		require.Equal(t, "cargo-index", preserved.InternalUsage)
		after, err := x.Query("SELECT * FROM enterprise_feature_grant ORDER BY id")
		require.NoError(t, err)
		require.Equal(t, before, after)
		count, err := x.Count(new(feature_model.FeatureDefinition))
		require.NoError(t, err)
		require.EqualValues(t, 13, count)
	}
	duplicate := *grant
	duplicate.ID = 0
	_, err = x.Insert(&duplicate)
	require.Error(t, err)
}
