// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package cargo

import (
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	packages_model "gitea.dev/models/packages"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	unittest.MainTest(m)
}

func TestCargoIndexRepositoryUsesTrustedPurpose(t *testing.T) {
	t.Run("renamed", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
		t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
		owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		index := &repo_model.Repository{OwnerID: 2, Name: "renamed-index", LowerName: "renamed-index", InternalUsage: repo_model.InternalUsageCargoIndex}
		require.NoError(t, db.Insert(t.Context(), index))
		actual, err := getOrCreateIndexRepository(t.Context(), owner, owner)
		require.NoError(t, err)
		require.Equal(t, index.ID, actual.ID)
	})
	t.Run("unmarked", func(t *testing.T) {
		require.NoError(t, unittest.PrepareTestDatabase())
		owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		index := &repo_model.Repository{OwnerID: 2, Name: IndexRepositoryName, LowerName: IndexRepositoryName}
		require.NoError(t, db.Insert(t.Context(), index))
		t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{}))
		actual, err := getOrCreateIndexRepository(t.Context(), owner, owner)
		require.NoError(t, err)
		require.Equal(t, index.ID, actual.ID)
		setting.EnterpriseAuthz.Enabled = true
		_, err = getOrCreateIndexRepository(t.Context(), owner, owner)
		require.ErrorContains(t, err, "untrusted_cargo_index")
		require.Empty(t, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: index.ID}).InternalUsage)
	})
}

func TestCargoIndexRejectsHiddenSourceBeforeGit(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	index := &repo_model.Repository{OwnerID: 2, Name: IndexRepositoryName, LowerName: IndexRepositoryName, InternalUsage: repo_model.InternalUsageCargoIndex}
	require.NoError(t, db.Insert(t.Context(), index))
	pkg := &packages_model.Package{OwnerID: 2, RepoID: 1, Type: packages_model.TypeCargo, Name: "hidden", LowerName: "hidden"}
	require.NoError(t, db.Insert(t.Context(), pkg))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	require.ErrorContains(t, RebuildIndex(t.Context(), owner, owner), "feature_disabled")
}

func TestCargoIndexSourcesOutlivePackage(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	index := &repo_model.Repository{OwnerID: 2, Name: IndexRepositoryName, LowerName: IndexRepositoryName, InternalUsage: repo_model.InternalUsageCargoIndex}
	require.NoError(t, db.Insert(t.Context(), index))
	pkg := &packages_model.Package{OwnerID: 2, RepoID: 1, Type: packages_model.TypeCargo, Name: "historical-source", LowerName: "historical-source"}
	require.NoError(t, db.Insert(t.Context(), pkg))
	require.NoError(t, rememberIndexPackageSources(t.Context(), index, []*packages_model.Package{pkg}))
	require.NoError(t, rememberIndexPackageSources(t.Context(), index, []*packages_model.Package{pkg}))
	unittest.AssertExistsAndLoadBean(t, &authz_model.CargoIndexSource{IndexRepoID: index.ID, SourceRepoID: 1})
	require.NoError(t, packages_model.DeletePackageByID(t.Context(), pkg.ID))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	require.ErrorContains(t, authz_service.RequireCargoIndexFeature(t.Context(), index), "feature_disabled")
	_, err := getOrCreateIndexRepository(t.Context(), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}))
	require.ErrorContains(t, err, "feature_disabled")
}
