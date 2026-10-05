// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package packages_test

import (
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	packages_model "gitea.dev/models/packages"
	container_model "gitea.dev/models/packages/container"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

func TestPackagesFeatureFiltersBeforePagination(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	for _, name := range []string{"visible", "hidden"} {
		pkg := &packages_model.Package{OwnerID: 3, RepoID: 0, Type: packages_model.TypeGeneric, Name: name, LowerName: name}
		if name == "hidden" {
			pkg.RepoID = 3
		}
		require.NoError(t, db.Insert(t.Context(), pkg))
		require.NoError(t, db.Insert(t.Context(), &packages_model.PackageVersion{PackageID: pkg.ID, Version: "1", LowerVersion: "1"}))
	}
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 3, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	versions, count, err := packages_model.SearchVersions(t.Context(), &packages_model.PackageSearchOptions{OwnerID: 3, Type: packages_model.TypeGeneric, Paginator: db.NewAbsoluteListOptions(0, 1)})
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	require.Len(t, versions, 1)
	pkg, err := packages_model.GetPackageByID(t.Context(), versions[0].PackageID)
	require.NoError(t, err)
	require.Equal(t, "visible", pkg.Name)
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeOrg, ScopeID: 3, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	_, count, err = packages_model.SearchVersions(t.Context(), &packages_model.PackageSearchOptions{OwnerID: 3, Type: packages_model.TypeGeneric})
	require.NoError(t, err)
	require.Zero(t, count)
	setting.EnterpriseAuthz.Enforce = false
	_, count, err = packages_model.SearchVersions(t.Context(), &packages_model.PackageSearchOptions{OwnerID: 3, Type: packages_model.TypeGeneric})
	require.NoError(t, err)
	require.EqualValues(t, 2, count)
}

func TestPackagesFeatureUsesCurrentRepositoryOwner(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	pkg := &packages_model.Package{OwnerID: 2, RepoID: 1, Type: packages_model.TypeGeneric, Name: "transfer", LowerName: "transfer"}
	require.NoError(t, db.Insert(t.Context(), pkg))
	require.NoError(t, db.Insert(t.Context(), &packages_model.PackageVersion{PackageID: pkg.ID, Version: "1", LowerVersion: "1"}))
	opts := &packages_model.PackageSearchOptions{PackageID: pkg.ID}
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeOrg, ScopeID: 3, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	_, count, err := packages_model.SearchVersions(t.Context(), opts)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	_, err = db.GetEngine(t.Context()).ID(1).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 3})
	require.NoError(t, err)
	_, count, err = packages_model.SearchVersions(t.Context(), opts)
	require.NoError(t, err)
	require.Zero(t, count)
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeSystem, State: authz.FeatureRequired, ConfigJSON: "{}", Revision: 1}))
	_, count, err = packages_model.SearchVersions(t.Context(), opts)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	_, err = db.GetEngine(t.Context()).Where("key=?", authz.FeaturePackages).Delete(new(authz_model.FeatureDefinition))
	require.NoError(t, err)
	_, _, err = packages_model.SearchVersions(t.Context(), opts)
	require.ErrorContains(t, err, "feature_policy_unavailable")
	setting.EnterpriseAuthz.FailClosedOnError = false
	_, count, err = packages_model.SearchVersions(t.Context(), opts)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
}

func TestPackagesContainerFeatureFilters(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	pkg := &packages_model.Package{OwnerID: 2, RepoID: 1, Type: packages_model.TypeContainer, Name: "image", LowerName: "image"}
	require.NoError(t, db.Insert(t.Context(), pkg))
	require.NoError(t, db.Insert(t.Context(), &packages_model.PackageVersion{PackageID: pkg.ID, Version: "tag", LowerVersion: "tag"}))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	_, count, err := container_model.SearchImageTags(t.Context(), &container_model.ImageTagsSearchOptions{PackageID: pkg.ID, IsTagged: false, Paginator: db.NewAbsoluteListOptions(0, 1)})
	require.NoError(t, err)
	require.Zero(t, count)
	setting.EnterpriseAuthz.Enforce = false
	counter := authz.FeatureQueryCandidate.WithLabelValues(string(authz.FeaturePackages), "would_deny")
	before := shadowCounterValue(counter)
	versions, count, err := container_model.SearchImageTags(t.Context(), &container_model.ImageTagsSearchOptions{PackageID: pkg.ID, IsTagged: false, Paginator: db.NewAbsoluteListOptions(10, 1)})
	require.NoError(t, err)
	require.Empty(t, versions)
	require.EqualValues(t, 1, count)
	require.InDelta(t, before+1, shadowCounterValue(counter), 0)
}

func TestPackageQueryShadowCandidate(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true}))
	pkg := &packages_model.Package{OwnerID: 2, RepoID: 1, Type: packages_model.TypeGeneric, Name: "shadow", LowerName: "shadow"}
	require.NoError(t, db.Insert(t.Context(), pkg))
	require.NoError(t, db.Insert(t.Context(), &packages_model.PackageVersion{PackageID: pkg.ID, Version: "1", LowerVersion: "1"}))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	counter := authz.FeatureQueryCandidate.WithLabelValues(string(authz.FeaturePackages), "would_deny")
	before := shadowCounterValue(counter)
	versions, count, err := packages_model.SearchVersions(t.Context(), &packages_model.PackageSearchOptions{OwnerID: 2, Paginator: db.NewAbsoluteListOptions(10, 1)})
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	require.Empty(t, versions)
	require.InDelta(t, before+1, shadowCounterValue(counter), 0)
	before = shadowCounterValue(counter)
	_, count, err = packages_model.SearchVersions(t.Context(), &packages_model.PackageSearchOptions{OwnerID: 3})
	require.NoError(t, err)
	require.Zero(t, count)
	require.InDelta(t, before, shadowCounterValue(counter), 0)
}

func shadowCounterValue(counter prometheus.Counter) float64 {
	var metric dto.Metric
	if err := counter.Write(&metric); err != nil {
		panic(err)
	}
	return metric.GetCounter().GetValue()
}
