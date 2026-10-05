// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package packages

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/organization"
	packages_model "gitea.dev/models/packages"
	repo_model "gitea.dev/models/repo"
	unit_model "gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	packages_module "gitea.dev/modules/packages"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	unittest.MainTest(m)
}

func TestCreatePackageAndAddFileRestoresMissingBlobFile(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())
	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

	uploadPackage := func(t *testing.T, user *user_model.User, name, filename string, data []byte) (*packages_model.PackageFile, error) {
		buf, err := packages_module.CreateHashedBufferFromReader(bytes.NewReader(data))
		require.NoError(t, err)
		_, pf, err := CreatePackageAndAddFile(t.Context(),
			&PackageCreationInfo{
				Owner:            user,
				PackageType:      packages_model.TypeNuGet,
				Name:             name,
				Version:          "1.0.0",
				SemverCompatible: true,
				Creator:          user,
			},
			&PackageFileCreationInfo{
				Filename: filename,
				Creator:  user,
				Data:     buf,
				IsLead:   true,
			})
		return pf, err
	}

	// This test data is from https://github.com/go-gitea/gitea/issues/39215, it doesn't really matter, actually.
	// The key point is that if the blob object is missing in the content storage, it must be restored when uploaded again.
	pkgData := test.WriteZipArchive(map[string]string{
		"package.nuspec":         "<package><metadata><id>nuget.repro</id><version>1.0.0</version></metadata></package>",
		"lib/netstandard2.0/_._": "",
	}).Bytes()
	pkgDataSum := sha256.Sum256(pkgData)
	key := packages_module.BlobHash256Key(hex.EncodeToString(pkgDataSum[:]))
	contentStore := packages_module.NewContentStore()

	// The initial upload writes the blob row and its file
	pf1, err := uploadPackage(t, user, "nuget.repro", "nuget.repro.1.0.0.nupkg", pkgData)
	require.NoError(t, err)
	sz, err := contentStore.OptionalSize(key)
	assert.NoError(t, err)
	assert.EqualValues(t, len(pkgData), sz.ValueOrDefault(-1))

	// Simulate the storage inconsistency: the blob row survives but its file is missing
	require.NoError(t, contentStore.Delete(key))
	sz, err = contentStore.OptionalSize(key)
	assert.NoError(t, err)
	assert.EqualValues(t, -1, sz.ValueOrDefault(-1))

	// Publishing a package with identical content must restore the blob file
	pf2, err := uploadPackage(t, user, "nuget.repro-copy", "nuget.repro-copy.1.0.0.nupkg", pkgData)
	require.NoError(t, err)
	sz, err = contentStore.OptionalSize(key)
	assert.NoError(t, err)
	assert.EqualValues(t, len(pkgData), sz.ValueOrDefault(-1))

	// The blob file must be present and both packages must be downloadable
	for _, pf := range []*packages_model.PackageFile{pf1, pf2} {
		s, _, _, err := OpenFileForDownload(t.Context(), pf, http.MethodGet)
		require.NoError(t, err)
		respData, err := io.ReadAll(s)
		require.NoError(t, err)
		assert.NoError(t, s.Close())
		assert.Equal(t, pkgData, respData)
	}
}

func TestUnlinkFromRepositoryRequiresTargetRepoAdmin(t *testing.T) {
	assert.NoError(t, unittest.PrepareTestDatabase())
	repo := &repo_model.Repository{OwnerID: 3, OwnerName: "org3", Name: "package-repo", LowerName: "package-repo", IsPrivate: true}
	require.NoError(t, db.Insert(t.Context(), repo))
	require.NoError(t, db.Insert(t.Context(),
		&repo_model.RepoUnit{RepoID: repo.ID, Type: unit_model.TypeCode},
		&repo_model.RepoUnit{RepoID: repo.ID, Type: unit_model.TypePackages},
		&organization.TeamRepo{OrgID: repo.OwnerID, TeamID: 14, RepoID: repo.ID},
	))
	pkg := &packages_model.Package{OwnerID: repo.OwnerID, RepoID: repo.ID, Type: packages_model.TypeGeneric, Name: "package", LowerName: "package"}
	require.NoError(t, db.Insert(t.Context(), pkg))
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 28})

	assert.Error(t, UnlinkFromRepository(t.Context(), pkg, doer))
	assert.Equal(t, repo.ID, unittest.AssertExistsAndLoadBean(t, &packages_model.Package{ID: pkg.ID}).RepoID)

	require.NoError(t, db.Insert(t.Context(), &organization.TeamRepo{OrgID: repo.OwnerID, TeamID: 12, RepoID: repo.ID}))
	require.NoError(t, UnlinkFromRepository(t.Context(), pkg, doer))
	assert.Zero(t, unittest.AssertExistsAndLoadBean(t, &packages_model.Package{ID: pkg.ID}).RepoID)
}

func TestPackageFeatureBlocksCreationAndUnlink(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	grant := &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeSystem, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}
	require.NoError(t, db.Insert(t.Context(), grant))
	err := db.WithTx(t.Context(), func(ctx context.Context) error {
		_, _, err := createPackageAndVersion(ctx, &PackageCreationInfo{PackageInfo: PackageInfo{Owner: owner, PackageType: packages_model.TypeGeneric, Name: "denied-create", Version: "1"}, Creator: owner}, false)
		return err
	})
	require.ErrorContains(t, err, "feature_disabled")
	unittest.AssertNotExistsBean(t, &packages_model.Package{Name: "denied-create"})
	pkg := &packages_model.Package{OwnerID: 2, RepoID: 1, Type: packages_model.TypeGeneric, Name: "cannot-unlink", LowerName: "cannot-unlink"}
	require.NoError(t, db.Insert(t.Context(), pkg))
	require.Error(t, UnlinkFromRepository(t.Context(), pkg, owner))
	require.EqualValues(t, 1, unittest.AssertExistsAndLoadBean(t, &packages_model.Package{ID: pkg.ID}).RepoID)
}

func TestPackageFeatureAllowsDeletion(t *testing.T) {
	manager := GetSpecManager()
	previous := manager.specMap
	t.Cleanup(func() { manager.specMap = previous })
	manager.specMap = map[packages_model.Type]Specialization{packages_model.TypeGeneric: &specDefault{}}
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	pkg := &packages_model.Package{OwnerID: 2, RepoID: 1, Type: packages_model.TypeGeneric, Name: "delete-disabled", LowerName: "delete-disabled"}
	require.NoError(t, db.Insert(t.Context(), pkg))
	pv := &packages_model.PackageVersion{PackageID: pkg.ID, Version: "1", LowerVersion: "1", CreatorID: 2}
	require.NoError(t, db.Insert(t.Context(), pv))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeSystem, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	require.NoError(t, RemovePackageVersionByNameAndVersion(t.Context(), owner, &PackageInfo{Owner: owner, PackageType: packages_model.TypeGeneric, Name: pkg.Name, Version: "1"}))
	unittest.AssertNotExistsBean(t, &packages_model.PackageVersion{ID: pv.ID})
}

func TestDerivedPackageIndexRejectsDisabledLinkedContent(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	pkg := &packages_model.Package{OwnerID: 2, RepoID: 1, Type: packages_model.TypeArch, Name: "hidden-source", LowerName: "hidden-source"}
	require.NoError(t, db.Insert(t.Context(), pkg))
	require.NoError(t, db.Insert(t.Context(), &packages_model.PackageVersion{PackageID: pkg.ID, Version: "1", LowerVersion: "1"}))
	index := &packages_model.Package{OwnerID: 2, Type: packages_model.TypeArch, Name: "_arch", LowerName: "_arch", IsInternal: true}
	require.NoError(t, db.Insert(t.Context(), index))
	pv := &packages_model.PackageVersion{PackageID: index.ID, Version: "_repository", LowerVersion: "_repository", IsInternal: true}
	require.NoError(t, db.Insert(t.Context(), pv))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	_, _, _, err := OpenBlobForDownload(t.Context(), &packages_model.PackageFile{VersionID: pv.ID}, &packages_model.PackageBlob{HashSHA256: "missing"}, http.MethodGet, nil)
	require.ErrorContains(t, err, "feature_disabled")
}

func TestInternalPackageMetadataCannotBypassFeature(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	pkg := &packages_model.Package{OwnerID: 2, RepoID: 1, Type: packages_model.TypeArch, Name: "_arch", LowerName: "_arch"}
	require.NoError(t, db.Insert(t.Context(), pkg))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	_, err := GetOrCreateInternalPackageVersion(t.Context(), 2, packages_model.TypeArch, "_arch", "_repository")
	require.ErrorContains(t, err, "feature_disabled")
	unittest.AssertNotExistsBean(t, &packages_model.PackageVersion{PackageID: pkg.ID})
	ctx := packages_model.WithCleanupIndexMaintenance(t.Context(), 2, packages_model.TypeArch)
	_, err = GetOrCreateInternalPackageVersion(ctx, 2, packages_model.TypeArch, "_arch", "_repository")
	require.ErrorContains(t, err, "invalid_cleanup_index")
	_, err = GetOrCreateInternalPackageVersion(ctx, 2, packages_model.TypeArch, "other-index", "_repository")
	require.ErrorContains(t, err, "invalid_cleanup_index")
	unittest.AssertNotExistsBean(t, &packages_model.Package{Name: "other-index"})
}

func TestCleanupFixedIndexRemainsWritable(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeSystem, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	_, err := GetOrCreateInternalPackageVersion(t.Context(), 2, packages_model.TypeArch, "_arch", "_repository")
	require.ErrorContains(t, err, "feature_disabled")
	require.NoError(t, RebuildIndexAfterPackageCleanup(t.Context(), 2, packages_model.TypeArch, func(ctx context.Context) error {
		pv, err := GetOrCreateInternalPackageVersion(ctx, 2, packages_model.TypeArch, "_arch", "_repository")
		if err != nil {
			return err
		}
		buf, err := packages_module.CreateHashedBufferFromReader(bytes.NewBufferString("remaining-index"))
		if err != nil {
			return err
		}
		defer buf.Close()
		_, err = AddFileToPackageVersionInternal(ctx, pv, &PackageFileCreationInfo{Filename: "packages.db", Data: buf, Creator: unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})})
		return err
	}))
}

func TestPackageFeatureDoesNotReduceStorageQuota(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Packages.LimitTotalOwnerCount, int64(0)))
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	pkg := &packages_model.Package{OwnerID: 4, RepoID: 1, Type: packages_model.TypeGeneric, Name: "quota-hidden", LowerName: "quota-hidden"}
	require.NoError(t, db.Insert(t.Context(), pkg))
	require.NoError(t, db.Insert(t.Context(), &packages_model.PackageVersion{PackageID: pkg.ID, Version: "1", LowerVersion: "1"}))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	require.ErrorIs(t, CheckCountQuotaExceeded(t.Context(), owner, owner), ErrQuotaTotalCount)
}

func TestPackageMetadataWriteRechecksActualSource(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	pkg := &packages_model.Package{OwnerID: 2, RepoID: 1, Type: packages_model.TypeGeneric, Name: "metadata-feature", LowerName: "metadata-feature"}
	require.NoError(t, db.Insert(t.Context(), pkg))
	pv := &packages_model.PackageVersion{PackageID: pkg.ID, Version: "1", LowerVersion: "1", MetadataJSON: "original"}
	require.NoError(t, db.Insert(t.Context(), pv))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	pv.PackageID = 0
	pv.MetadataJSON = "denied"
	require.ErrorContains(t, UpdatePackageVersionMetadata(t.Context(), pv), "feature_disabled")
	require.Equal(t, "original", unittest.AssertExistsAndLoadBean(t, &packages_model.PackageVersion{ID: pv.ID}).MetadataJSON)
}

func TestDerivedPackageIndexRecordsActualOwnerDecision(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	require.NoError(t, db.Insert(t.Context(), &packages_model.Package{OwnerID: 2, RepoID: 1, Type: packages_model.TypeArch, Name: "candidate-source", LowerName: "candidate-source"}))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	assertDecision := func(actual, mode string) {
		var events []*audit_model.Event
		require.NoError(t, db.GetEngine(t.Context()).Where("action=? AND scope_type=? AND scope_id=?", audit_model.EnterpriseFeatureDecision, audit_model.ScopeUser, 2).Find(&events))
		require.NotEmpty(t, events)
		event := events[len(events)-1]
		require.Contains(t, event.Metadata, `"candidate_decision":"deny"`)
		require.Contains(t, event.Metadata, `"actual_decision":"`+actual+`"`)
		require.Contains(t, event.Metadata, `"mode":"`+mode+`"`)
		require.Contains(t, event.Metadata, `"derived_index":"arch"`)
	}
	require.NoError(t, RequireDerivedIndexFeature(t.Context(), 2, packages_model.TypeArch))
	assertDecision("native", "shadow")
	setting.EnterpriseAuthz.Enforce = true
	require.ErrorContains(t, RequireDerivedIndexFeature(t.Context(), 2, packages_model.TypeArch), "feature_disabled")
	assertDecision("deny", "enforce")
	countDecisions := func() int64 {
		count, err := db.GetEngine(t.Context()).Where("action=? AND scope_type=? AND scope_id=?", audit_model.EnterpriseFeatureDecision, audit_model.ScopeUser, 2).Count(new(audit_model.Event))
		require.NoError(t, err)
		return count
	}
	before := countDecisions()
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		require.ErrorContains(t, RequireDerivedIndexFeature(ctx, 2, packages_model.TypeArch), "feature_disabled")
		return nil
	}))
	require.Equal(t, before+1, countDecisions())
	err := db.WithTx(t.Context(), func(ctx context.Context) error {
		return RequireDerivedIndexFeature(ctx, 2, packages_model.TypeArch)
	})
	require.ErrorContains(t, err, "feature_disabled")
	require.Equal(t, before+2, countDecisions())
	setting.Audit.RecordOutput = setting.AuditRecordOutputDisabled
	setting.EnterpriseAuthz.FailClosedOnError = false
	require.ErrorContains(t, RequireDerivedIndexFeature(t.Context(), 2, packages_model.TypeArch), "feature_disabled")
	setting.EnterpriseAuthz.Enforce = false
	require.NoError(t, RequireDerivedIndexFeature(t.Context(), 2, packages_model.TypeArch))
}

func TestDerivedPackageIndexAuditUsesOrganizationOwner(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	require.NoError(t, db.Insert(t.Context(), &packages_model.Package{OwnerID: 3, RepoID: 1, Type: packages_model.TypeDebian, Name: "org-source", LowerName: "org-source"}))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	require.ErrorContains(t, RequireDerivedIndexFeature(t.Context(), 3, packages_model.TypeDebian), "feature_disabled")
	var events []*audit_model.Event
	require.NoError(t, db.GetEngine(t.Context()).Where("action=? AND scope_type=? AND scope_id=?", audit_model.EnterpriseFeatureDecision, audit_model.ScopeOrganization, 3).Find(&events))
	var derived []*audit_model.Event
	for _, event := range events {
		if strings.Contains(event.Metadata, `"derived_index":"debian"`) {
			derived = append(derived, event)
		}
	}
	require.Len(t, derived, 1)
	require.Contains(t, derived[0].Metadata, `"candidate_decision":"deny"`)
	require.Contains(t, derived[0].Metadata, `"actual_decision":"deny"`)
}
