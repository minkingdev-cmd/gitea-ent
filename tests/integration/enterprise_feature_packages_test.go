// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"net/http"
	neturl "net/url"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/packages"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	cargo_module "gitea.dev/modules/packages/cargo"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	cargo_service "gitea.dev/services/packages/cargo"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseFeaturePackageProtocolCleanup(t *testing.T) {
	for _, kind := range []packages.Type{packages.TypeGeneric, packages.TypeArch} {
		t.Run(string(kind), func(t *testing.T) {
			defer tests.PrepareTestEnv(t)()
			defer test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true})()
			defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
			var uploadPath, deletePath string
			content := []byte("content")
			if kind == packages.TypeGeneric {
				uploadPath = "/api/packages/user2/generic/cleanup-feature/1/file.bin"
				deletePath = "/api/packages/user2/generic/cleanup-feature/1"
			} else {
				uploadPath = "/api/packages/user2/arch/main"
				deletePath = "/api/packages/user2/arch/main/cleanup-feature/1/x86_64"
				var buf bytes.Buffer
				gw := gzip.NewWriter(&buf)
				tw := tar.NewWriter(gw)
				info := []byte("pkgname = cleanup-feature\npkgbase = cleanup-feature\npkgver = 1\npkgdesc = cleanup\nbuilddate = 1678834800\nsize = 1\narch = x86_64\nlicense = MIT")
				require.NoError(t, tw.WriteHeader(&tar.Header{Name: ".PKGINFO", Mode: 0o600, Size: int64(len(info))}))
				_, err := tw.Write(info)
				require.NoError(t, err)
				require.NoError(t, tw.Close())
				require.NoError(t, gw.Close())
				content = buf.Bytes()
			}
			MakeRequest(t, NewRequestWithBody(t, "PUT", uploadPath, bytes.NewReader(content)).AddBasicAuth("user2"), http.StatusCreated)
			pkg := unittest.AssertExistsAndLoadBean(t, &packages.Package{OwnerID: 2, Type: kind, LowerName: "cleanup-feature"})
			if kind == packages.TypeArch {
				index := unittest.AssertExistsAndLoadBean(t, &packages.Package{OwnerID: 2, Type: kind, LowerName: "_arch", IsInternal: true})
				pv := unittest.AssertExistsAndLoadBean(t, &packages.PackageVersion{PackageID: index.ID, LowerVersion: "_repository"})
				unittest.AssertExistsAndLoadBean(t, &packages.PackageFile{VersionID: pv.ID, Name: "packages.db"})
			}
			require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeSystem, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
			MakeRequest(t, NewRequestWithBody(t, "PUT", uploadPath, bytes.NewReader(content)).AddBasicAuth("user2"), http.StatusForbidden)
			MakeRequest(t, NewRequest(t, "DELETE", deletePath), http.StatusUnauthorized)
			MakeRequest(t, NewRequest(t, "DELETE", deletePath).AddBasicAuth("user2"), http.StatusNoContent)
			unittest.AssertNotExistsBean(t, &packages.PackageVersion{PackageID: pkg.ID})
			if kind == packages.TypeArch {
				index := unittest.AssertExistsAndLoadBean(t, &packages.Package{OwnerID: 2, Type: kind, LowerName: "_arch", IsInternal: true})
				pv := unittest.AssertExistsAndLoadBean(t, &packages.PackageVersion{PackageID: index.ID, LowerVersion: "_repository"})
				unittest.AssertNotExistsBean(t, &packages.PackageFile{VersionID: pv.ID, Name: "packages.db"})
			}
		})
	}
}

func TestEnterpriseFeatureCargoYankCleanup(t *testing.T) {
	onGiteaRun(t, testEnterpriseFeatureCargoYankCleanup)
}

func testEnterpriseFeatureCargoYankCleanup(t *testing.T, _ *neturl.URL) {
	defer test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, cargo_service.InitializeIndexRepository(t.Context(), owner, owner))
	index := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: owner.ID, InternalUsage: repo_model.InternalUsageCargoIndex})
	readIndex := func() string {
		gitRepo, err := git.OpenRepository(t.Context(), index)
		require.NoError(t, err)
		defer gitRepo.Close()
		commit, err := gitRepo.GetBranchCommit(t.Context(), index.DefaultBranch)
		require.NoError(t, err)
		blob, err := commit.GetBlobByPath(t.Context(), gitRepo, cargo_service.BuildPackagePath("cleanup-cargo"))
		require.NoError(t, err)
		content, err := blob.GetBlobContent(t.Context(), 4096)
		require.NoError(t, err)
		return content
	}
	metadata := []byte(`{"name":"cleanup-cargo","vers":"1.0.0","deps":[],"features":{}}`)
	var upload bytes.Buffer
	require.NoError(t, binary.Write(&upload, binary.LittleEndian, uint32(len(metadata))))
	_, err := upload.Write(metadata)
	require.NoError(t, err)
	require.NoError(t, binary.Write(&upload, binary.LittleEndian, uint32(4)))
	_, err = upload.WriteString("test")
	require.NoError(t, err)
	MakeRequest(t, NewRequestWithBody(t, "PUT", "/api/packages/user2/cargo/api/v1/crates/new", &upload).AddBasicAuth("user2"), http.StatusOK)
	pkg := unittest.AssertExistsAndLoadBean(t, &packages.Package{OwnerID: 2, Type: packages.TypeCargo, LowerName: "cleanup-cargo"})
	require.NoError(t, packages.SetRepositoryLink(t.Context(), pkg.ID, 1))
	require.NoError(t, cargo_service.UpdatePackageIndexIfExists(t.Context(), owner, owner, pkg.ID))
	require.Contains(t, readIndex(), `"yanked":false`)
	pv := unittest.AssertExistsAndLoadBean(t, &packages.PackageVersion{PackageID: pkg.ID, LowerVersion: "1.0.0"})
	properties, err := packages.GetPropertiesByName(t.Context(), packages.PropertyTypeVersion, pv.ID, cargo_module.PropertyYanked)
	require.NoError(t, err)
	require.Len(t, properties, 1)
	property := properties[0]
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeSystem, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	path := "/api/packages/user2/cargo/api/v1/crates/cleanup-cargo/1.0.0/"
	MakeRequest(t, NewRequest(t, "DELETE", path+"yank"), http.StatusUnauthorized)
	require.Equal(t, "false", unittest.AssertExistsAndLoadBean(t, &packages.PackageProperty{ID: property.ID}).Value)
	require.Contains(t, readIndex(), `"yanked":false`)
	MakeRequest(t, NewRequest(t, "DELETE", path+"yank").AddBasicAuth("user2"), http.StatusOK)
	require.Contains(t, readIndex(), `"yanked":true`)
	require.Equal(t, "true", unittest.AssertExistsAndLoadBean(t, &packages.PackageProperty{ID: property.ID}).Value)
	MakeRequest(t, NewRequest(t, "PUT", path+"unyank").AddBasicAuth("user2"), http.StatusForbidden)
	require.Contains(t, readIndex(), `"yanked":true`)
	require.Equal(t, "true", unittest.AssertExistsAndLoadBean(t, &packages.PackageProperty{ID: property.ID}).Value)
}
