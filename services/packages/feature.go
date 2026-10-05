// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package packages

import (
	"context"
	"slices"
	"strings"
	"time"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	packages_model "gitea.dev/models/packages"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	cargo_module "gitea.dev/modules/packages/cargo"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	authz_service "gitea.dev/services/enterpriseauthz"

	"xorm.io/builder"
)

func RequirePackageFeature(ctx context.Context, pkg *packages_model.Package) error {
	if !setting.EnterpriseAuthz.Enabled {
		return nil
	}
	if pkg.ID > 0 {
		current, err := packages_model.GetPackageByID(ctx, pkg.ID)
		if err != nil {
			return authz_service.FeatureGuardError(err)
		}
		pkg = current
	}
	if err := authz_service.RequireOwnerFeature(ctx, pkg.OwnerID, authz.FeaturePackages); err != nil {
		return err
	}
	if pkg.RepoID > 0 {
		return authz_service.RequireRepoFeature(ctx, pkg.RepoID, authz.FeaturePackages)
	}
	return nil
}

func RequirePackageWriteFeature(ctx context.Context, pkg *packages_model.Package) error {
	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
		if pkg.ID > 0 {
			current, err := packages_model.GetPackageByID(ctx, pkg.ID)
			if err != nil {
				return authz_service.FeatureGuardError(err)
			}
			pkg = current
		}
		if err := authz_model.LockScope(ctx, authz_model.Scope{Type: authz_model.ScopeOrg, ID: pkg.OwnerID}); err != nil {
			return authz_service.FeatureGuardError(err)
		}
		if pkg.RepoID > 0 {
			if err := authz_model.LockScope(ctx, authz_model.Scope{Type: authz_model.ScopeRepo, ID: pkg.RepoID}); err != nil {
				return authz_service.FeatureGuardError(err)
			}
		}
		if pkg.ID > 0 {
			if _, err := db.Exec(ctx, "UPDATE `package` SET id=id WHERE id=?", pkg.ID); err != nil {
				return authz_service.FeatureGuardError(err)
			}
		}
		if err := authz_model.LockFeatures(ctx, []authz.FeatureKey{authz.FeaturePackages}); err != nil {
			if denied := authz_service.FeatureGuardError(err); denied != nil {
				return denied
			}
		}
	}
	return RequirePackageFeature(ctx, pkg)
}

func requirePackageVersionFeature(ctx context.Context, pv *packages_model.PackageVersion) error {
	if !setting.EnterpriseAuthz.Enabled {
		return nil
	}
	pkg, err := packages_model.GetPackageByID(ctx, pv.PackageID)
	if err != nil {
		return authz_service.FeatureGuardError(err)
	}
	if packages_model.CleanupIndexWriteAllowed(ctx, pkg, pv.Version) {
		return nil
	}
	if pkg.IsInternal && packages_model.CleanupIndexWriteAllowed(packages_model.WithCleanupIndexMaintenance(ctx, pkg.OwnerID, pkg.Type), pkg, pv.Version) {
		if err := RequireDerivedIndexFeature(ctx, pkg.OwnerID, pkg.Type); err != nil {
			return err
		}
	}
	return RequirePackageFeature(ctx, pkg)
}

func requirePackageCreationFeature(ctx context.Context, info *PackageCreationInfo) error {
	return RequirePackageNameWriteFeature(ctx, info.Owner.ID, info.PackageType, info.Name)
}

func RequirePackageNameWriteFeature(ctx context.Context, ownerID int64, kind packages_model.Type, name string) error {
	if !setting.EnterpriseAuthz.Enabled {
		return nil
	}
	pkg, exists, err := db.Get[packages_model.Package](ctx, builder.Eq{"owner_id": ownerID, "type": kind, "lower_name": strings.ToLower(name)})
	if err != nil {
		return authz_service.FeatureGuardError(err)
	}
	if exists {
		return RequirePackageWriteFeature(ctx, pkg)
	}
	return RequirePackageWriteFeature(ctx, &packages_model.Package{OwnerID: ownerID})
}

func SetRepositoryAssociation(ctx context.Context, packageID, repoID int64) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		pkg, err := packages_model.GetPackageByID(ctx, packageID)
		if err != nil {
			return err
		}
		if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
			if err := authz_model.LockScope(ctx, authz_model.Scope{Type: authz_model.ScopeOrg, ID: pkg.OwnerID}); err != nil {
				return authz_service.FeatureGuardError(err)
			}
			ids := []int64{pkg.RepoID, repoID}
			slices.Sort(ids)
			for _, id := range slices.Compact(ids) {
				if id > 0 {
					if err := authz_model.LockScope(ctx, authz_model.Scope{Type: authz_model.ScopeRepo, ID: id}); err != nil {
						return err
					}
				}
			}
			if _, err := db.Exec(ctx, "UPDATE `package` SET id=id WHERE id=?", packageID); err != nil {
				return err
			}
			if err := authz_model.LockFeatures(ctx, []authz.FeatureKey{authz.FeaturePackages}); err != nil {
				if denied := authz_service.FeatureGuardError(err); denied != nil {
					return denied
				}
			}
		}
		if err := RequirePackageFeature(ctx, pkg); err != nil {
			return err
		}
		if repoID > 0 {
			repo, err := repo_model.GetRepositoryByID(ctx, repoID)
			if err != nil {
				return err
			}
			if repo.OwnerID != pkg.OwnerID {
				return util.ErrPermissionDenied
			}
			if err := authz_service.RequireRepoFeature(ctx, repoID, authz.FeaturePackages); err != nil {
				return err
			}
		}
		return packages_model.SetRepositoryLink(ctx, packageID, repoID)
	})
}

func RebuildIndexAfterPackageCleanup(ctx context.Context, ownerID int64, kind packages_model.Type, rebuild func(context.Context) error) error {
	return rebuild(packages_model.WithCleanupIndexMaintenance(ctx, ownerID, kind))
}

func RequireDerivedIndexFeature(ctx context.Context, ownerID int64, kind packages_model.Type) error {
	if !setting.EnterpriseAuthz.Enabled {
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := authz_service.RequireOwnerFeature(bounded, ownerID, authz.FeaturePackages); err != nil {
		return err
	}
	var policy *authz_service.FeaturePolicy
	read := func(tx context.Context) error {
		hidden, err := packages_model.HasFeatureDeniedPackages(tx, ownerID, kind)
		if err != nil || !hidden {
			return err
		}
		owner, err := user_model.GetUserByID(tx, ownerID)
		if err != nil {
			return err
		}
		scope := authz_model.Scope{Type: authz_model.ScopeSystem}
		if owner.IsOrganization() {
			scope = authz_model.Scope{Type: authz_model.ScopeOrg, ID: owner.ID}
		}
		policy, err = authz_service.GetFeaturePolicy(tx, authz.FeaturePackages, scope)
		return err
	}
	var err error
	if db.InTransaction(ctx) {
		err = read(bounded)
	} else {
		err = db.WithIndependentReadTx(bounded, read)
	}
	if err != nil {
		return authz_service.FeatureGuardError(err)
	}
	if policy == nil {
		return nil
	}
	return authz_service.RecordDerivedPackageIndexDecision(ctx, ownerID, string(kind), policy)
}

func withPackageVersionWrite(ctx context.Context, versionID int64, write func(context.Context, *packages_model.PackageVersion) error) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		current, err := packages_model.GetVersionByID(ctx, versionID)
		if err != nil {
			return err
		}
		pkg, err := packages_model.GetPackageByID(ctx, current.PackageID)
		if err != nil {
			return err
		}
		if err := RequirePackageWriteFeature(ctx, pkg); err != nil {
			return err
		}
		return write(ctx, current)
	})
}

func UpdatePackageVersionMetadata(ctx context.Context, pv *packages_model.PackageVersion) error {
	return withPackageVersionWrite(ctx, pv.ID, func(ctx context.Context, current *packages_model.PackageVersion) error {
		_, err := db.GetEngine(ctx).ID(current.ID).Cols("metadata_json").Update(&packages_model.PackageVersion{MetadataJSON: pv.MetadataJSON})
		return err
	})
}

func UpdatePackageVersionProperty(ctx context.Context, pv *packages_model.PackageVersion, property *packages_model.PackageProperty) error {
	return withPackageVersionWrite(ctx, pv.ID, func(ctx context.Context, current *packages_model.PackageVersion) error {
		actual, exists, err := db.Get[packages_model.PackageProperty](ctx, builder.Eq{"id": property.ID, "ref_type": packages_model.PropertyTypeVersion, "ref_id": current.ID})
		if err != nil {
			return err
		}
		if !exists {
			return util.ErrNotExist
		}
		actual.Value = property.Value
		return packages_model.UpdateProperty(ctx, actual)
	})
}

func InsertPackageVersionProperty(ctx context.Context, pv *packages_model.PackageVersion, name, value string) error {
	return withPackageVersionWrite(ctx, pv.ID, func(ctx context.Context, current *packages_model.PackageVersion) error {
		_, err := packages_model.InsertProperty(ctx, packages_model.PropertyTypeVersion, current.ID, name, value)
		return err
	})
}

func YankCargoVersionForCleanup(ctx context.Context, versionID int64) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		pv, err := packages_model.GetVersionByID(ctx, versionID)
		if err != nil {
			return err
		}
		pkg, err := packages_model.GetPackageByID(ctx, pv.PackageID)
		if err != nil {
			return err
		}
		if pkg.Type != packages_model.TypeCargo || pkg.IsInternal || pv.IsInternal {
			return util.ErrPermissionDenied
		}
		property, exists, err := db.Get[packages_model.PackageProperty](ctx, builder.Eq{"ref_type": packages_model.PropertyTypeVersion, "ref_id": pv.ID, "name": cargo_module.PropertyYanked})
		if err != nil {
			return err
		}
		if !exists {
			return util.ErrNotExist
		}
		property.Value = "true"
		return packages_model.UpdateProperty(ctx, property)
	})
}
