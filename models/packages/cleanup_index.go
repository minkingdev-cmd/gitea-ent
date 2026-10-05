// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package packages

import (
	"context"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"

	"xorm.io/builder"
)

type (
	cleanupIndexKey   struct{}
	cleanupIndexScope struct {
		ownerID int64
		kind    Type
	}
)

func WithCleanupIndexMaintenance(ctx context.Context, ownerID int64, kind Type) context.Context {
	if ownerID <= 0 {
		return ctx
	}
	switch kind {
	case TypeAlpine, TypeArch, TypeDebian, TypeRpm, TypeCargo:
		return context.WithValue(ctx, cleanupIndexKey{}, cleanupIndexScope{ownerID: ownerID, kind: kind})
	}
	return ctx
}

func CleanupIndexReadAllowed(ctx context.Context, ownerID int64, kind Type) bool {
	scope, ok := ctx.Value(cleanupIndexKey{}).(cleanupIndexScope)
	return ok && scope.ownerID == ownerID && scope.kind == kind
}

func CleanupIndexWriteAllowed(ctx context.Context, pkg *Package, version string) bool {
	if !CleanupIndexReadAllowed(ctx, pkg.OwnerID, pkg.Type) || !pkg.IsInternal || pkg.RepoID != 0 || version != "_repository" {
		return false
	}
	switch pkg.Type {
	case TypeAlpine, TypeArch, TypeDebian, TypeRpm:
		return pkg.LowerName == "_"+string(pkg.Type)
	}
	return false
}

func FeatureQueryCond(ctx context.Context, ownerID int64, kind Type) (builder.Cond, error) {
	if CleanupIndexReadAllowed(ctx, ownerID, kind) {
		return builder.NewCond(), nil
	}
	return authz_model.PackageFeatureQueryCond(ctx)
}

func packageSearchFeatureCond(ctx context.Context, opts *PackageSearchOptions) (builder.Cond, error) {
	if opts.PackageID > 0 {
		if _, ok := ctx.Value(cleanupIndexKey{}).(cleanupIndexScope); ok {
			pkg, err := GetPackageByID(ctx, opts.PackageID)
			if err != nil {
				return nil, err
			}
			return FeatureQueryCond(ctx, pkg.OwnerID, pkg.Type)
		}
	}
	return FeatureQueryCond(ctx, opts.OwnerID, opts.Type)
}

func HasFeatureDeniedPackages(ctx context.Context, ownerID int64, kind Type) (bool, error) {
	if !setting.EnterpriseAuthz.Enabled {
		return false, nil
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	definition, exists, err := db.Get[authz_model.FeatureDefinition](ctx, builder.Eq{"key": authz.FeaturePackages})
	if err != nil || !exists || definition.Validate() != nil {
		return false, authz_model.ErrFeatureQueryUnavailable
	}
	cond := authz_model.PackageFeatureCandidateCond(ctx)
	return db.GetEngine(ctx).Where(builder.Eq{"package.owner_id": ownerID, "package.type": kind, "package.is_internal": false}.And(builder.Not{cond})).Exist(new(Package))
}
