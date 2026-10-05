// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package packages

import (
	"context"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	authz "gitea.dev/modules/enterpriseauthz"

	"xorm.io/builder"
)

func ObserveFeatureQuery(ctx context.Context, ownerID int64, kind Type, probe func(context.Context, builder.Cond) (bool, error)) {
	if CleanupIndexReadAllowed(ctx, ownerID, kind) {
		return
	}
	authz_model.ObserveFeatureQuery(ctx, authz.FeaturePackages, authz_model.PackageFeatureCandidateCond(ctx), probe)
}

func observeVersionQuery(ctx context.Context, opts *PackageSearchOptions) {
	if scope, ok := ctx.Value(cleanupIndexKey{}).(cleanupIndexScope); ok && opts.PackageID > 0 && CleanupIndexReadAllowed(ctx, scope.ownerID, scope.kind) {
		return
	}

	ObserveFeatureQuery(ctx, opts.OwnerID, opts.Type, func(tx context.Context, denied builder.Cond) (bool, error) {
		return db.GetEngine(tx).Table("package_version").Join("INNER", "package", "package.id=package_version.package_id").Where(opts.ToConds().And(denied)).Exist(new(PackageVersion))
	})
}

func ObserveFeatureSession(ctx context.Context, ownerID int64, kind Type, session func(context.Context) db.Session) {
	ObserveFeatureQuery(ctx, ownerID, kind, func(tx context.Context, denied builder.Cond) (bool, error) {
		return session(tx).And(denied).Exist()
	})
}
