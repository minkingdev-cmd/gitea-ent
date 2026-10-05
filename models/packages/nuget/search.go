// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package nuget

import (
	"context"
	"strings"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	packages_model "gitea.dev/models/packages"

	"xorm.io/builder"
)

// SearchVersions gets all versions of packages matching the search options
func SearchVersions(ctx context.Context, opts *packages_model.PackageSearchOptions) ([]*packages_model.PackageVersion, int64, error) {
	featureCond, err := authz_model.PackageFeatureQueryCond(ctx)
	if err != nil {
		return nil, 0, err
	}
	packages_model.ObserveFeatureSession(ctx, opts.OwnerID, packages_model.TypeNuGet, func(tx context.Context) db.Session { return db.GetEngine(tx).Table("package").Where(toConds(opts)) })
	cond := toConds(opts).And(featureCond)

	e := db.GetEngine(ctx)

	total, err := e.
		Where(cond).
		Count(&packages_model.Package{})
	if err != nil {
		return nil, 0, err
	}

	inner := builder.
		Dialect(db.BuilderDialect()). // builder needs the sql dialect to build the Limit() below
		Select("*").
		From("package").
		Where(cond).
		OrderBy("package.name ASC")
	if opts.Paginator != nil {
		skip, take := opts.Paginator.GetSkipTake()
		inner = inner.Limit(take, skip)
	}

	sess := e.
		Where(opts.ToConds().And(featureCond)).
		Table("package_version").
		Join("INNER", inner, "package.id = package_version.package_id")

	pvs := make([]*packages_model.PackageVersion, 0, 10)
	return pvs, total, sess.Find(&pvs)
}

// CountPackages counts all packages matching the search options
func CountPackages(ctx context.Context, opts *packages_model.PackageSearchOptions) (int64, error) {
	packages_model.ObserveFeatureSession(ctx, opts.OwnerID, packages_model.TypeNuGet, func(tx context.Context) db.Session { return db.GetEngine(tx).Table("package").Where(toConds(opts)) })
	featureCond, err := authz_model.PackageFeatureQueryCond(ctx)
	if err != nil {
		return 0, err
	}
	return db.GetEngine(ctx).
		Where(toConds(opts).And(featureCond)).
		Count(&packages_model.Package{})
}

func toConds(opts *packages_model.PackageSearchOptions) builder.Cond {
	var cond builder.Cond = builder.Eq{
		"package.is_internal": opts.IsInternal.Value(),
		"package.owner_id":    opts.OwnerID,
		"package.type":        packages_model.TypeNuGet,
	}
	if opts.Name.Value != "" {
		if opts.Name.ExactMatch {
			cond = cond.And(builder.Eq{"package.lower_name": strings.ToLower(opts.Name.Value)})
		} else {
			cond = cond.And(builder.Like{"package.lower_name", strings.ToLower(opts.Name.Value)})
		}
	}
	return cond
}
