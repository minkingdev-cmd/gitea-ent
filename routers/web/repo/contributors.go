// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	"errors"
	"net/http"

	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/templates"
	"gitea.dev/routers/common"
	"gitea.dev/services/context"
	contributors_service "gitea.dev/services/repository"
)

const (
	tplContributors templates.TplName = "repo/activity"
)

// Contributors render the page to show repository contributors graph
func Contributors(ctx *context.Context) {
	defer common.ObserveRepoRequest(ctx.Base, ctx.Doer, ctx.Repo.Repository, &ctx.Repo.Permission, authz.ViewMetadata, "web")()
	ctx.Data["Title"] = ctx.Tr("repo.activity.navbar.contributors")
	ctx.Data["PageIsActivity"] = true
	ctx.Data["PageIsContributors"] = true
	ctx.HTML(http.StatusOK, tplContributors)
}

// ContributorsData renders JSON of contributors along with their weekly commit statistics
func ContributorsData(ctx *context.Context) {
	defer common.ObserveRepoRequest(ctx.Base, ctx.Doer, ctx.Repo.Repository, &ctx.Repo.Permission, authz.ViewMetadata, "web")()
	if contributorStats, err := contributors_service.GetContributorStats(ctx, ctx.Cache, ctx.Repo.Repository, ctx.Repo.Repository.DefaultBranch); err != nil {
		if errors.Is(err, contributors_service.ErrAwaitGeneration) {
			ctx.Status(http.StatusAccepted)
			return
		}
		ctx.ServerError("GetContributorStats", err)
	} else {
		ctx.JSON(http.StatusOK, contributorStats)
	}
}
