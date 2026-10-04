// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	"net/http"

	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/templates"
	"gitea.dev/routers/common"
	"gitea.dev/services/context"
)

const (
	tplRecentCommits templates.TplName = "repo/activity"
)

// RecentCommits renders the page to show recent commit frequency on repository
func RecentCommits(ctx *context.Context) {
	defer common.ObserveRepoRequest(ctx.Base, ctx.Doer, ctx.Repo.Repository, &ctx.Repo.Permission, authz.ViewMetadata, "web")()
	ctx.Data["Title"] = ctx.Tr("repo.activity.navbar.recent_commits")

	ctx.Data["PageIsActivity"] = true
	ctx.Data["PageIsRecentCommits"] = true
	ctx.PageData["repoLink"] = ctx.Repo.RepoLink

	ctx.HTML(http.StatusOK, tplRecentCommits)
}
