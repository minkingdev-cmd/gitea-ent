// Copyright 2022 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package feed

import (
	"time"

	"gitea.dev/models/db"
	repo_model "gitea.dev/models/repo"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/routers/common"
	"gitea.dev/services/context"

	"github.com/gorilla/feeds"
)

// shows tags and/or releases on the repo as RSS / Atom feed
func ShowReleaseFeed(ctx *context.Context, repo *repo_model.Repository, isReleasesOnly bool, formatType string) {
	if !checkRepoFeedTokenScope(ctx) {
		return
	}
	if !isReleasesOnly {
		defer common.ObserveRepoRequest(ctx.Base, ctx.Doer, ctx.Repo.Repository, &ctx.Repo.Permission, authz.ViewMetadata, "web")()
	}
	releases, err := db.Find[repo_model.Release](ctx, repo_model.FindReleasesOptions{
		IncludeTags: !isReleasesOnly,
		RepoID:      ctx.Repo.Repository.ID,
	})
	if err != nil {
		ctx.ServerError("GetReleasesByRepoID", err)
		return
	}

	var title string
	var link *feeds.Link

	if isReleasesOnly {
		title = ctx.Locale.TrString("repo.release.releases_for", repo.FullName())
		link = &feeds.Link{Href: repo.HTMLURL() + "/release"}
	} else {
		title = ctx.Locale.TrString("repo.release.tags_for", repo.FullName())
		link = &feeds.Link{Href: repo.HTMLURL() + "/tags"}
	}

	feed := &feeds.Feed{
		Title:       title,
		Link:        link,
		Description: repo.Description,
		Created:     time.Now(),
	}

	feed.Items, err = releasesToFeedItems(ctx, releases)
	if err != nil {
		ctx.ServerError("releasesToFeedItems", err)
		return
	}

	writeFeed(ctx, feed, formatType)
}
