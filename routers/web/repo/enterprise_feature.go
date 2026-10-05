// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	"errors"
	"net/http"
	"strings"

	issues_model "gitea.dev/models/issues"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
	issue_service "gitea.dev/services/issue"
)

func featureErrorStatus(err error) int {
	if rejection, ok := errors.AsType[*authz_service.ExecutionError](err); ok {
		return rejection.Status
	}
	return http.StatusForbidden
}

func featureHTTPError(ctx *context.Context, err error) bool {
	if err == nil {
		return false
	}
	status := featureErrorStatus(err)
	ctx.HTTPError(status, "", err.Error())
	return true
}

func requireRepoFeature(ctx *context.Context, key authz.FeatureKey) bool {
	return !featureHTTPError(ctx, authz_service.RequireRepoFeature(ctx, ctx.Repo.Repository.ID, key))
}

// MustAllowIssueOrPullFeature uses the object type even for legacy PR issue URLs.
func MustAllowIssueOrPullFeature(ctx *context.Context) {
	if index := ctx.PathParamInt64("index"); index > 0 {
		issue, err := issues_model.GetIssueByIndex(ctx, ctx.Repo.Repository.ID, index)
		if err != nil {
			ctx.NotFoundOrServerError("GetIssueByIndex", issues_model.IsErrIssueNotExist, err)
			return
		}
		featureHTTPError(ctx, issue_service.RequireFeature(ctx, issue))
		return
	}
	if id := ctx.PathParamInt64("id"); id > 0 && strings.Contains(ctx.Req.URL.Path, "/comments/") {
		comment, err := issues_model.GetCommentByID(ctx, id)
		if err != nil {
			ctx.NotFoundOrServerError("GetCommentByID", issues_model.IsErrCommentNotExist, err)
			return
		}
		if err := comment.LoadIssue(ctx); err != nil {
			ctx.ServerError("LoadIssue", err)
			return
		}
		if comment.Issue.RepoID != ctx.Repo.Repository.ID {
			ctx.NotFound(nil)
			return
		}
		featureHTTPError(ctx, issue_service.RequireFeature(ctx, comment.Issue))
		return
	}
	// Unlinked uploads and shared labels/milestones can serve either business type.
	if authz_service.RequireRepoFeature(ctx, ctx.Repo.Repository.ID, authz.FeatureIssues) == nil {
		return
	}
	featureHTTPError(ctx, authz_service.RequireRepoFeature(ctx, ctx.Repo.Repository.ID, authz.FeaturePullRequests))
}

func MustAllowIssueFeature(ctx *context.Context) { requireRepoFeature(ctx, authz.FeatureIssues) }
func MustAllowPullFeature(ctx *context.Context)  { requireRepoFeature(ctx, authz.FeaturePullRequests) }
