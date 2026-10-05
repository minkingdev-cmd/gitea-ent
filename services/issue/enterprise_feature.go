// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package issue

import (
	"context"

	issues_model "gitea.dev/models/issues"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func RequireFeature(ctx context.Context, issue *issues_model.Issue) error {
	if issue == nil {
		return util.ErrInvalidArgument
	}
	return requireRepoFeature(ctx, issue.RepoID, issue.IsPull)
}

func requireRepoFeature(ctx context.Context, repoID int64, isPull bool) error {
	key := authz.FeatureIssues
	if isPull {
		key = authz.FeaturePullRequests
	}
	return authz_service.RequireRepoFeature(ctx, repoID, key)
}

func requireCommentFeature(ctx context.Context, comment *issues_model.Comment) error {
	if !setting.EnterpriseAuthz.Enabled {
		return nil
	}
	if err := comment.LoadIssue(ctx); err != nil {
		return err
	}
	return RequireFeature(ctx, comment.Issue)
}
