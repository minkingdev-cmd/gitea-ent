// Copyright 2022 The Gitea Authors.
// All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"errors"

	issues_model "gitea.dev/models/issues"
	access_model "gitea.dev/models/perm/access"
	unit_model "gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	authz_service "gitea.dev/services/enterpriseauthz"
)

var ErrUserHasNoPermissionForAction = errors.New("user not allowed to do this action")

// SetAllowEdits allow edits from maintainers to PRs
func SetAllowEdits(ctx context.Context, doer *user_model.User, pr *issues_model.PullRequest, allow bool) error {
	if err := authz_service.RequireRepoFeature(ctx, pr.BaseRepoID, authz.FeaturePullRequests); err != nil {
		return err
	}
	if doer == nil || !pr.Issue.IsPoster(doer.ID) {
		return ErrUserHasNoPermissionForAction
	}

	if err := pr.LoadHeadRepo(ctx); err != nil {
		return err
	}

	permission, err := access_model.GetDoerRepoPermission(ctx, pr.HeadRepo, doer)
	if err != nil {
		return err
	}

	if !permission.CanWrite(unit_model.TypeCode) {
		return ErrUserHasNoPermissionForAction
	}

	pr.AllowMaintainerEdit = allow
	return issues_model.UpdateAllowEdits(ctx, pr)
}
