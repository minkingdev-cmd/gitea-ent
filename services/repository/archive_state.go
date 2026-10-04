// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"

	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func SetArchiveRepoState(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, isArchived bool) (err error) {
	ctx, observation := authz_service.WithRepoMutationObservation(ctx, doer, repo, authz.Archive)
	defer func() {
		outcome := authz_service.NativeSuccess
		if err != nil {
			outcome = authz_service.NativeFailed
		}
		observation.Finish(ctx, outcome, authz_service.StageOperation)
	}()
	return repo_model.SetArchiveRepoState(ctx, repo, isArchived)
}
