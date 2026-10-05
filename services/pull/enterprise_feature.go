// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"

	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/modules/setting"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func requirePullCodeFeatures(ctx context.Context, pr *issues_model.PullRequest) error {
	if !setting.EnterpriseAuthz.Enabled {
		return nil
	}
	for _, id := range []int64{pr.BaseRepoID, pr.HeadRepoID} {
		if id <= 0 {
			continue
		}
		repo, err := repo_model.GetRepositoryByID(ctx, id)
		if err != nil {
			return err
		}
		if err := authz_service.RequireCargoIndexFeature(ctx, repo); err != nil {
			return err
		}
		if pr.BaseRepoID == pr.HeadRepoID {
			break
		}
	}
	return nil
}
