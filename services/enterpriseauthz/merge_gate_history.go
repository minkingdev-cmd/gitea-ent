// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	issues_model "gitea.dev/models/issues"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/util"
)

func authorizeMergeGateHistory(ctx context.Context, actor *user_model.User, repoID, pullID int64) error {
	if repoID <= 0 || pullID <= 0 {
		return util.ErrNotExist
	}
	if actor == nil || actor.ID <= 0 || actor.ExtDoerData != nil {
		return util.ErrPermissionDenied
	}
	fresh, err := user_model.GetUserByID(ctx, actor.ID)
	if err != nil {
		return ErrPolicyStorage
	}
	if fresh.IsAdmin {
		fresh.IsAdmin, err = access_model.HasSystemManagementAuthority(ctx, fresh)
		if err != nil {
			return ErrPolicyStorage
		}
	}
	actor = fresh
	if err := authorizeProtectedPaths(ctx, actor, authz_model.Scope{Type: authz_model.ScopeRepo, ID: repoID}, false); err != nil {
		return err
	}
	repo, err := repo_model.GetRepositoryByID(ctx, repoID)
	if err != nil {
		return err
	}
	permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
	if err != nil {
		return ErrPolicyStorage
	}
	if !permission.CanRead(unit.TypeCode) || !permission.CanRead(unit.TypePullRequests) {
		return util.ErrPermissionDenied
	}
	exists, err := db.GetEngine(ctx).Where("id=? AND base_repo_id=?", pullID, repoID).Exist(new(issues_model.PullRequest))
	if err != nil {
		return ErrPolicyStorage
	}
	if !exists {
		return util.ErrNotExist
	}
	return nil
}

func ListMergeGateEvaluations(ctx context.Context, actor *user_model.User, repoID, pullID int64, options PolicyListOptions) ([]authz_model.MergeGateEvaluation, int64, error) {
	limit, offset, err := options.pagination()
	if err != nil {
		return nil, 0, err
	}
	records := make([]authz_model.MergeGateEvaluation, 0)
	var total int64
	err = db.WithIndependentReadTx(ctx, func(tx context.Context) error {
		if err := authorizeMergeGateHistory(tx, actor, repoID, pullID); err != nil {
			return err
		}
		var err error
		total, err = db.GetEngine(tx).Where("repo_id=? AND pull_id=?", repoID, pullID).OrderBy("created_unix DESC, id DESC").Limit(limit, offset).FindAndCount(&records)
		if err != nil {
			return ErrPolicyStorage
		}
		for _, record := range records {
			if record.Validate() != nil {
				return ErrPolicyStorage
			}
		}
		return nil
	})
	if err != nil {
		return nil, 0, safePolicyError(err)
	}
	return records, total, nil
}

func GetMergeGateEvaluation(ctx context.Context, actor *user_model.User, repoID, pullID, id int64) (*authz_model.MergeGateEvaluation, error) {
	if id <= 0 {
		return nil, ErrInvalidPolicy
	}
	record := new(authz_model.MergeGateEvaluation)
	err := db.WithIndependentReadTx(ctx, func(tx context.Context) error {
		if err := authorizeMergeGateHistory(tx, actor, repoID, pullID); err != nil {
			return err
		}
		exists, err := db.GetEngine(tx).Where("id=? AND repo_id=? AND pull_id=?", id, repoID, pullID).Get(record)
		if err != nil {
			return ErrPolicyStorage
		}
		if !exists {
			return util.ErrNotExist
		}
		if record.Validate() != nil {
			return ErrPolicyStorage
		}
		return nil
	})
	if err != nil {
		return nil, safePolicyError(err)
	}
	return record, nil
}
