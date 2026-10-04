// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"

	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/globallock"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func SetArchiveRepoState(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, isArchived bool) (err error) {
	var observation *authz_service.Observation
	if !setting.EnterpriseAuthz.Enforce {
		ctx, observation = authz_service.WithRepoMutationObservation(ctx, doer, repo, authz.Archive)
	}
	release, err := globallock.Lock(ctx, getRepoWorkingLockKey(repo.ID))
	if err != nil {
		return err
	}
	defer release()
	doer, err = refreshLifecycleTarget(ctx, doer, repo)
	if err != nil {
		return err
	}
	if err = checkLifecycleArchiveNative(ctx, doer, repo); err != nil {
		return err
	}
	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce && isArchived && repo.IsMirror {
		return util.ErrPermissionDenied
	}
	ctx, admission, err := beginLifecycleExecution(ctx, doer, repo, authz.Archive, authz_service.ArchiveIntent(isArchived), 0)
	if err != nil {
		return err
	}
	defer func() { finishLifecycleExecution(ctx, admission, err) }()
	defer func() {
		outcome := authz_service.NativeSuccess
		if err != nil {
			outcome = authz_service.NativeFailed
		}
		observation.Finish(ctx, outcome, authz_service.StageOperation)
	}()
	return repo_model.SetArchiveRepoState(ctx, repo, isArchived)
}

func CheckArchiveRepoState(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, archived bool) error {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return nil
	}
	doer, err := refreshLifecycleTarget(ctx, doer, repo)
	if err != nil {
		return err
	}
	if err := checkLifecycleArchiveNative(ctx, doer, repo); err != nil {
		return err
	}
	if archived && repo.IsMirror {
		return &authz_service.ExecutionError{Reason: "native_visibility_denied", Status: 403}
	}
	return nil
}
