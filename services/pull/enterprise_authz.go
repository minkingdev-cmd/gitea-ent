// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"errors"

	issues_model "gitea.dev/models/issues"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	asymkey_service "gitea.dev/services/asymkey"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func observeMergeCheckFailure(ctx context.Context, doer *user_model.User, pr *issues_model.PullRequest, err error) {
	if err == nil || doer == nil || pr == nil {
		return
	}
	outcome := authz_service.NativeFailed
	stage := authz_service.StageOperation
	if errors.Is(err, ErrNoPermissionToMerge) || errors.Is(err, ErrNotReadyToMerge) || errors.Is(err, ErrHeadCommitsNotAllVerified) || errors.Is(err, ErrDependenciesLeft) || asymkey_service.IsErrWontSign(err) {
		outcome, stage = authz_service.NativeDenied, authz_service.StageAuthorization
	}
	authz_service.FinishOperationObservation(ctx, doer.ID, pr.BaseRepoID, authz.MergePullRequest, outcome, stage)
}
