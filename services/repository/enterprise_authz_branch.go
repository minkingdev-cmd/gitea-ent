// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"errors"

	git_model "gitea.dev/models/git"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/modules/git"
	"gitea.dev/modules/util"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func branchMutationOutcome(err error) authz_service.NativeOutcome {
	if err == nil {
		return authz_service.NativeSuccess
	}
	if errors.Is(err, util.ErrPermissionDenied) || errors.Is(err, git_model.ErrBranchIsProtected) || repo_model.IsErrUserDoesNotHaveAccessToRepo(err) || git.IsErrPushRejected(err) {
		return authz_service.NativeDenied
	}
	return authz_service.NativeFailed
}
