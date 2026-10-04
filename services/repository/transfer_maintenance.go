// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/organization"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	"gitea.dev/services/audit"
)

type (
	blockedTransferCleanupKey struct{}
	blockedTransferCleanup    struct{ blockerID, blockeeID, transferID, repoID, ownerID int64 }
)

func CancelBlockedRepositoryTransfer(ctx context.Context, transfer *repo_model.RepoTransfer, doer, blocker, blockee *user_model.User) error {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return CancelRepositoryTransfer(ctx, transfer, doer)
	}
	if doer == nil || blocker == nil || blockee == nil || transfer == nil {
		return util.ErrPermissionDenied
	}
	if err := transfer.LoadAttributes(ctx); err != nil {
		return err
	}
	marker := blockedTransferCleanup{blocker.ID, blockee.ID, transfer.ID, transfer.RepoID, transfer.Repo.OwnerID}
	ctx = context.WithValue(ctx, blockedTransferCleanupKey{}, marker)
	if ok, err := validateBlockedTransferCleanup(ctx, transfer.Repo, transfer.Recipient, doer, transfer.ID); err != nil || !ok {
		if err != nil {
			return err
		}
		return util.ErrPermissionDenied
	}
	auditCtx, check := audit.WithRequiredPersistence(audit.WithOrigin(ctx, audit_model.OriginSystem))
	audit.RecordAs(auditCtx, user_model.NewCliUser(), audit_model.RepositoryTransferCancel, transfer.Repo, "maintenance", "blocked-user-cleanup")
	if err := check(); err != nil {
		return err
	}
	return CancelRepositoryTransfer(auditCtx, transfer, doer)
}

func validateBlockedTransferCleanup(ctx context.Context, repo *repo_model.Repository, recipient, doer *user_model.User, transferID int64) (bool, error) {
	marker, ok := ctx.Value(blockedTransferCleanupKey{}).(blockedTransferCleanup)
	if !ok {
		return false, nil
	}
	if marker.transferID != transferID || marker.repoID != repo.ID || marker.ownerID != repo.OwnerID {
		return false, util.ErrPermissionDenied
	}
	if !((repo.OwnerID == marker.blockerID && recipient.ID == marker.blockeeID) || (repo.OwnerID == marker.blockeeID && recipient.ID == marker.blockerID)) {
		return false, util.ErrPermissionDenied
	}
	block, err := user_model.GetBlocking(ctx, marker.blockerID, marker.blockeeID)
	if err != nil {
		return false, err
	}
	if block == nil {
		return false, util.ErrPermissionDenied
	}
	actor, err := user_model.GetUserByID(ctx, doer.ID)
	if err != nil {
		return false, err
	}
	if !actor.IsIndividual() || !actor.IsActive || actor.ProhibitLogin {
		return false, util.ErrPermissionDenied
	}
	if actor.IsAdmin {
		actor.IsAdmin, err = access_model.HasSystemManagementAuthority(ctx, actor)
		if err != nil {
			return false, err
		}
	}
	blocker, err := user_model.GetUserByID(ctx, marker.blockerID)
	if err != nil {
		return false, err
	}
	if actor.ID == marker.blockeeID {
		return false, util.ErrPermissionDenied
	}
	if !actor.IsAdmin {
		if blocker.IsOrganization() {
			owned, err := organization.OrgFromUser(blocker).IsOwnedBy(ctx, actor.ID)
			if err != nil {
				return false, err
			}
			if !owned {
				return false, util.ErrPermissionDenied
			}
		} else if actor.ID != blocker.ID {
			return false, util.ErrPermissionDenied
		}
	}
	pending, err := repo_model.GetPendingRepositoryTransfer(ctx, repo)
	if err != nil {
		return false, err
	}
	if pending.ID != transferID || !canUserCancelTransfer(ctx, pending, actor) {
		return false, util.ErrPermissionDenied
	}
	return true, nil
}
