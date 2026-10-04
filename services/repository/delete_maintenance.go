// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"
	"fmt"

	audit_model "gitea.dev/models/audit"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/git"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	"gitea.dev/services/audit"
)

func repositoryDeletionMaintenance(ctx context.Context, repo *repo_model.Repository, kind string) context.Context {
	return context.WithValue(ctx, repositoryDeleteMaintenanceKey{}, repositoryDeleteMaintenance{repo.ID, repo.OwnerID, kind})
}

func recordRepositoryDeletionMaintenance(ctx context.Context, repo *repo_model.Repository) error {
	maintenance, ok := ctx.Value(repositoryDeleteMaintenanceKey{}).(repositoryDeleteMaintenance)
	if !ok {
		return nil
	}
	auditCtx, check := audit.WithRequiredPersistence(audit.WithOrigin(ctx, audit_model.OriginSystem))
	audit.RecordAs(auditCtx, user_model.NewCliUser(), audit_model.RepositoryDelete, repo, "maintenance", maintenance.kind)
	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
		return check()
	}
	return nil
}

func DeleteOrphanedRepository(ctx context.Context, repoID int64) error {
	repo, err := repo_model.GetRepositoryByID(ctx, repoID)
	if err != nil {
		return err
	}
	if _, err = user_model.GetUserByID(ctx, repo.OwnerID); !user_model.IsErrUserNotExist(err) {
		if err != nil {
			return err
		}
		return util.ErrPermissionDenied
	}
	return DeleteRepositoryDirectly(repositoryDeletionMaintenance(ctx, repo, "orphan-cleanup"), repo.ID, true)
}

func DeleteFailedMigrationRepository(ctx context.Context, repoID int64) error {
	repo, err := repo_model.GetRepositoryByID(ctx, repoID)
	if err != nil {
		return err
	}
	if repo.Status != repo_model.RepositoryBeingMigrated && repo.Status != repo_model.RepositoryBroken {
		return util.ErrPermissionDenied
	}
	return DeleteRepositoryDirectly(repositoryDeletionMaintenance(ctx, repo, "failed-migration"), repo.ID)
}

func deleteMissingRepository(ctx context.Context, repo *repo_model.Repository) error {
	current, err := repo_model.GetRepositoryByID(ctx, repo.ID)
	if err != nil {
		return err
	}
	exists, err := git.IsRepositoryExist(ctx, current)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("repository %d still has Git storage", repo.ID)
	}
	return DeleteRepositoryDirectly(repositoryDeletionMaintenance(ctx, current, "missing-storage-cleanup"), current.ID)
}

func validateRepositoryDeletionMaintenance(ctx context.Context, repo *repo_model.Repository, maintenance repositoryDeleteMaintenance) error {
	if maintenance.repoID != repo.ID || maintenance.ownerID != repo.OwnerID {
		return util.ErrPermissionDenied
	}
	switch maintenance.kind {
	case "orphan-cleanup":
		_, err := user_model.GetUserByID(ctx, repo.OwnerID)
		if user_model.IsErrUserNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
	case "failed-migration":
		if repo.Status == repo_model.RepositoryBeingMigrated || repo.Status == repo_model.RepositoryBroken {
			return nil
		}
	case "missing-storage-cleanup":
		exists, err := git.IsRepositoryExist(ctx, repo)
		if err != nil {
			return err
		}
		if !exists {
			return nil
		}
	case "owner-removal":
		_, err := user_model.GetUserByID(ctx, repo.OwnerID)
		return err
	case "failed-creation":
		return nil
	}
	return util.ErrPermissionDenied
}
