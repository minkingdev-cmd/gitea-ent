// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	"gitea.dev/models/organization"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	"gitea.dev/services/audit"
)

type (
	accessInitializationKey struct{}
	accessInitialization    struct{ repoID, ownerID, creatorID int64 }
)

func recordAccessMaintenance(ctx context.Context, action audit_model.Action, repo *repo_model.Repository, kind string, metadata ...any) error {
	auditCtx, check := audit.WithRequiredPersistence(audit.WithOrigin(ctx, audit_model.OriginSystem))
	audit.RecordAs(auditCtx, user_model.NewCliUser(), action, repo, append([]any{"maintenance", kind}, metadata...)...)
	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
		return check()
	}
	return nil
}

func initializeRepositoryCreatorAccess(ctx context.Context, repo *repo_model.Repository, creator *user_model.User) error {
	marker, ok := ctx.Value(accessInitializationKey{}).(accessInitialization)
	if !ok || !db.InTransaction(ctx) || creator == nil || marker.repoID != repo.ID || marker.ownerID != repo.OwnerID || marker.creatorID != creator.ID {
		return util.ErrPermissionDenied
	}
	if err := recordAccessMaintenance(ctx, audit_model.RepositoryCollaboratorAdd, repo, "repository-creator-initialization", "collaborator", creator.Name, "access_mode", perm.AccessModeAdmin.ToString()); err != nil {
		return err
	}
	return addOrUpdateCollaborator(ctx, repo, creator, perm.AccessModeAdmin)
}

func initializeRepositoryTeamAccess(ctx context.Context, team *organization.Team, repo *repo_model.Repository) error {
	marker, ok := ctx.Value(accessInitializationKey{}).(accessInitialization)
	if !ok || !db.InTransaction(ctx) || marker.repoID != repo.ID || marker.ownerID != repo.OwnerID || team.OrgID != repo.OwnerID || !team.IncludesAllRepositories {
		return util.ErrPermissionDenied
	}
	if err := recordAccessMaintenance(ctx, audit_model.RepositoryCollaboratorTeamAdd, repo, "repository-all-teams-initialization", "team", team.Name); err != nil {
		return err
	}
	return addRepositoryToTeam(ctx, team, repo)
}

func DeleteCollaborationBlockedUser(ctx context.Context, repo *repo_model.Repository, collaborator, doer *user_model.User, blockerID, blockeeID int64) error {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return deleteCollaboration(ctx, repo, collaborator, &repo_model.Collaboration{RepoID: repo.ID, UserID: collaborator.ID})
	}
	if repo == nil || collaborator == nil || doer == nil || !db.InTransaction(ctx) {
		return util.ErrPermissionDenied
	}
	current, err := repo_model.GetRepositoryByID(ctx, repo.ID)
	if err != nil {
		return err
	}
	if current.OwnerID != repo.OwnerID || !((repo.OwnerID == blockerID && collaborator.ID == blockeeID) || (repo.OwnerID == blockeeID && collaborator.ID == blockerID)) {
		return util.ErrPermissionDenied
	}
	block, err := user_model.GetBlocking(ctx, blockerID, blockeeID)
	if err != nil {
		return err
	}
	if block == nil {
		return util.ErrPermissionDenied
	}
	actor, err := user_model.GetUserByID(ctx, doer.ID)
	if err != nil {
		return err
	}
	if !actor.IsIndividual() || !actor.IsActive || actor.ProhibitLogin || actor.ID == blockeeID {
		return util.ErrPermissionDenied
	}
	trusted, err := access_model.HasSystemManagementAuthority(ctx, actor)
	if err != nil {
		return err
	}
	if !trusted && actor.ID != blockerID {
		blocker, err := user_model.GetUserByID(ctx, blockerID)
		if err != nil {
			return err
		}
		if !blocker.IsOrganization() {
			return util.ErrPermissionDenied
		}
		owner, err := organization.IsOrganizationOwner(ctx, blockerID, actor.ID)
		if err != nil {
			return err
		}
		if !owner {
			return util.ErrPermissionDenied
		}
	}
	if err := recordAccessMaintenance(ctx, audit_model.RepositoryCollaboratorRemove, repo, "blocked-user-cleanup", "collaborator", collaborator.Name); err != nil {
		return err
	}
	return deleteCollaboration(ctx, repo, collaborator, &repo_model.Collaboration{RepoID: repo.ID, UserID: collaborator.ID})
}
