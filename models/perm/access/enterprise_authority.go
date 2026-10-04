// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package access

import (
	"context"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	"gitea.dev/models/perm"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
)

func HasSystemManagementAuthority(ctx context.Context, actor *user_model.User) (bool, error) {
	if actor == nil || !actor.IsAdmin {
		return false, nil
	}
	if !setting.EnterpriseWeCom.Enabled {
		return true, nil
	}
	return wecom_model.IsActiveManagementAuthorityBoundUser(ctx, setting.EnterpriseWeCom.CorpID, setting.EnterpriseWeCom.AgentID, actor.ID)
}

func HasOrganizationManagementAuthority(ctx context.Context, actor *user_model.User, orgID int64) (bool, error) {
	if actor == nil {
		return false, nil
	}
	if allowed, err := HasSystemManagementAuthority(ctx, actor); err != nil || allowed {
		return allowed, err
	}
	return organization.IsOrganizationOwner(ctx, orgID, actor.ID)
}

func HasEnterpriseRepoAuthorization(ctx context.Context, actor *user_model.User, repo *repo_model.Repository) (bool, error) {
	if actor == nil || repo == nil {
		return false, nil
	}
	allowed, err := wecom_model.IsActiveManagementAuthorityBoundUser(ctx, setting.EnterpriseWeCom.CorpID, setting.EnterpriseWeCom.AgentID, actor.ID)
	if err != nil || allowed {
		return allowed, err
	}
	governance := &wecom_model.RepositoryGovernance{RepoID: repo.ID}
	has, err := db.GetEngine(ctx).Get(governance)
	if err != nil {
		return false, err
	}
	if has && governance.CreatorID == actor.ID {
		return true, nil
	}
	owner, err := user_model.GetUserByID(ctx, repo.OwnerID)
	if err != nil {
		return false, err
	}
	if !owner.IsOrganization() {
		return actor.ID == owner.ID, nil
	}
	teams, err := organization.GetUserRepoTeams(ctx, owner.ID, actor.ID, repo.ID)
	if err != nil {
		return false, err
	}
	for _, team := range teams {
		if team.IsOwnerTeam() || team.AccessMode == perm.AccessModeOwner {
			return true, nil
		}
	}
	return false, nil
}
