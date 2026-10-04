// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"
	"slices"

	"gitea.dev/models/db"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/log"
	actions_service "gitea.dev/services/actions"
	authz_service "gitea.dev/services/enterpriseauthz"
)

// UpdateRepositoryUnits updates a repository's units
func UpdateRepositoryUnits(ctx context.Context, repo *repo_model.Repository, units []repo_model.RepoUnit, deleteUnitTypes []unit.Type) (err error) {
	managesCI := slices.Contains(deleteUnitTypes, unit.TypeActions)
	for _, item := range units {
		managesCI = managesCI || item.Type == unit.TypeActions
	}
	if managesCI {
		if err := authz_service.RequireSettingsExecution(ctx, repo.ID, authz.ManageCI, authz_service.SettingsIntent(authz.ManageCI, "repo-settings")); err != nil {
			return err
		}
	}
	return db.WithTx(ctx, func(ctx context.Context) error {
		// Delete existing settings of units before adding again
		for _, u := range units {
			deleteUnitTypes = append(deleteUnitTypes, u.Type)
		}

		if slices.Contains(deleteUnitTypes, unit.TypeActions) {
			if err := actions_service.CleanRepoScheduleTasks(ctx, repo); err != nil {
				log.Error("CleanRepoScheduleTasks: %v", err)
			}
		}

		for _, u := range units {
			if u.Type == unit.TypeActions {
				if err := actions_service.DetectAndHandleSchedules(ctx, repo); err != nil {
					log.Error("DetectAndHandleSchedules: %v", err)
				}
				break
			}
		}

		if _, err = db.GetEngine(ctx).Where("repo_id = ?", repo.ID).In("type", deleteUnitTypes).Delete(new(repo_model.RepoUnit)); err != nil {
			return err
		}

		if len(units) > 0 {
			if err = db.Insert(ctx, units); err != nil {
				return err
			}
		}

		return nil
	})
}

func UpdateActionsUnitConfig(ctx context.Context, actionsUnit *repo_model.RepoUnit) error {
	if err := authz_service.RequireSettingsExecution(ctx, actionsUnit.RepoID, authz.ManageCI, authz_service.SettingsIntent(authz.ManageCI, "repo-settings")); err != nil {
		return err
	}
	return repo_model.UpdateRepoUnitConfig(ctx, actionsUnit)
}
