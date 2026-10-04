// Copyright 2024 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package actions

import (
	"context"
	"strconv"

	actions_model "gitea.dev/models/actions"
	"gitea.dev/models/db"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	authz_service "gitea.dev/services/enterpriseauthz"
	secret_service "gitea.dev/services/secrets"
)

func CreateVariable(ctx context.Context, ownerID, repoID int64, name, data, description string) (*actions_model.ActionVariable, error) {
	if err := secret_service.ValidateName(name); err != nil {
		return nil, err
	}

	if repoID > 0 {
		if err := authz_service.RequireSettingsExecution(ctx, repoID, authz.ManageCI, authz_service.SettingsIntent(authz.ManageCI, "variable:create:"+name)); err != nil {
			return nil, err
		}
	}
	v, err := actions_model.InsertVariable(ctx, ownerID, repoID, name, util.NormalizeStringEOL(data), description)
	if err != nil {
		return nil, err
	}

	return v, nil
}

func UpdateVariableNameData(ctx context.Context, variable *actions_model.ActionVariable) (bool, error) {
	if err := secret_service.ValidateName(variable.Name); err != nil {
		return false, err
	}

	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
		current, exists, err := db.GetByID[actions_model.ActionVariable](ctx, variable.ID)
		if err != nil {
			return false, err
		}
		if !exists || current.RepoID != variable.RepoID || current.OwnerID != variable.OwnerID {
			return false, &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
		}
	}
	if variable.RepoID > 0 {
		if err := authz_service.RequireSettingsExecution(ctx, variable.RepoID, authz.ManageCI, authz_service.SettingsIntent(authz.ManageCI, "variable:"+strconv.FormatInt(variable.ID, 10))); err != nil {
			return false, err
		}
	}
	variable.Data = util.NormalizeStringEOL(variable.Data)

	return actions_model.UpdateVariableCols(ctx, variable, "name", "data", "description")
}

func DeleteVariableByID(ctx context.Context, variableID int64) error {
	v, exists, err := db.GetByID[actions_model.ActionVariable](ctx, variableID)
	if err != nil {
		return err
	}
	if !exists {
		return util.NewNotExistErrorf("variable not found")
	}
	if v.RepoID > 0 {
		if err := authz_service.RequireSettingsExecution(ctx, v.RepoID, authz.ManageCI, authz_service.SettingsIntent(authz.ManageCI, "variable:"+strconv.FormatInt(v.ID, 10))); err != nil {
			return err
		}
	}
	return actions_model.DeleteVariable(ctx, variableID)
}

func DeleteVariableByName(ctx context.Context, ownerID, repoID int64, name string) error {
	v, err := GetVariable(ctx, actions_model.FindVariablesOpts{
		OwnerID: ownerID,
		RepoID:  repoID,
		Name:    name,
	})
	if err != nil {
		return err
	}

	return DeleteVariableByID(ctx, v.ID)
}

func GetVariable(ctx context.Context, opts actions_model.FindVariablesOpts) (*actions_model.ActionVariable, error) {
	vars, err := actions_model.FindVariables(ctx, opts)
	if err != nil {
		return nil, err
	}
	if len(vars) != 1 {
		return nil, util.NewNotExistErrorf("variable not found")
	}
	return vars[0], nil
}
