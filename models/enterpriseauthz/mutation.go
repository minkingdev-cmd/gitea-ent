// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"

	"gitea.dev/models/db"
	"gitea.dev/modules/timeutil"
)

func InsertRoleIfAbsent(ctx context.Context, role *RoleDefinition) (bool, error) {
	role.CreatedUnix, role.UpdatedUnix = timeutil.TimeStampNow(), timeutil.TimeStampNow()
	result, err := db.Exec(ctx, "INSERT INTO `enterprise_role_definition` (scope_type, scope_id, name, lower_name, description, revision, created_by, created_unix, updated_unix) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (scope_type, scope_id, lower_name) DO NOTHING",
		role.ScopeType, role.ScopeID, role.Name, role.LowerName, role.Description, role.Revision, role.CreatedBy, role.CreatedUnix, role.UpdatedUnix)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil || n == 0 {
		return false, err
	}
	var stored RoleDefinition
	has, err := db.GetEngine(ctx).Where("scope_type = ? AND scope_id = ? AND lower_name = ?", role.ScopeType, role.ScopeID, role.LowerName).Get(&stored)
	if err == nil && !has {
		return false, errors.New("policy_row_missing")
	}
	if err == nil {
		*role = stored
	}
	return true, err
}

func InsertBindingIfAbsent(ctx context.Context, binding *SubjectRoleBinding) (bool, error) {
	binding.CreatedUnix = timeutil.TimeStampNow()
	result, err := db.Exec(ctx, "INSERT INTO `enterprise_subject_role_binding` (subject_type, subject_id, scope_type, scope_id, scope_owner_id, role_id, created_by, created_unix) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (subject_type, subject_id, scope_type, scope_id, scope_owner_id, role_id) DO NOTHING",
		binding.SubjectType, binding.SubjectID, binding.ScopeType, binding.ScopeID, binding.ScopeOwnerID, binding.RoleID, binding.CreatedBy, binding.CreatedUnix)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	var stored SubjectRoleBinding
	has, err := db.GetEngine(ctx).Where("subject_type = ? AND subject_id = ? AND scope_type = ? AND scope_id = ? AND scope_owner_id = ? AND role_id = ?", binding.SubjectType, binding.SubjectID, binding.ScopeType, binding.ScopeID, binding.ScopeOwnerID, binding.RoleID).Get(&stored)
	if err == nil && !has {
		return false, errors.New("policy_row_missing")
	}
	if err == nil {
		*binding = stored
	}
	return n != 0, err
}
