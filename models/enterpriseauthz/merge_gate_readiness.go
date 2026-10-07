// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"
	"slices"

	"gitea.dev/models/db"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"

	"xorm.io/xorm/schemas"
)

func CheckMergeGateReady(ctx context.Context) error {
	if !setting.EnterpriseMergeGate.Enabled {
		return nil
	}
	tables, err := db.GetEngine(ctx).Context(ctx).Engine().DBMetas()
	if err != nil {
		return errors.New("merge_gate_preflight_failed")
	}
	for _, required := range []struct {
		table   string
		columns []string
		indexes [][]string
	}{
		{"audit_event", []string{"id", "action", "actor_id", "actor_name", "actor_credential", "impersonator_id", "impersonator_name", "scope_id", "scope_type", "scope_name", "origin", "message", "metadata", "ip_address", "timestamp_unix"}, [][]string{{"scope_id", "scope_type"}, {"timestamp_unix"}}},
		{"enterprise_protected_path_rule", []string{"id", "scope_type", "scope_id", "owner_id", "required_role_id", "config_json", "enabled", "deleted", "revision", "created_by", "updated_by", "created_unix", "updated_unix"}, [][]string{{"scope_type", "scope_id", "deleted"}, {"required_role_id"}}},
		{"enterprise_merge_gate_evaluation", []string{"id", "operation_id", "attempt", "phase", "repo_id", "pull_id", "issue_id", "actor_id", "scheduled_merge_id", "source", "mode", "head_sha", "base_sha", "merged_sha", "candidate_decision", "admission_decision", "reasons_json", "snapshot_json", "snapshot_version", "snapshot_hash", "bypass_requested", "bypass_used", "bypass_reason", "execution_state", "created_unix", "started_unix", "terminal_unix"}, [][]string{{"operation_id", "attempt", "phase"}, {"repo_id", "pull_id", "created_unix"}, {"execution_state", "started_unix"}, {"scheduled_merge_id"}}},
	} {
		var stored *schemas.Table
		for _, table := range tables {
			if table.Name == required.table {
				stored = table
				break
			}
		}
		if stored == nil {
			return errors.New("merge_gate_schema_missing")
		}
		for _, column := range required.columns {
			if stored.GetColumn(column) == nil {
				return errors.New("merge_gate_schema_missing")
			}
		}
		for _, columns := range required.indexes {
			found := false
			for _, index := range stored.Indexes {
				if slices.Equal(index.Cols, columns) && (columns[0] != "operation_id" || index.Type == schemas.UniqueType) {
					found = true
					break
				}
			}
			if !found {
				return errors.New("merge_gate_schema_missing")
			}
		}
	}
	for _, key := range []string{"owner", "platform-admin"} {
		role := new(RoleDefinition)
		found, err := db.GetEngine(ctx).Where("builtin_key=?", key).Get(role)
		if err != nil {
			return errors.New("merge_gate_preflight_failed")
		}
		if !found || role.ScopeType != ScopeSystem || role.ScopeID != 0 || role.Revision != 1 {
			return errSeedIncomplete
		}
		var permissions []RolePermission
		if err := db.GetEngine(ctx).Where("role_id=?", role.ID).In("action", []authz.Action{authz.ManageSensitivePaths, authz.BypassMergeGate}).Find(&permissions); err != nil {
			return errors.New("merge_gate_preflight_failed")
		}
		if len(permissions) != 2 {
			return errSeedIncomplete
		}
		for _, permission := range permissions {
			_, canonical, hash, err := authz.ParseCondition([]byte(permission.ConditionJSON))
			if err != nil || canonical != "{}" || hash != permission.ConditionHash || permission.Effect != "allow" {
				return errSeedIncomplete
			}
		}
	}
	return nil
}
