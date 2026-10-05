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

var errSeedIncomplete = errors.New("authz_seed_incomplete")

func CheckReady(ctx context.Context) error {
	if !setting.EnterpriseAuthz.Enabled {
		return nil
	}
	for _, table := range []any{new(RoleDefinition), new(RolePermission), new(SubjectRoleBinding), new(DecisionRecord), new(FeatureDefinition), new(FeatureGrant), new(CargoIndexSource)} {
		exists, err := db.GetEngine(ctx).IsTableExist(table)
		if err != nil {
			return errors.New("authz_preflight_failed")
		}
		if !exists {
			return errors.New("authz_schema_missing")
		}
	}
	if _, err := db.GetEngine(ctx).Query("SELECT decision_mode, authorization_decision, authorization_reason, execution_started FROM enterprise_authz_decision WHERE 1=0"); err != nil {
		return errors.New("authz_schema_missing")
	}
	tables, err := db.GetEngine(ctx).Context(ctx).Engine().DBMetas()
	if err != nil {
		return errors.New("authz_preflight_failed")
	}
	for _, required := range []struct {
		table string
		cols  []string
	}{{"enterprise_feature_definition", []string{"key"}}, {"enterprise_feature_grant", []string{"feature_key", "scope_type", "scope_id"}}, {"enterprise_cargo_index_source", []string{"index_repo_id", "source_repo_id"}}} {
		found := false
		for _, table := range tables {
			if table.Name != required.table {
				continue
			}
			for _, index := range table.Indexes {
				if index.Type == schemas.UniqueType && slices.Equal(index.Cols, required.cols) {
					found = true
				}
			}
		}
		if !found {
			return errors.New("authz_schema_missing")
		}
	}
	if _, err := db.GetEngine(ctx).Query("SELECT id, feature_key, scope_type, scope_id, state, config_json, revision, created_by, updated_by, created_unix, updated_unix FROM enterprise_feature_grant WHERE 1=0"); err != nil {
		return errors.New("authz_schema_missing")
	}
	if _, err := db.GetEngine(ctx).Query("SELECT internal_usage FROM repository WHERE 1=0"); err != nil {
		return errors.New("authz_schema_missing")
	}
	if _, err := db.GetEngine(ctx).Query("SELECT id, index_repo_id, source_repo_id FROM enterprise_cargo_index_source WHERE 1=0"); err != nil {
		return errors.New("authz_schema_missing")
	}
	if err := CheckCargoIndexPurposes(ctx); err != nil {
		return err
	}
	if _, err := db.GetEngine(ctx).Query("SELECT source_repo_id, source_owner_id, source_resolved FROM hook_task WHERE 1=0"); err != nil {
		return errors.New("authz_schema_missing")
	}
	err = db.WithIndependentReadTx(ctx, func(ctx context.Context) error {
		for key, actions := range authz.BuiltinRoles() {
			role := new(RoleDefinition)
			exists, err := db.GetEngine(ctx).Where("builtin_key = ?", key).Get(role)
			if err != nil {
				return errors.New("authz_preflight_failed")
			}
			if !exists || role.ScopeType != ScopeSystem || role.ScopeID != 0 || role.Revision != 1 {
				return errSeedIncomplete
			}
			var permissions []RolePermission
			if err := db.GetEngine(ctx).Where("role_id = ?", role.ID).Find(&permissions); err != nil {
				return errors.New("authz_preflight_failed")
			}
			if len(permissions) != len(actions) {
				return errSeedIncomplete
			}
			seen := make(map[authz.Action]bool)
			for _, p := range permissions {
				_, normalized, hash, err := authz.ParseCondition([]byte(p.ConditionJSON))
				if err != nil || normalized != "{}" || hash != p.ConditionHash || p.Effect != "allow" || !slices.Contains(actions, p.Action) || seen[p.Action] {
					return errSeedIncomplete
				}
				seen[p.Action] = true
			}
		}
		return CheckFeatureReady(ctx)
	})
	if err != nil && !errors.Is(err, errSeedIncomplete) {
		return errors.New("authz_preflight_failed")
	}
	return err
}

func CheckCargoIndexPurposes(ctx context.Context) error {
	rows, err := db.GetEngine(ctx).Query("SELECT owner_id FROM repository WHERE internal_usage='cargo-index' GROUP BY owner_id HAVING COUNT(*)>1")
	if err != nil {
		return errors.New("authz_preflight_failed")
	}
	if len(rows) > 0 {
		return errors.New("cargo_index_purpose_conflict")
	}
	exists, err := db.GetEngine(ctx).IsTableExist("package")
	if err != nil {
		return errors.New("authz_preflight_failed")
	}
	if !exists {
		return nil
	}
	rows, err = db.GetEngine(ctx).Query("SELECT r.id FROM repository r WHERE r.lower_name='_cargo-index' AND r.internal_usage='' AND EXISTS (SELECT 1 FROM package p WHERE p.owner_id=r.owner_id AND p.type='cargo') LIMIT 1")
	if err != nil {
		return errors.New("authz_preflight_failed")
	}
	if len(rows) > 0 {
		return errors.New("cargo_index_purpose_unresolved")
	}
	return nil
}
