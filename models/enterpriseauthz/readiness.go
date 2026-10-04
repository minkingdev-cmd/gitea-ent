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
)

var errSeedIncomplete = errors.New("authz_seed_incomplete")

func CheckReady(ctx context.Context) error {
	if !setting.EnterpriseAuthz.Enabled {
		return nil
	}
	for _, table := range []any{new(RoleDefinition), new(RolePermission), new(SubjectRoleBinding), new(DecisionRecord)} {
		exists, err := db.GetEngine(ctx).IsTableExist(table)
		if err != nil {
			return errors.New("authz_preflight_failed")
		}
		if !exists {
			return errors.New("authz_schema_missing")
		}
	}
	err := db.WithIndependentReadTx(ctx, func(ctx context.Context) error {
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
		return nil
	})
	if err != nil && !errors.Is(err, errSeedIncomplete) {
		return errors.New("authz_preflight_failed")
	}
	return err
}
