// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"context"
	"errors"

	"gitea.dev/modelmigration/base"

	"xorm.io/xorm"
)

type authzDecisionV362 struct {
	ID                    int64  `xorm:"pk autoincr"`
	DecisionMode          string `xorm:"VARCHAR(16) NOT NULL DEFAULT 'shadow' INDEX"`
	AuthorizationDecision string `xorm:"VARCHAR(16) NOT NULL DEFAULT 'not_enforced' INDEX"`
	AuthorizationReason   string `xorm:"VARCHAR(64) NOT NULL DEFAULT ''"`
	ExecutionStarted      bool   `xorm:"NOT NULL DEFAULT false"`
}

func (*authzDecisionV362) TableName() string { return "enterprise_authz_decision" }

type authzRoleV362 struct {
	ID         int64
	ScopeType  string
	ScopeID    int64
	LowerName  string
	BuiltinKey *string
	Revision   int64
}

func (*authzRoleV362) TableName() string { return "enterprise_role_definition" }

type authzPermissionV362 struct {
	ID            int64  `xorm:"pk autoincr"`
	RoleID        int64  `xorm:"NOT NULL UNIQUE(permission) INDEX"`
	Action        string `xorm:"VARCHAR(64) NOT NULL UNIQUE(permission)"`
	Effect        string `xorm:"VARCHAR(16) NOT NULL"`
	ConditionJSON string `xorm:"TEXT NOT NULL"`
	ConditionHash string `xorm:"VARCHAR(64) NOT NULL UNIQUE(permission)"`
}

func (*authzPermissionV362) TableName() string { return "enterprise_role_permission" }

func AddEnterpriseAuthzEnforcement(ctx context.Context, x base.EngineMigration) error {
	if _, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true, IgnoreConstrains: true}, new(authzDecisionV362)); err != nil {
		return err
	}
	sess := x.NewSession().Context(ctx)
	defer sess.Close()
	if err := sess.Begin(); err != nil {
		return err
	}
	for _, key := range []string{"owner", "platform-admin"} {
		role := new(authzRoleV362)
		has, err := sess.Where("builtin_key = ?", key).Get(role)
		if err != nil {
			return err
		}
		if !has || role.ScopeType != "system" || role.ScopeID != 0 || role.LowerName != key || role.Revision != 1 {
			return errors.New("builtin_role_conflict")
		}
		var permissions []authzPermissionV362
		if err := sess.Where("role_id = ? AND action = ?", role.ID, "repo.manage_access").Find(&permissions); err != nil {
			return err
		}
		const hash = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
		if len(permissions) > 1 {
			return errors.New("builtin_permission_conflict")
		}
		if len(permissions) == 1 {
			p := permissions[0]
			if p.Effect != "allow" || p.ConditionJSON != "{}" || p.ConditionHash != hash {
				return errors.New("builtin_permission_conflict")
			}
			continue
		}
		if _, err := sess.Insert(&authzPermissionV362{RoleID: role.ID, Action: "repo.manage_access", Effect: "allow", ConditionJSON: "{}", ConditionHash: hash}); err != nil {
			return err
		}
	}
	return sess.Commit()
}
