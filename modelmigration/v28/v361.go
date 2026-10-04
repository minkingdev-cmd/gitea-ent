// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"gitea.dev/modelmigration/base"
	"gitea.dev/modules/timeutil"

	"xorm.io/xorm"
)

type authzRoleDefinitionV361 struct {
	ID          int64              `xorm:"pk autoincr"`
	ScopeType   string             `xorm:"VARCHAR(16) NOT NULL UNIQUE(scope_name)"`
	ScopeID     int64              `xorm:"NOT NULL UNIQUE(scope_name)"`
	Name        string             `xorm:"VARCHAR(64) NOT NULL"`
	LowerName   string             `xorm:"VARCHAR(64) NOT NULL UNIQUE(scope_name)"`
	Description string             `xorm:"TEXT"`
	BuiltinKey  *string            `xorm:"VARCHAR(64) UNIQUE"`
	Revision    int64              `xorm:"NOT NULL DEFAULT 1"`
	CreatedBy   int64              `xorm:"NOT NULL"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

func (*authzRoleDefinitionV361) TableName() string { return "enterprise_role_definition" }

type authzRolePermissionV361 struct {
	ID            int64  `xorm:"pk autoincr"`
	RoleID        int64  `xorm:"NOT NULL UNIQUE(permission) INDEX"`
	Action        string `xorm:"VARCHAR(64) NOT NULL UNIQUE(permission)"`
	Effect        string `xorm:"VARCHAR(16) NOT NULL"`
	ConditionJSON string `xorm:"TEXT NOT NULL"`
	ConditionHash string `xorm:"VARCHAR(64) NOT NULL UNIQUE(permission)"`
}

func (*authzRolePermissionV361) TableName() string { return "enterprise_role_permission" }

type authzBindingV361 struct {
	ID           int64              `xorm:"pk autoincr"`
	SubjectType  string             `xorm:"VARCHAR(16) NOT NULL UNIQUE(binding)"`
	SubjectID    int64              `xorm:"NOT NULL UNIQUE(binding)"`
	ScopeType    string             `xorm:"VARCHAR(16) NOT NULL UNIQUE(binding)"`
	ScopeID      int64              `xorm:"NOT NULL UNIQUE(binding) INDEX"`
	ScopeOwnerID int64              `xorm:"NOT NULL UNIQUE(binding)"`
	RoleID       int64              `xorm:"NOT NULL UNIQUE(binding) INDEX"`
	CreatedBy    int64              `xorm:"NOT NULL"`
	CreatedUnix  timeutil.TimeStamp `xorm:"created"`
}

func (*authzBindingV361) TableName() string { return "enterprise_subject_role_binding" }

type authzDecisionV361 struct {
	ID                int64              `xorm:"pk autoincr"`
	ObservationID     string             `xorm:"VARCHAR(64) NOT NULL UNIQUE"`
	OperationID       string             `xorm:"VARCHAR(64) NOT NULL INDEX"`
	ActorID           int64              `xorm:"NOT NULL INDEX(actor_time)"`
	RepoID            int64              `xorm:"NOT NULL INDEX(repo_time)"`
	OwnerID           int64              `xorm:"NOT NULL"`
	Action            string             `xorm:"VARCHAR(64) NOT NULL INDEX(action_time)"`
	RequestSource     string             `xorm:"VARCHAR(32) NOT NULL"`
	CandidateDecision string             `xorm:"VARCHAR(16) NOT NULL INDEX(decision_time)"`
	Reason            string             `xorm:"VARCHAR(64) NOT NULL"`
	MissingActions    string             `xorm:"TEXT NOT NULL"`
	NativeOutcome     string             `xorm:"VARCHAR(16) NOT NULL"`
	NativeStage       string             `xorm:"VARCHAR(64) NOT NULL"`
	SnapshotJSON      string             `xorm:"LONGTEXT NOT NULL"`
	CreatedUnix       timeutil.TimeStamp `xorm:"created INDEX(repo_time) INDEX(actor_time) INDEX(action_time) INDEX(decision_time)"`
}

func (*authzDecisionV361) TableName() string { return "enterprise_authz_decision" }

var authzBuiltinPermissionsV361 = map[string][]string{
	"guest":               {"repo.view_metadata"},
	"reporter":            {"repo.view_metadata", "repo.read_code", "repo.clone"},
	"developer":           {"repo.view_metadata", "repo.read_code", "repo.clone", "repo.create_branch", "repo.push_branch", "repo.create_pull_request"},
	"reviewer":            {"repo.view_metadata", "repo.read_code", "repo.clone", "repo.review_pull_request"},
	"maintainer":          {"repo.view_metadata", "repo.read_code", "repo.clone", "repo.create_branch", "repo.push_branch", "repo.create_pull_request", "repo.review_pull_request", "repo.merge_pull_request", "repo.manage_webhook", "repo.manage_ci"},
	"security-maintainer": {"repo.view_metadata", "repo.read_code", "repo.clone", "repo.review_pull_request", "repo.manage_codeowners", "repo.manage_ci"},
	"owner":               {"repo.view_metadata", "repo.read_code", "repo.clone", "repo.create_branch", "repo.push_branch", "repo.push_protected_branch", "repo.create_pull_request", "repo.review_pull_request", "repo.merge_pull_request", "repo.manage_branch_protection", "repo.manage_codeowners", "repo.manage_webhook", "repo.manage_ci", "repo.manage_secret", "repo.manage_feature_grant", "repo.migrate", "repo.transfer", "repo.archive", "repo.delete"},
	"platform-admin":      {"repo.view_metadata", "repo.read_code", "repo.clone", "repo.create_branch", "repo.push_branch", "repo.push_protected_branch", "repo.create_pull_request", "repo.review_pull_request", "repo.merge_pull_request", "repo.manage_branch_protection", "repo.manage_codeowners", "repo.manage_webhook", "repo.manage_ci", "repo.manage_secret", "repo.manage_feature_grant", "repo.migrate", "repo.transfer", "repo.archive", "repo.delete"},
}

func AddEnterpriseAuthzFoundation(ctx context.Context, x base.EngineMigration) error {
	if _, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(authzRoleDefinitionV361), new(authzRolePermissionV361), new(authzBindingV361), new(authzDecisionV361)); err != nil {
		return err
	}
	sess := x.NewSession().Context(ctx)
	defer sess.Close()
	if err := sess.Begin(); err != nil {
		return err
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte("{}")))
	keys := make([]string, 0, len(authzBuiltinPermissionsV361))
	for key := range authzBuiltinPermissionsV361 {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		role := &authzRoleDefinitionV361{}
		has, err := sess.Where("builtin_key = ?", key).Get(role)
		if err != nil {
			return err
		}
		if !has {
			role = &authzRoleDefinitionV361{ScopeType: "system", ScopeID: 0, Name: key, LowerName: key, BuiltinKey: &key, Revision: 1}
			if _, err := sess.Insert(role); err != nil {
				return err
			}
		} else if role.ScopeType != "system" || role.ScopeID != 0 || role.Revision != 1 || role.LowerName != key {
			return errors.New("builtin_role_conflict")
		}
		for _, action := range authzBuiltinPermissionsV361[key] {
			permission := &authzRolePermissionV361{}
			has, err := sess.Where("role_id = ? AND action = ? AND condition_hash = ?", role.ID, action, hash).Get(permission)
			if err != nil {
				return err
			}
			if has {
				if permission.Effect != "allow" || permission.ConditionJSON != "{}" {
					return errors.New("builtin_permission_conflict")
				}
				continue
			}
			if _, err := sess.Insert(&authzRolePermissionV361{RoleID: role.ID, Action: action, Effect: "allow", ConditionJSON: "{}", ConditionHash: hash}); err != nil {
				return err
			}
		}
	}
	return sess.Commit()
}
