// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package modelmigration

import (
	"context"
	"maps"
	"slices"

	"gitea.dev/modelmigration/base"
	"gitea.dev/modelmigration/v28"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/timeutil"
)

type authzRoleDefinitionInstall struct {
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

func (*authzRoleDefinitionInstall) TableName() string { return "enterprise_role_definition" }

type authzRolePermissionInstall struct {
	ID            int64  `xorm:"pk autoincr"`
	RoleID        int64  `xorm:"NOT NULL UNIQUE(permission) INDEX"`
	Action        string `xorm:"VARCHAR(64) NOT NULL UNIQUE(permission)"`
	Effect        string `xorm:"VARCHAR(16) NOT NULL"`
	ConditionJSON string `xorm:"TEXT NOT NULL"`
	ConditionHash string `xorm:"VARCHAR(64) NOT NULL UNIQUE(permission)"`
}

func (*authzRolePermissionInstall) TableName() string { return "enterprise_role_permission" }

type authzBindingInstall struct {
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

func (*authzBindingInstall) TableName() string { return "enterprise_subject_role_binding" }

type authzDecisionInstall struct {
	DecisionMode          string             `xorm:"VARCHAR(16) NOT NULL DEFAULT 'shadow' INDEX"`
	AuthorizationDecision string             `xorm:"VARCHAR(16) NOT NULL DEFAULT 'not_enforced' INDEX"`
	AuthorizationReason   string             `xorm:"VARCHAR(64) NOT NULL DEFAULT ''"`
	ExecutionStarted      bool               `xorm:"NOT NULL DEFAULT false"`
	ID                    int64              `xorm:"pk autoincr"`
	ObservationID         string             `xorm:"VARCHAR(64) NOT NULL UNIQUE"`
	OperationID           string             `xorm:"VARCHAR(64) NOT NULL INDEX"`
	ActorID               int64              `xorm:"NOT NULL INDEX(actor_time)"`
	RepoID                int64              `xorm:"NOT NULL INDEX(repo_time)"`
	OwnerID               int64              `xorm:"NOT NULL"`
	Action                string             `xorm:"VARCHAR(64) NOT NULL INDEX(action_time)"`
	RequestSource         string             `xorm:"VARCHAR(32) NOT NULL"`
	CandidateDecision     string             `xorm:"VARCHAR(16) NOT NULL INDEX(decision_time)"`
	Reason                string             `xorm:"VARCHAR(64) NOT NULL"`
	MissingActions        string             `xorm:"TEXT NOT NULL"`
	NativeOutcome         string             `xorm:"VARCHAR(16) NOT NULL"`
	NativeStage           string             `xorm:"VARCHAR(64) NOT NULL"`
	SnapshotJSON          string             `xorm:"LONGTEXT NOT NULL"`
	CreatedUnix           timeutil.TimeStamp `xorm:"created INDEX(repo_time) INDEX(actor_time) INDEX(action_time) INDEX(decision_time)"`
}

func (*authzDecisionInstall) TableName() string { return "enterprise_authz_decision" }

func initializeFreshDatabase(ctx context.Context, x base.EngineMigration, version int64) error {
	sess := x.NewSession().Context(ctx)
	defer sess.Close()
	if err := sess.Begin(); err != nil {
		return err
	}
	if err := sess.Sync(new(Version), new(authzRoleDefinitionInstall), new(authzRolePermissionInstall), new(authzBindingInstall), new(authzDecisionInstall), new(v28.FeatureDefinitionV363), new(v28.FeatureGrantV363), new(v28.FeatureHookTaskV363), new(v28.FeatureRepositoryV363), new(v28.FeatureCargoSourceV363)); err != nil {
		return err
	}
	if err := v28.SeedEnterpriseFeaturesV363(sess); err != nil {
		return err
	}
	roles := authz.BuiltinRoles()
	const hash = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	for _, key := range slices.Sorted(maps.Keys(roles)) {
		role := &authzRoleDefinitionInstall{ScopeType: "system", Name: key, LowerName: key, BuiltinKey: &key, Revision: 1}
		if _, err := sess.Insert(role); err != nil {
			return err
		}
		for _, action := range roles[key] {
			if _, err := sess.Insert(&authzRolePermissionInstall{RoleID: role.ID, Action: string(action), Effect: "allow", ConditionJSON: "{}", ConditionHash: hash}); err != nil {
				return err
			}
		}
	}
	if _, err := sess.Insert(&Version{ID: 1, Version: version}); err != nil {
		return err
	}
	return sess.Commit()
}
