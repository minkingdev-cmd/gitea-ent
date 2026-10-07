// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"context"
	"errors"

	"gitea.dev/modelmigration/base"
	"gitea.dev/modules/timeutil"

	"xorm.io/xorm"
)

type ProtectedPathRuleV364 struct {
	ID             int64              `xorm:"pk autoincr"`
	ScopeType      string             `xorm:"VARCHAR(16) NOT NULL INDEX(scope_rule)"`
	ScopeID        int64              `xorm:"NOT NULL INDEX(scope_rule)"`
	OwnerID        int64              `xorm:"NOT NULL"`
	RequiredRoleID int64              `xorm:"NOT NULL INDEX"`
	ConfigJSON     string             `xorm:"TEXT NOT NULL"`
	Enabled        bool               `xorm:"NOT NULL"`
	Deleted        bool               `xorm:"NOT NULL DEFAULT false INDEX(scope_rule)"`
	Revision       int64              `xorm:"NOT NULL"`
	CreatedBy      int64              `xorm:"NOT NULL"`
	UpdatedBy      int64              `xorm:"NOT NULL"`
	CreatedUnix    timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix    timeutil.TimeStamp `xorm:"updated"`
}

func (*ProtectedPathRuleV364) TableName() string { return "enterprise_protected_path_rule" }

type MergeGateEvaluationV364 struct {
	ID                int64              `xorm:"pk autoincr"`
	OperationID       string             `xorm:"VARCHAR(64) NOT NULL UNIQUE(operation_attempt_phase) INDEX"`
	Attempt           int                `xorm:"NOT NULL UNIQUE(operation_attempt_phase)"`
	Phase             string             `xorm:"VARCHAR(32) NOT NULL UNIQUE(operation_attempt_phase)"`
	RepoID            int64              `xorm:"NOT NULL INDEX(repo_pull_time)"`
	PullID            int64              `xorm:"NOT NULL INDEX(repo_pull_time)"`
	IssueID           int64              `xorm:"NOT NULL"`
	ActorID           int64              `xorm:"NOT NULL INDEX"`
	ScheduledMergeID  int64              `xorm:"NOT NULL DEFAULT 0 INDEX"`
	Source            string             `xorm:"VARCHAR(32) NOT NULL"`
	Mode              string             `xorm:"VARCHAR(16) NOT NULL"`
	HeadSHA           string             `xorm:"VARCHAR(64) NOT NULL"`
	BaseSHA           string             `xorm:"VARCHAR(64) NOT NULL"`
	MergedSHA         string             `xorm:"VARCHAR(64) NOT NULL"`
	CandidateDecision string             `xorm:"VARCHAR(16) NOT NULL"`
	AdmissionDecision string             `xorm:"VARCHAR(16) NOT NULL"`
	ReasonsJSON       string             `xorm:"TEXT NOT NULL"`
	SnapshotJSON      string             `xorm:"LONGTEXT NOT NULL"`
	SnapshotVersion   int                `xorm:"NOT NULL"`
	SnapshotHash      string             `xorm:"VARCHAR(64) NOT NULL"`
	BypassRequested   bool               `xorm:"NOT NULL DEFAULT false"`
	BypassUsed        bool               `xorm:"NOT NULL DEFAULT false"`
	BypassReason      string             `xorm:"TEXT NOT NULL"`
	ExecutionState    string             `xorm:"VARCHAR(16) NOT NULL INDEX(reconcile)"`
	CreatedUnix       timeutil.TimeStamp `xorm:"created INDEX(repo_pull_time)"`
	StartedUnix       timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0 INDEX(reconcile)"`
	TerminalUnix      timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
}

func (*MergeGateEvaluationV364) TableName() string { return "enterprise_merge_gate_evaluation" }

func AddEnterpriseMergeGate(ctx context.Context, x base.EngineMigration) error {
	if _, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(ProtectedPathRuleV364), new(MergeGateEvaluationV364)); err != nil {
		return err
	}
	sess := x.NewSession().Context(ctx)
	defer sess.Close()
	if err := sess.Begin(); err != nil {
		return err
	}
	if err := SeedEnterpriseMergeGateV364(sess); err != nil {
		return err
	}
	return sess.Commit()
}

func SeedEnterpriseMergeGateV364(sess base.Session) error {
	const hash = "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	for _, key := range []string{"owner", "platform-admin"} {
		role := new(authzRoleV362)
		found, err := sess.Where("builtin_key=?", key).Get(role)
		if err != nil {
			return err
		}
		if !found || role.ScopeType != "system" || role.ScopeID != 0 || role.LowerName != key || role.Revision != 1 {
			return errors.New("builtin_role_conflict")
		}
		for _, action := range []string{"repo.manage_sensitive_paths", "repo.bypass_merge_gate"} {
			var permissions []authzPermissionV362
			if err := sess.Where("role_id=? AND action=?", role.ID, action).Find(&permissions); err != nil {
				return err
			}
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
			if _, err := sess.Insert(&authzPermissionV362{RoleID: role.ID, Action: action, Effect: "allow", ConditionJSON: "{}", ConditionHash: hash}); err != nil {
				return err
			}
		}
	}
	return nil
}
