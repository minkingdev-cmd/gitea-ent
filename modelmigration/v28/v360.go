// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"context"
	"strings"

	"gitea.dev/modelmigration/base"
	"gitea.dev/modules/json"
	"gitea.dev/modules/timeutil"

	"xorm.io/xorm"
)

type GovernanceAuthzMapping struct {
	ID          int64              `xorm:"pk autoincr"`
	CorpID      string             `xorm:"VARCHAR(128) NOT NULL INDEX UNIQUE(mapping_unique)"`
	AgentID     string             `xorm:"VARCHAR(64) NOT NULL DEFAULT '' INDEX UNIQUE(mapping_unique)"`
	Origin      string             `xorm:"VARCHAR(32) NOT NULL DEFAULT 'legacy' INDEX UNIQUE(mapping_unique)"`
	SourceType  string             `xorm:"VARCHAR(32) NOT NULL UNIQUE(mapping_unique)"`
	SourceID    string             `xorm:"VARCHAR(255) NOT NULL UNIQUE(mapping_unique)"`
	TargetType  string             `xorm:"VARCHAR(32) NOT NULL UNIQUE(mapping_unique)"`
	OrgID       int64              `xorm:"INDEX NOT NULL UNIQUE(mapping_unique)"`
	TeamID      int64              `xorm:"INDEX NOT NULL DEFAULT 0 UNIQUE(mapping_unique)"`
	IsActive    bool               `xorm:"INDEX NOT NULL DEFAULT true"`
	CreatedBy   int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

func (*GovernanceAuthzMapping) TableName() string {
	return "enterprise_wecom_authz_mapping"
}

type GovernanceCoordinator struct {
	ID                int64  `xorm:"pk autoincr"`
	CorpID            string `xorm:"VARCHAR(128) NOT NULL UNIQUE(app_scope)"`
	AgentID           string `xorm:"VARCHAR(64) NOT NULL UNIQUE(app_scope)"`
	PublishedRevision int64  `xorm:"NOT NULL DEFAULT 0"`
	ManagedOrgID      int64  `xorm:"NOT NULL DEFAULT 0"`
	LeaseOwner        string `xorm:"VARCHAR(128)"`
	FencingGeneration int64  `xorm:"NOT NULL DEFAULT 0"`
	LeaseUntilUnix    int64  `xorm:"NOT NULL DEFAULT 0 INDEX"`
}

func (*GovernanceCoordinator) TableName() string { return "enterprise_wecom_governance_coordinator" }

type CallbackReceipt struct {
	ID             int64  `xorm:"pk autoincr"`
	CorpID         string `xorm:"VARCHAR(128) NOT NULL INDEX"`
	AgentID        string `xorm:"VARCHAR(64) NOT NULL INDEX"`
	Event          string `xorm:"VARCHAR(64) NOT NULL"`
	DedupKey       string `xorm:"VARCHAR(64) NOT NULL UNIQUE"`
	Status         string `xorm:"VARCHAR(16) NOT NULL INDEX"`
	RunID          string `xorm:"VARCHAR(64)"`
	Attempts       int
	NextRetryUnix  timeutil.TimeStamp `xorm:"INDEX"`
	LeaseUntilUnix timeutil.TimeStamp `xorm:"INDEX"`
	LeaseToken     string             `xorm:"VARCHAR(64)"`
	Reason         string             `xorm:"VARCHAR(64)"`
	CreatedUnix    timeutil.TimeStamp
	UpdatedUnix    timeutil.TimeStamp
}

func (*CallbackReceipt) TableName() string { return "enterprise_wecom_callback_receipt" }

type GovernanceReconcileRun struct {
	EnterpriseWeComReconcileRun `xorm:"extends"`
	Stage                       string `xorm:"VARCHAR(32)"`
	Reason                      string `xorm:"VARCHAR(64)"`
	PublishedRevision           int64  `xorm:"NOT NULL DEFAULT 0"`
}

func (*GovernanceReconcileRun) TableName() string { return "enterprise_wecom_reconcile_run" }

type governanceAuditEvent struct {
	ID       int64 `xorm:"pk autoincr"`
	Action   string
	Message  string
	Metadata string `xorm:"LONGTEXT JSON"`
}

func (*governanceAuditEvent) TableName() string { return "audit_event" }

func HardenEnterpriseWeComGovernance(ctx context.Context, x base.EngineMigration) error {
	indexes, err := x.Dialect().GetIndexes(x.DB(), ctx, "enterprise_wecom_authz_mapping")
	if err != nil {
		return err
	}
	if index, ok := indexes["mapping_unique"]; ok && len(index.Cols) == 6 {
		if _, err := x.Exec(x.Dialect().DropIndexSQL("enterprise_wecom_authz_mapping", index)); err != nil {
			return err
		}
	}
	if _, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(GovernanceAuthzMapping), new(GovernanceCoordinator), new(CallbackReceipt), new(GovernanceReconcileRun)); err != nil {
		return err
	}
	sess := x.NewSession()
	defer sess.Close()
	if err := sess.Begin(); err != nil {
		return err
	}
	var mappings []GovernanceAuthzMapping
	if err := sess.Where("origin = ?", "legacy").Find(&mappings); err != nil {
		return err
	}
	for _, mapping := range mappings {
		if mapping.TargetType != "team" {
			continue
		}
		var teams []EnterpriseWeComGeneratedTeam
		if err := sess.Where("corp_id = ? AND source_type = ? AND source_id = ? AND org_id = ? AND team_id = ? AND status = ?", mapping.CorpID, mapping.SourceType, mapping.SourceID, mapping.OrgID, mapping.TeamID, "applied").Find(&teams); err != nil {
			return err
		}
		if len(teams) != 1 || teams[0].RunID == "" || teams[0].AgentID == "" {
			continue
		}
		team := teams[0]
		var evidence []EnterpriseWeComGeneratedMapping
		err := sess.Where("run_id = ? AND corp_id = ? AND agent_id = ? AND source_type = ? AND source_id = ? AND target_type = ? AND org_id = ? AND team_id = ? AND status = ?", team.RunID, mapping.CorpID, team.AgentID, mapping.SourceType, mapping.SourceID, mapping.TargetType, mapping.OrgID, mapping.TeamID, "applied").Limit(2).Find(&evidence)
		if err != nil {
			return err
		}
		if len(evidence) != 1 {
			continue
		}
		run := new(EnterpriseWeComReconcileRun)
		has, err := sess.Where("run_id = ? AND corp_id = ? AND agent_id = ? AND status = ?", team.RunID, mapping.CorpID, team.AgentID, "success").Get(run)
		if err != nil {
			return err
		}
		if !has {
			continue
		}
		// 必须同时有 source、target、run 证据；actor 或名称不证明自动生成来源。
		if _, err := sess.ID(mapping.ID).Cols("origin", "agent_id").Update(&GovernanceAuthzMapping{Origin: "generated", AgentID: team.AgentID}); err != nil {
			return err
		}
	}
	for _, field := range []struct{ table, column string }{
		{"enterprise_wecom_reconcile_run", "error_message"},
		{"enterprise_wecom_generated_mapping", "error_message"},
		{"wecom_admin_authority", "last_error"},
	} {
		if _, err := sess.Exec("UPDATE `"+field.table+"` SET `"+field.column+"` = ? WHERE `"+field.column+"` <> ?", "legacy_error_redacted", ""); err != nil {
			return err
		}
	}
	exists, err := x.IsTableExist("audit_event")
	if err != nil {
		return err
	}
	if exists {
		var events []governanceAuditEvent
		if err := sess.Where("action LIKE ?", "enterprise:wecom:%").Find(&events); err != nil {
			return err
		}
		for _, event := range events {
			if !strings.HasPrefix(event.Action, "enterprise:wecom:") || strings.HasPrefix(event.Action, "enterprise:wecom:login:") || strings.HasPrefix(event.Action, "enterprise:wecom:identity:") {
				continue
			}
			var raw map[string]any
			_ = json.Unmarshal([]byte(event.Metadata), &raw)
			safe := map[string]any{}
			for _, key := range []string{"mapping_id", "request_id", "run_id", "receipt_id", "org_id", "team_id", "user_id", "quota", "current", "total", "management_count", "message_only_count", "generated_mappings", "generated_teams", "added_memberships", "removed_memberships", "added_team_admins", "removed_team_admins", "skipped", "errors", "protected", "deactivated_missing", "additions", "removals", "protected_removals"} {
				if value, ok := raw[key].(float64); ok {
					safe[key] = value
				}
			}
			safe["reason"] = "legacy_metadata_redacted"
			encoded, err := json.Marshal(safe)
			if err != nil {
				return err
			}
			if _, err := sess.ID(event.ID).Cols("metadata", "message").Update(&governanceAuditEvent{Metadata: string(encoded), Message: "Enterprise WeCom governance event (legacy metadata redacted)."}); err != nil {
				return err
			}
		}
	}
	return sess.Commit()
}
