// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"context"

	"gitea.dev/modelmigration/base"
	"gitea.dev/modules/timeutil"
)

type WeComAdminAuthority struct {
	ID              int64  `xorm:"pk autoincr"`
	CorpID          string `xorm:"VARCHAR(128) NOT NULL INDEX UNIQUE(corp_agent_user)"`
	AgentID         string `xorm:"VARCHAR(64) NOT NULL INDEX UNIQUE(corp_agent_user)"`
	WeComUserID     string `xorm:"wecom_userid VARCHAR(255) NOT NULL UNIQUE(corp_agent_user)"`
	OpenUserID      string `xorm:"VARCHAR(255)"`
	AuthType        int    `xorm:"NOT NULL DEFAULT 0"`
	IsManagement    bool   `xorm:"INDEX NOT NULL DEFAULT false"`
	IsActive        bool   `xorm:"INDEX NOT NULL DEFAULT true"`
	RefreshID       string `xorm:"VARCHAR(128) INDEX"`
	RefreshTrigger  string `xorm:"VARCHAR(32)"`
	LastRefreshUnix timeutil.TimeStamp
	LastSeenUnix    timeutil.TimeStamp
	LastError       string             `xorm:"TEXT"`
	CreatedUnix     timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix     timeutil.TimeStamp `xorm:"updated"`
}

func (*WeComAdminAuthority) TableName() string {
	return "wecom_admin_authority"
}

type EnterpriseWeComGeneratedMapping struct {
	ID             int64  `xorm:"pk autoincr"`
	RunID          string `xorm:"VARCHAR(128) INDEX"`
	CorpID         string `xorm:"VARCHAR(128) NOT NULL INDEX"`
	AgentID        string `xorm:"VARCHAR(64) NOT NULL INDEX"`
	SourceType     string `xorm:"VARCHAR(32) NOT NULL INDEX"`
	SourceID       string `xorm:"VARCHAR(255) NOT NULL INDEX"`
	SourceName     string
	TargetType     string `xorm:"VARCHAR(32) NOT NULL"`
	OrgID          int64  `xorm:"INDEX NOT NULL DEFAULT 0"`
	TeamID         int64  `xorm:"INDEX NOT NULL DEFAULT 0"`
	DerivationRule string `xorm:"VARCHAR(128)"`
	Status         string `xorm:"VARCHAR(32) NOT NULL INDEX DEFAULT 'pending'"`
	SkipReason     string `xorm:"VARCHAR(255)"`
	ErrorMessage   string `xorm:"TEXT"`
	MemberCount    int
	AdminCount     int
	LastApplyUnix  timeutil.TimeStamp
	CreatedUnix    timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix    timeutil.TimeStamp `xorm:"updated"`
}

func (*EnterpriseWeComGeneratedMapping) TableName() string {
	return "enterprise_wecom_generated_mapping"
}

type EnterpriseWeComGeneratedTeam struct {
	ID               int64  `xorm:"pk autoincr"`
	RunID            string `xorm:"VARCHAR(128) INDEX"`
	CorpID           string `xorm:"VARCHAR(128) NOT NULL INDEX UNIQUE(corp_agent_source)"`
	AgentID          string `xorm:"VARCHAR(64) NOT NULL INDEX UNIQUE(corp_agent_source)"`
	SourceType       string `xorm:"VARCHAR(32) NOT NULL UNIQUE(corp_agent_source)"`
	SourceID         string `xorm:"VARCHAR(255) NOT NULL UNIQUE(corp_agent_source)"`
	SourceName       string
	OrgID            int64  `xorm:"INDEX NOT NULL DEFAULT 0"`
	TeamID           int64  `xorm:"INDEX NOT NULL DEFAULT 0"`
	TeamName         string `xorm:"VARCHAR(255)"`
	DerivationRule   string `xorm:"VARCHAR(128)"`
	Status           string `xorm:"VARCHAR(32) NOT NULL INDEX DEFAULT 'pending'"`
	AdminStatus      string `xorm:"VARCHAR(32) NOT NULL DEFAULT 'unresolved'"`
	UnresolvedReason string `xorm:"VARCHAR(255)"`
	MemberCount      int
	AdminCount       int
	LastApplyUnix    timeutil.TimeStamp
	CreatedUnix      timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix      timeutil.TimeStamp `xorm:"updated"`
}

func (*EnterpriseWeComGeneratedTeam) TableName() string {
	return "enterprise_wecom_generated_team"
}

type EnterpriseWeComGeneratedTeamAdmin struct {
	ID            int64  `xorm:"pk autoincr"`
	RunID         string `xorm:"VARCHAR(128) INDEX"`
	CorpID        string `xorm:"VARCHAR(128) NOT NULL INDEX UNIQUE(corp_agent_team_user_source)"`
	AgentID       string `xorm:"VARCHAR(64) NOT NULL INDEX UNIQUE(corp_agent_team_user_source)"`
	SourceType    string `xorm:"VARCHAR(32) NOT NULL UNIQUE(corp_agent_team_user_source)"`
	SourceID      string `xorm:"VARCHAR(255) NOT NULL UNIQUE(corp_agent_team_user_source)"`
	TeamID        int64  `xorm:"INDEX NOT NULL UNIQUE(corp_agent_team_user_source)"`
	UserID        int64  `xorm:"INDEX NOT NULL DEFAULT 0 UNIQUE(corp_agent_team_user_source)"`
	WeComUserID   string `xorm:"wecom_userid VARCHAR(255) UNIQUE(corp_agent_team_user_source)"`
	AdminSource   string `xorm:"VARCHAR(64) NOT NULL"`
	Status        string `xorm:"VARCHAR(32) NOT NULL INDEX DEFAULT 'pending'"`
	Reason        string `xorm:"VARCHAR(255)"`
	LastApplyUnix timeutil.TimeStamp
	CreatedUnix   timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix   timeutil.TimeStamp `xorm:"updated"`
}

func (*EnterpriseWeComGeneratedTeamAdmin) TableName() string {
	return "enterprise_wecom_generated_team_admin"
}

type EnterpriseWeComReconcileRun struct {
	ID                     int64  `xorm:"pk autoincr"`
	RunID                  string `xorm:"VARCHAR(128) UNIQUE NOT NULL"`
	CorpID                 string `xorm:"VARCHAR(128) NOT NULL INDEX"`
	AgentID                string `xorm:"VARCHAR(64) NOT NULL INDEX"`
	Trigger                string `xorm:"VARCHAR(32) NOT NULL INDEX"`
	Status                 string `xorm:"VARCHAR(32) NOT NULL INDEX DEFAULT 'running'"`
	DirectorySyncStatus    string `xorm:"VARCHAR(32)"`
	AuthorityRefreshStatus string `xorm:"VARCHAR(32)"`
	GeneratedMappings      int
	GeneratedTeams         int
	AddedMemberships       int
	RemovedMemberships     int
	AddedTeamAdmins        int
	RemovedTeamAdmins      int
	SkippedCount           int
	ErrorCount             int
	ProtectedCount         int
	ErrorMessage           string `xorm:"TEXT"`
	StartedUnix            timeutil.TimeStamp
	FinishedUnix           timeutil.TimeStamp
	CreatedUnix            timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix            timeutil.TimeStamp `xorm:"updated"`
}

func (*EnterpriseWeComReconcileRun) TableName() string {
	return "enterprise_wecom_reconcile_run"
}

func AddEnterpriseWeComAutomationStateTables(_ context.Context, x base.EngineMigration) error {
	return x.Sync(
		new(WeComAdminAuthority),
		new(EnterpriseWeComGeneratedMapping),
		new(EnterpriseWeComGeneratedTeam),
		new(EnterpriseWeComGeneratedTeamAdmin),
		new(EnterpriseWeComReconcileRun),
	)
}
