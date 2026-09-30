// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"gitea.dev/models/db"
	"gitea.dev/modules/timeutil"
)

type AuthzSourceType string

const (
	AuthzSourceUser       AuthzSourceType = "user"
	AuthzSourceDepartment AuthzSourceType = "department"
	AuthzSourceTag        AuthzSourceType = "tag"
)

type AuthzTargetType string

const (
	AuthzTargetOrg  AuthzTargetType = "org"
	AuthzTargetTeam AuthzTargetType = "team"
)

const (
	AuthzMappingOriginLegacy    = "legacy"
	AuthzMappingOriginGenerated = "generated"
)

type AuthzMapping struct {
	ID          int64              `xorm:"pk autoincr"`
	CorpID      string             `xorm:"VARCHAR(128) NOT NULL INDEX UNIQUE(mapping_unique)"`
	AgentID     string             `xorm:"VARCHAR(64) NOT NULL DEFAULT '' INDEX UNIQUE(mapping_unique)"`
	Origin      string             `xorm:"VARCHAR(32) NOT NULL DEFAULT 'legacy' INDEX UNIQUE(mapping_unique)"`
	SourceType  AuthzSourceType    `xorm:"VARCHAR(32) NOT NULL UNIQUE(mapping_unique)"`
	SourceID    string             `xorm:"VARCHAR(255) NOT NULL UNIQUE(mapping_unique)"`
	TargetType  AuthzTargetType    `xorm:"VARCHAR(32) NOT NULL UNIQUE(mapping_unique)"`
	OrgID       int64              `xorm:"INDEX NOT NULL UNIQUE(mapping_unique)"`
	TeamID      int64              `xorm:"INDEX NOT NULL DEFAULT 0 UNIQUE(mapping_unique)"`
	IsActive    bool               `xorm:"INDEX NOT NULL DEFAULT true"`
	CreatedBy   int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

func (*AuthzMapping) TableName() string {
	return "enterprise_wecom_authz_mapping"
}

type ManagedMembership struct {
	ID              int64           `xorm:"pk autoincr"`
	MappingID       int64           `xorm:"INDEX NOT NULL UNIQUE(mapping_member)"`
	UserID          int64           `xorm:"INDEX NOT NULL UNIQUE(mapping_member)"`
	TargetType      AuthzTargetType `xorm:"VARCHAR(32) NOT NULL UNIQUE(mapping_member)"`
	OrgID           int64           `xorm:"INDEX NOT NULL UNIQUE(mapping_member)"`
	TeamID          int64           `xorm:"INDEX NOT NULL DEFAULT 0 UNIQUE(mapping_member)"`
	LastApplyUnix   timeutil.TimeStamp
	LastSeenApplyID string             `xorm:"VARCHAR(128)"`
	CreatedUnix     timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix     timeutil.TimeStamp `xorm:"updated"`
}

func (*ManagedMembership) TableName() string {
	return "enterprise_wecom_managed_membership"
}

func init() {
	db.RegisterModel(new(AuthzMapping))
	db.RegisterModel(new(ManagedMembership))
}
