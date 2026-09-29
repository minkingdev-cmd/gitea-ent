// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"context"

	"gitea.dev/modelmigration/base"
	"gitea.dev/modules/timeutil"
)

type EnterpriseWeComAuthzMapping struct {
	ID          int64              `xorm:"pk autoincr"`
	CorpID      string             `xorm:"VARCHAR(128) NOT NULL INDEX UNIQUE(mapping_unique)"`
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

func (*EnterpriseWeComAuthzMapping) TableName() string {
	return "enterprise_wecom_authz_mapping"
}

type EnterpriseWeComManagedMembership struct {
	ID              int64  `xorm:"pk autoincr"`
	MappingID       int64  `xorm:"INDEX NOT NULL UNIQUE(mapping_member)"`
	UserID          int64  `xorm:"INDEX NOT NULL UNIQUE(mapping_member)"`
	TargetType      string `xorm:"VARCHAR(32) NOT NULL UNIQUE(mapping_member)"`
	OrgID           int64  `xorm:"INDEX NOT NULL UNIQUE(mapping_member)"`
	TeamID          int64  `xorm:"INDEX NOT NULL DEFAULT 0 UNIQUE(mapping_member)"`
	LastApplyUnix   timeutil.TimeStamp
	LastSeenApplyID string             `xorm:"VARCHAR(128)"`
	CreatedUnix     timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix     timeutil.TimeStamp `xorm:"updated"`
}

func (*EnterpriseWeComManagedMembership) TableName() string {
	return "enterprise_wecom_managed_membership"
}

func AddEnterpriseWeComAuthzMappingTables(_ context.Context, x base.EngineMigration) error {
	return x.Sync(
		new(EnterpriseWeComAuthzMapping),
		new(EnterpriseWeComManagedMembership),
	)
}
