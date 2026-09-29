// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"context"

	"gitea.dev/modelmigration/base"
)

type weComDepartmentLeaderMetadata struct {
	ID            int64  `xorm:"pk autoincr"`
	LeaderUserIDs string `xorm:"leader_user_ids TEXT"`
}

func (*weComDepartmentLeaderMetadata) TableName() string {
	return "wecom_department"
}

type weComMembershipLeaderMetadata struct {
	ID       int64 `xorm:"pk autoincr"`
	IsLeader bool  `xorm:"INDEX NOT NULL DEFAULT false"`
}

func (*weComMembershipLeaderMetadata) TableName() string {
	return "wecom_membership"
}

func AddEnterpriseWeComDirectoryLeadershipMetadata(_ context.Context, x base.EngineMigration) error {
	return x.Sync(
		new(weComDepartmentLeaderMetadata),
		new(weComMembershipLeaderMetadata),
	)
}
