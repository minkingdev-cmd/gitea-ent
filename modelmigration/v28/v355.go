// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"context"

	"gitea.dev/modelmigration/base"
)

type weComIdentitySyncVersion struct {
	ID          int64 `xorm:"pk autoincr"`
	SyncVersion int64 `xorm:"INDEX NOT NULL DEFAULT 0"`
}

func (*weComIdentitySyncVersion) TableName() string {
	return "wecom_identity"
}

type weComDepartmentSyncVersion struct {
	ID          int64 `xorm:"pk autoincr"`
	SyncVersion int64 `xorm:"INDEX NOT NULL DEFAULT 0"`
}

func (*weComDepartmentSyncVersion) TableName() string {
	return "wecom_department"
}

type weComTagSyncVersion struct {
	ID          int64 `xorm:"pk autoincr"`
	SyncVersion int64 `xorm:"INDEX NOT NULL DEFAULT 0"`
}

func (*weComTagSyncVersion) TableName() string {
	return "wecom_tag"
}

type weComMembershipSyncVersion struct {
	ID          int64 `xorm:"pk autoincr"`
	SyncVersion int64 `xorm:"INDEX NOT NULL DEFAULT 0"`
}

func (*weComMembershipSyncVersion) TableName() string {
	return "wecom_membership"
}

func AddEnterpriseWeComSyncVersionColumns(_ context.Context, x base.EngineMigration) error {
	return x.Sync(
		new(weComIdentitySyncVersion),
		new(weComDepartmentSyncVersion),
		new(weComTagSyncVersion),
		new(weComMembershipSyncVersion),
	)
}
