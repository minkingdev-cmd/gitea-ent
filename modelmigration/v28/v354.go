// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"context"

	"gitea.dev/modelmigration/base"
	"gitea.dev/modules/timeutil"
)

type WeComIdentity struct {
	ID            int64  `xorm:"pk autoincr"`
	UserID        int64  `xorm:"INDEX NOT NULL"`
	CorpID        string `xorm:"VARCHAR(128) NOT NULL UNIQUE(corp_user)"`
	WeComUserID   string `xorm:"wecom_userid VARCHAR(255) NOT NULL UNIQUE(corp_user)"`
	ExternalID    string `xorm:"VARCHAR(512) UNIQUE NOT NULL"`
	LoginSourceID int64  `xorm:"INDEX NOT NULL"`
	Status        string `xorm:"VARCHAR(32) NOT NULL DEFAULT 'active'"`
	Name          string
	Email         string
	LastLoginUnix timeutil.TimeStamp
	LastSyncUnix  timeutil.TimeStamp
	CreatedUnix   timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix   timeutil.TimeStamp `xorm:"updated"`
}

func (*WeComIdentity) TableName() string {
	return "wecom_identity"
}

type WeComDepartment struct {
	ID           int64  `xorm:"pk autoincr"`
	CorpID       string `xorm:"VARCHAR(128) NOT NULL UNIQUE(corp_department)"`
	DepartmentID int64  `xorm:"NOT NULL UNIQUE(corp_department)"`
	ParentID     int64
	Name         string
	Order        int64
	LastSyncUnix timeutil.TimeStamp
	CreatedUnix  timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix  timeutil.TimeStamp `xorm:"updated"`
}

func (*WeComDepartment) TableName() string {
	return "wecom_department"
}

type WeComTag struct {
	ID           int64  `xorm:"pk autoincr"`
	CorpID       string `xorm:"VARCHAR(128) NOT NULL UNIQUE(corp_tag)"`
	TagID        int64  `xorm:"NOT NULL UNIQUE(corp_tag)"`
	Name         string
	LastSyncUnix timeutil.TimeStamp
	CreatedUnix  timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix  timeutil.TimeStamp `xorm:"updated"`
}

func (*WeComTag) TableName() string {
	return "wecom_tag"
}

type WeComMembership struct {
	ID           int64  `xorm:"pk autoincr"`
	CorpID       string `xorm:"VARCHAR(128) NOT NULL UNIQUE(corp_member_target)"`
	WeComUserID  string `xorm:"wecom_userid VARCHAR(255) NOT NULL UNIQUE(corp_member_target)"`
	Kind         string `xorm:"VARCHAR(32) NOT NULL UNIQUE(corp_member_target)"`
	TargetID     int64  `xorm:"NOT NULL UNIQUE(corp_member_target)"`
	LastSyncUnix timeutil.TimeStamp
	CreatedUnix  timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix  timeutil.TimeStamp `xorm:"updated"`
}

func (*WeComMembership) TableName() string {
	return "wecom_membership"
}

func AddWeComIdentityAndDirectoryTables(_ context.Context, x base.EngineMigration) error {
	return x.Sync(
		new(WeComIdentity),
		new(WeComDepartment),
		new(WeComTag),
		new(WeComMembership),
	)
}
