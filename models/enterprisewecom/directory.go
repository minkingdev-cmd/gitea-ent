// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"

	"gitea.dev/models/db"
	"gitea.dev/modules/json"
	"gitea.dev/modules/timeutil"
)

type Department struct {
	ID            int64  `xorm:"pk autoincr"`
	CorpID        string `xorm:"VARCHAR(128) NOT NULL UNIQUE(corp_department)"`
	DepartmentID  int64  `xorm:"NOT NULL UNIQUE(corp_department)"`
	ParentID      int64
	Name          string
	LeaderUserIDs string `xorm:"leader_user_ids TEXT"`
	Order         int64
	LastSyncUnix  timeutil.TimeStamp
	SyncVersion   int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	CreatedUnix   timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix   timeutil.TimeStamp `xorm:"updated"`
}

func (*Department) TableName() string {
	return "wecom_department"
}

type Tag struct {
	ID           int64  `xorm:"pk autoincr"`
	CorpID       string `xorm:"VARCHAR(128) NOT NULL UNIQUE(corp_tag)"`
	TagID        int64  `xorm:"NOT NULL UNIQUE(corp_tag)"`
	Name         string
	LastSyncUnix timeutil.TimeStamp
	SyncVersion  int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	CreatedUnix  timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix  timeutil.TimeStamp `xorm:"updated"`
}

func (*Tag) TableName() string {
	return "wecom_tag"
}

type MembershipKind string

const (
	MembershipDepartment MembershipKind = "department"
	MembershipTag        MembershipKind = "tag"
)

type Membership struct {
	ID           int64          `xorm:"pk autoincr"`
	CorpID       string         `xorm:"VARCHAR(128) NOT NULL UNIQUE(corp_member_target)"`
	WeComUserID  string         `xorm:"wecom_userid VARCHAR(255) NOT NULL UNIQUE(corp_member_target)"`
	Kind         MembershipKind `xorm:"VARCHAR(32) NOT NULL UNIQUE(corp_member_target)"`
	TargetID     int64          `xorm:"NOT NULL UNIQUE(corp_member_target)"`
	IsLeader     bool           `xorm:"INDEX NOT NULL DEFAULT false"`
	LastSyncUnix timeutil.TimeStamp
	SyncVersion  int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	CreatedUnix  timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix  timeutil.TimeStamp `xorm:"updated"`
}

func (*Membership) TableName() string {
	return "wecom_membership"
}

func init() {
	db.RegisterModel(new(Department))
	db.RegisterModel(new(Tag))
	db.RegisterModel(new(Membership))
}

func UpsertDepartment(ctx context.Context, dept *Department) error {
	existing := &Department{}
	has, err := db.GetEngine(ctx).Where("corp_id = ? AND department_id = ?", dept.CorpID, dept.DepartmentID).Get(existing)
	if err != nil {
		return err
	}
	if has {
		dept.ID = existing.ID
		_, err = db.GetEngine(ctx).ID(existing.ID).Cols("parent_id", "name", "leader_user_ids", "order", "last_sync_unix", "sync_version").Update(dept)
		return err
	}
	return db.Insert(ctx, dept)
}

func UpsertTag(ctx context.Context, tag *Tag) error {
	existing := &Tag{}
	has, err := db.GetEngine(ctx).Where("corp_id = ? AND tag_id = ?", tag.CorpID, tag.TagID).Get(existing)
	if err != nil {
		return err
	}
	if has {
		tag.ID = existing.ID
		_, err = db.GetEngine(ctx).ID(existing.ID).Cols("name", "last_sync_unix", "sync_version").Update(tag)
		return err
	}
	return db.Insert(ctx, tag)
}

func UpsertMembership(ctx context.Context, membership *Membership) error {
	existing := &Membership{}
	has, err := db.GetEngine(ctx).Where(
		"corp_id = ? AND wecom_userid = ? AND kind = ? AND target_id = ?",
		membership.CorpID, membership.WeComUserID, membership.Kind, membership.TargetID,
	).Get(existing)
	if err != nil {
		return err
	}
	if has {
		membership.ID = existing.ID
		_, err = db.GetEngine(ctx).ID(existing.ID).Cols("is_leader", "last_sync_unix", "sync_version").Update(membership)
		return err
	}
	return db.Insert(ctx, membership)
}

func EncodeLeaderUserIDs(userIDs []string) string {
	if len(userIDs) == 0 {
		return ""
	}
	b, err := json.Marshal(userIDs)
	if err != nil {
		return ""
	}
	return string(b)
}

func DecodeLeaderUserIDs(encoded string) []string {
	if encoded == "" {
		return nil
	}
	var userIDs []string
	if err := json.Unmarshal([]byte(encoded), &userIDs); err != nil {
		return nil
	}
	return userIDs
}

func ReconcileDirectorySnapshot(ctx context.Context, corpID string, syncDepartments, syncTags bool, syncVersion int64) error {
	engine := db.GetEngine(ctx)
	if syncDepartments {
		if _, err := engine.Where("corp_id = ? AND kind = ? AND sync_version <> ?", corpID, MembershipDepartment, syncVersion).Delete(new(Membership)); err != nil {
			return err
		}
		if _, err := engine.Where("corp_id = ? AND sync_version <> ?", corpID, syncVersion).Delete(new(Department)); err != nil {
			return err
		}
	}
	if syncTags {
		if _, err := engine.Where("corp_id = ? AND kind = ? AND sync_version <> ?", corpID, MembershipTag, syncVersion).Delete(new(Membership)); err != nil {
			return err
		}
		if _, err := engine.Where("corp_id = ? AND sync_version <> ?", corpID, syncVersion).Delete(new(Tag)); err != nil {
			return err
		}
	}
	if syncDepartments || syncTags {
		if _, err := engine.Where("corp_id = ? AND sync_version <> ? AND status = ?", corpID, syncVersion, IdentityStatusActive).
			Cols("status").Update(&Identity{Status: IdentityStatusOutOfScope}); err != nil {
			return err
		}
	}
	return nil
}
