// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"fmt"
	"time"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/timeutil"
	"gitea.dev/services/audit"
)

type DepartmentInfo struct {
	ID       int64
	ParentID int64
	Name     string
	Order    int64
}

type MemberInfo struct {
	UserID string
	Name   string
	Email  string
}

type TagInfo struct {
	ID   int64
	Name string
}

type DirectoryClient interface {
	ListDepartments(ctx context.Context) ([]DepartmentInfo, error)
	ListMembers(ctx context.Context, departmentID int64) ([]MemberInfo, error)
	ListTags(ctx context.Context) ([]TagInfo, error)
	ListTagMembers(ctx context.Context, tagID int64) ([]string, error)
}

type directoryMembership struct {
	UserID   string
	Kind     wecom_model.MembershipKind
	TargetID int64
}

type directorySnapshot struct {
	departments []DepartmentInfo
	tags        []TagInfo
	members     map[string]MemberInfo
	memberships []directoryMembership
}

func SyncDirectory(ctx context.Context, client DirectoryClient) error {
	if !setting.EnterpriseWeCom.Enabled {
		return ErrWeComDisabled
	}
	corpID := setting.EnterpriseWeCom.CorpID
	audit.RecordAs(ctx, user_model.NewAuthSourceUser(), audit_model.EnterpriseWeComSyncStart, nil, "corp_id", corpID)

	if err := syncDirectory(ctx, client, corpID); err != nil {
		audit.RecordAs(ctx, user_model.NewAuthSourceUser(), audit_model.EnterpriseWeComSyncFinish, nil,
			"corp_id", corpID,
			"outcome", "error",
			"reason", "sync_failed",
		)
		return err
	}
	audit.RecordAs(ctx, user_model.NewAuthSourceUser(), audit_model.EnterpriseWeComSyncFinish, nil,
		"corp_id", corpID,
		"outcome", "success",
	)
	return nil
}

func syncDirectory(ctx context.Context, client DirectoryClient, corpID string) error {
	if corpID == "" {
		return fmt.Errorf("%w: missing corp id", ErrWeComDenied)
	}

	syncDepartments := setting.EnterpriseWeCom.SyncDepartments
	syncTags := setting.EnterpriseWeCom.SyncTags
	snapshot, err := fetchDirectorySnapshot(ctx, client, syncDepartments, syncTags)
	if err != nil {
		return err
	}

	now := timeutil.TimeStamp(time.Now().Unix())
	syncVersion := time.Now().UnixNano()
	return db.WithTx(ctx, func(ctx context.Context) error {
		for _, dept := range snapshot.departments {
			if err := wecom_model.UpsertDepartment(ctx, &wecom_model.Department{
				CorpID:       corpID,
				DepartmentID: dept.ID,
				ParentID:     dept.ParentID,
				Name:         dept.Name,
				Order:        dept.Order,
				LastSyncUnix: now,
				SyncVersion:  syncVersion,
			}); err != nil {
				return err
			}
		}
		for _, tag := range snapshot.tags {
			if err := wecom_model.UpsertTag(ctx, &wecom_model.Tag{
				CorpID:       corpID,
				TagID:        tag.ID,
				Name:         tag.Name,
				LastSyncUnix: now,
				SyncVersion:  syncVersion,
			}); err != nil {
				return err
			}
		}
		for _, member := range snapshot.members {
			if err := upsertSyncedMember(ctx, corpID, member, now, syncVersion); err != nil {
				return err
			}
		}
		for _, membership := range snapshot.memberships {
			if err := wecom_model.UpsertMembership(ctx, &wecom_model.Membership{
				CorpID:       corpID,
				WeComUserID:  membership.UserID,
				Kind:         membership.Kind,
				TargetID:     membership.TargetID,
				LastSyncUnix: now,
				SyncVersion:  syncVersion,
			}); err != nil {
				return err
			}
		}
		return wecom_model.ReconcileDirectorySnapshot(ctx, corpID, syncDepartments, syncTags, syncVersion)
	})
}

func fetchDirectorySnapshot(ctx context.Context, client DirectoryClient, syncDepartments, syncTags bool) (*directorySnapshot, error) {
	snapshot := &directorySnapshot{members: map[string]MemberInfo{}}
	if syncDepartments {
		departments, err := client.ListDepartments(ctx)
		if err != nil {
			return nil, err
		}
		snapshot.departments = departments
		for _, dept := range departments {
			members, err := client.ListMembers(ctx, dept.ID)
			if err != nil {
				return nil, err
			}
			for _, member := range members {
				snapshot.members[member.UserID] = member
				snapshot.memberships = append(snapshot.memberships, directoryMembership{
					UserID: member.UserID, Kind: wecom_model.MembershipDepartment, TargetID: dept.ID,
				})
			}
		}
	}
	if syncTags {
		tags, err := client.ListTags(ctx)
		if err != nil {
			return nil, err
		}
		snapshot.tags = tags
		for _, tag := range tags {
			userIDs, err := client.ListTagMembers(ctx, tag.ID)
			if err != nil {
				return nil, err
			}
			for _, userID := range userIDs {
				if _, ok := snapshot.members[userID]; !ok {
					snapshot.members[userID] = MemberInfo{UserID: userID}
				}
				snapshot.memberships = append(snapshot.memberships, directoryMembership{
					UserID: userID, Kind: wecom_model.MembershipTag, TargetID: tag.ID,
				})
			}
		}
	}
	return snapshot, nil
}

func upsertSyncedMember(ctx context.Context, corpID string, member MemberInfo, now timeutil.TimeStamp, syncVersion int64) error {
	_, _, err := wecom_model.UpsertIdentitySnapshot(ctx, wecom_model.BindIdentityOptions{
		CorpID:       corpID,
		WeComUserID:  member.UserID,
		Status:       wecom_model.IdentityStatusActive,
		Name:         member.Name,
		Email:        member.Email,
		LastSyncUnix: now,
		SyncVersion:  syncVersion,
	})
	return err
}
