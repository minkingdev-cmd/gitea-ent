// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"gitea.dev/models/db"
	"gitea.dev/modules/timeutil"
)

type IdentityStatus string

const (
	IdentityStatusActive     IdentityStatus = "active"
	IdentityStatusInactive   IdentityStatus = "inactive"
	IdentityStatusLeft       IdentityStatus = "left"
	IdentityStatusOutOfScope IdentityStatus = "out_of_scope"
)

var (
	ErrIdentityAlreadyBound = errors.New("wecom identity is already bound to another user")
	ErrIdentityNotFound     = errors.New("wecom identity not found")
)

type Identity struct {
	ID            int64          `xorm:"pk autoincr"`
	UserID        int64          `xorm:"INDEX NOT NULL"`
	CorpID        string         `xorm:"VARCHAR(128) NOT NULL UNIQUE(corp_user)"`
	WeComUserID   string         `xorm:"wecom_userid VARCHAR(255) NOT NULL UNIQUE(corp_user)"`
	ExternalID    string         `xorm:"VARCHAR(512) UNIQUE NOT NULL"`
	LoginSourceID int64          `xorm:"INDEX NOT NULL"`
	Status        IdentityStatus `xorm:"VARCHAR(32) NOT NULL DEFAULT 'active'"`
	Name          string
	Email         string
	LastLoginUnix timeutil.TimeStamp
	LastSyncUnix  timeutil.TimeStamp
	SyncVersion   int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	CreatedUnix   timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix   timeutil.TimeStamp `xorm:"updated"`
}

func (*Identity) TableName() string {
	return "wecom_identity"
}

func init() {
	db.RegisterModel(new(Identity))
}

func MakeExternalID(corpID, userid string) string {
	return fmt.Sprintf("wecom:%s:%s", corpID, userid)
}

func (i *Identity) ActiveForLogin() bool {
	return i != nil && i.Status == IdentityStatusActive
}

type BindIdentityOptions struct {
	UserID        int64
	CorpID        string
	WeComUserID   string
	LoginSourceID int64
	Status        IdentityStatus
	Name          string
	Email         string
	LastLoginUnix timeutil.TimeStamp
	LastSyncUnix  timeutil.TimeStamp
	SyncVersion   int64
}

func BindIdentityToUser(ctx context.Context, opts BindIdentityOptions) (*Identity, bool, error) {
	opts.CorpID = strings.TrimSpace(opts.CorpID)
	opts.WeComUserID = strings.TrimSpace(opts.WeComUserID)
	if opts.CorpID == "" || opts.WeComUserID == "" || opts.UserID == 0 {
		return nil, false, errors.New("missing required wecom identity binding fields")
	}
	if opts.Status == "" {
		opts.Status = IdentityStatusActive
	}

	identity, has, err := GetIdentityByCorpAndUserID(ctx, opts.CorpID, opts.WeComUserID)
	if err != nil {
		return nil, false, err
	}
	if has {
		if identity.UserID != 0 && identity.UserID != opts.UserID {
			return identity, false, ErrIdentityAlreadyBound
		}
		identity.UserID = opts.UserID
		identity.LoginSourceID = opts.LoginSourceID
		identity.Status = opts.Status
		identity.Name = opts.Name
		identity.Email = opts.Email
		if opts.LastLoginUnix != 0 {
			identity.LastLoginUnix = opts.LastLoginUnix
		}
		if opts.LastSyncUnix != 0 {
			identity.LastSyncUnix = opts.LastSyncUnix
		}
		if opts.SyncVersion != 0 {
			identity.SyncVersion = opts.SyncVersion
		}
		_, err := db.GetEngine(ctx).ID(identity.ID).Cols(
			"user_id", "login_source_id", "status", "name", "email", "last_login_unix", "last_sync_unix", "sync_version",
		).Update(identity)
		return identity, false, err
	}

	identity = &Identity{
		UserID:        opts.UserID,
		CorpID:        opts.CorpID,
		WeComUserID:   opts.WeComUserID,
		ExternalID:    MakeExternalID(opts.CorpID, opts.WeComUserID),
		LoginSourceID: opts.LoginSourceID,
		Status:        opts.Status,
		Name:          opts.Name,
		Email:         opts.Email,
		LastLoginUnix: opts.LastLoginUnix,
		LastSyncUnix:  opts.LastSyncUnix,
		SyncVersion:   opts.SyncVersion,
	}
	return identity, true, db.Insert(ctx, identity)
}

func UpsertIdentitySnapshot(ctx context.Context, opts BindIdentityOptions) (*Identity, bool, error) {
	opts.CorpID = strings.TrimSpace(opts.CorpID)
	opts.WeComUserID = strings.TrimSpace(opts.WeComUserID)
	if opts.CorpID == "" || opts.WeComUserID == "" {
		return nil, false, errors.New("missing required wecom identity snapshot fields")
	}
	if opts.Status == "" {
		opts.Status = IdentityStatusActive
	}
	identity, has, err := GetIdentityByCorpAndUserID(ctx, opts.CorpID, opts.WeComUserID)
	if err != nil {
		return nil, false, err
	}
	if has {
		identity.Status = opts.Status
		identity.Name = opts.Name
		identity.Email = opts.Email
		if opts.LastSyncUnix != 0 {
			identity.LastSyncUnix = opts.LastSyncUnix
		}
		if opts.SyncVersion != 0 {
			identity.SyncVersion = opts.SyncVersion
		}
		_, err := db.GetEngine(ctx).ID(identity.ID).Cols("status", "name", "email", "last_sync_unix", "sync_version").Update(identity)
		return identity, false, err
	}
	identity = &Identity{
		UserID:       opts.UserID,
		CorpID:       opts.CorpID,
		WeComUserID:  opts.WeComUserID,
		ExternalID:   MakeExternalID(opts.CorpID, opts.WeComUserID),
		Status:       opts.Status,
		Name:         opts.Name,
		Email:        opts.Email,
		LastSyncUnix: opts.LastSyncUnix,
		SyncVersion:  opts.SyncVersion,
	}
	return identity, true, db.Insert(ctx, identity)
}

func GetIdentityByCorpAndUserID(ctx context.Context, corpID, userid string) (*Identity, bool, error) {
	identity := &Identity{CorpID: corpID, WeComUserID: userid}
	has, err := db.GetEngine(ctx).Get(identity)
	return identity, has, err
}

func GetIdentityByExternalID(ctx context.Context, externalID string) (*Identity, bool, error) {
	identity := &Identity{ExternalID: externalID}
	has, err := db.GetEngine(ctx).Get(identity)
	return identity, has, err
}
