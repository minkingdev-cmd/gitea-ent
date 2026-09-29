// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"gitea.dev/models/db"
	"gitea.dev/modules/timeutil"
)

type OrgRepoRequestStatus string

const (
	OrgRepoRequestStatusPending  OrgRepoRequestStatus = "pending"
	OrgRepoRequestStatusApproved OrgRepoRequestStatus = "approved"
	OrgRepoRequestStatusRejected OrgRepoRequestStatus = "rejected"
)

type OrgRepoRequest struct {
	ID             int64                `xorm:"pk autoincr"`
	OrgID          int64                `xorm:"INDEX NOT NULL"`
	RequesterID    int64                `xorm:"INDEX NOT NULL"`
	ReviewerID     int64                `xorm:"INDEX NOT NULL DEFAULT 0"`
	RepoID         int64                `xorm:"INDEX NOT NULL DEFAULT 0"`
	Name           string               `xorm:"VARCHAR(100) NOT NULL"`
	Description    string               `xorm:"TEXT"`
	Reason         string               `xorm:"TEXT"`
	Status         OrgRepoRequestStatus `xorm:"VARCHAR(32) NOT NULL INDEX DEFAULT 'pending'"`
	DecisionReason string               `xorm:"TEXT"`
	ReviewedUnix   timeutil.TimeStamp
	CreatedUnix    timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix    timeutil.TimeStamp `xorm:"updated"`
}

func (*OrgRepoRequest) TableName() string {
	return "enterprise_wecom_org_repo_request"
}

type RepositoryGovernanceSource string

const (
	RepositoryGovernanceSourcePersonal         RepositoryGovernanceSource = "personal"
	RepositoryGovernanceSourceOrgRequest       RepositoryGovernanceSource = "org_request"
	RepositoryGovernanceSourceSuperAdminDirect RepositoryGovernanceSource = "super_admin_direct"
)

type RepositoryGovernance struct {
	ID          int64                      `xorm:"pk autoincr"`
	RepoID      int64                      `xorm:"INDEX UNIQUE NOT NULL"`
	CreatorID   int64                      `xorm:"INDEX NOT NULL"`
	RequestID   int64                      `xorm:"INDEX NOT NULL DEFAULT 0"`
	Source      RepositoryGovernanceSource `xorm:"VARCHAR(32) NOT NULL INDEX"`
	CreatedUnix timeutil.TimeStamp         `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp         `xorm:"updated"`
}

func (*RepositoryGovernance) TableName() string {
	return "enterprise_wecom_repository_governance"
}

func init() {
	db.RegisterModel(new(OrgRepoRequest))
	db.RegisterModel(new(RepositoryGovernance))
}
