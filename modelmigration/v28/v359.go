// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"context"

	"gitea.dev/modelmigration/base"
	"gitea.dev/modules/timeutil"
)

type EnterpriseWeComOrgRepoRequest struct {
	ID             int64  `xorm:"pk autoincr"`
	OrgID          int64  `xorm:"INDEX NOT NULL"`
	RequesterID    int64  `xorm:"INDEX NOT NULL"`
	ReviewerID     int64  `xorm:"INDEX NOT NULL DEFAULT 0"`
	RepoID         int64  `xorm:"INDEX NOT NULL DEFAULT 0"`
	Name           string `xorm:"VARCHAR(100) NOT NULL"`
	Description    string `xorm:"TEXT"`
	Reason         string `xorm:"TEXT"`
	Status         string `xorm:"VARCHAR(32) NOT NULL INDEX DEFAULT 'pending'"`
	DecisionReason string `xorm:"TEXT"`
	ReviewedUnix   timeutil.TimeStamp
	CreatedUnix    timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix    timeutil.TimeStamp `xorm:"updated"`
}

func (*EnterpriseWeComOrgRepoRequest) TableName() string {
	return "enterprise_wecom_org_repo_request"
}

type EnterpriseWeComRepositoryGovernance struct {
	ID          int64              `xorm:"pk autoincr"`
	RepoID      int64              `xorm:"INDEX UNIQUE NOT NULL"`
	CreatorID   int64              `xorm:"INDEX NOT NULL"`
	RequestID   int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	Source      string             `xorm:"VARCHAR(32) NOT NULL INDEX"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

func (*EnterpriseWeComRepositoryGovernance) TableName() string {
	return "enterprise_wecom_repository_governance"
}

func AddEnterpriseWeComRepositoryGovernanceTables(_ context.Context, x base.EngineMigration) error {
	return x.Sync(
		new(EnterpriseWeComOrgRepoRequest),
		new(EnterpriseWeComRepositoryGovernance),
	)
}
