// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import "gitea.dev/models/db"

type GovernanceCoordinator struct {
	ID                int64  `xorm:"pk autoincr"`
	CorpID            string `xorm:"VARCHAR(128) NOT NULL UNIQUE(app_scope)"`
	AgentID           string `xorm:"VARCHAR(64) NOT NULL UNIQUE(app_scope)"`
	PublishedRevision int64  `xorm:"NOT NULL DEFAULT 0"`
	ManagedOrgID      int64  `xorm:"NOT NULL DEFAULT 0"`
	LeaseOwner        string `xorm:"VARCHAR(128)"`
	FencingGeneration int64  `xorm:"NOT NULL DEFAULT 0"`
	LeaseUntilUnix    int64  `xorm:"NOT NULL DEFAULT 0 INDEX"`
}

func (*GovernanceCoordinator) TableName() string { return "enterprise_wecom_governance_coordinator" }

func init() { db.RegisterModel(new(GovernanceCoordinator)) }
