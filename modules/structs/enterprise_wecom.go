// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package structs

import "time"

// EnterpriseWeComAuthzMapping represents an Enterprise WeCom authorization mapping.
// swagger:model
type EnterpriseWeComAuthzMapping struct {
	ID         int64     `json:"id"`
	CorpID     string    `json:"corp_id"`
	SourceType string    `json:"source_type"`
	SourceID   string    `json:"source_id"`
	TargetType string    `json:"target_type"`
	OrgID      int64     `json:"org_id"`
	TeamID     int64     `json:"team_id"`
	Active     bool      `json:"active"`
	CreatedBy  int64     `json:"created_by"`
	Created    time.Time `json:"created"`
	Updated    time.Time `json:"updated"`
}

// EnterpriseWeComAuthzMappingOption options for creating or updating an Enterprise WeCom authorization mapping.
// swagger:model
type EnterpriseWeComAuthzMappingOption struct {
	CorpID string `json:"corp_id" binding:"MaxSize(128)"`
	// required: true
	SourceType string `json:"source_type" binding:"Required;In(user,department,tag)"`
	// required: true
	SourceID string `json:"source_id" binding:"Required;MaxSize(255)"`
	// required: true
	TargetType string `json:"target_type" binding:"Required;In(org,team)"`
	OrgID      int64  `json:"org_id"`
	TeamID     int64  `json:"team_id"`
}

// EnterpriseWeComAuthzReconcileOption options for dry-running or applying Enterprise WeCom authorization mappings.
// swagger:model
type EnterpriseWeComAuthzReconcileOption struct {
	CorpID  string `json:"corp_id" binding:"MaxSize(128)"`
	ApplyID string `json:"apply_id" binding:"MaxSize(128)"`
}

// EnterpriseWeComAuthzMembershipChange represents a planned or applied membership change.
// swagger:model
type EnterpriseWeComAuthzMembershipChange struct {
	MappingID  int64  `json:"mapping_id"`
	UserID     int64  `json:"user_id"`
	TargetType string `json:"target_type"`
	OrgID      int64  `json:"org_id"`
	TeamID     int64  `json:"team_id"`
}

// EnterpriseWeComAuthzSkippedIdentity represents a WeCom identity skipped during reconciliation.
// swagger:model
type EnterpriseWeComAuthzSkippedIdentity struct {
	MappingID    int64  `json:"mapping_id"`
	WeComUserID  string `json:"wecom_userid"`
	Reason       string `json:"reason"`
	Status       string `json:"status"`
	BoundUserID  int64  `json:"bound_user_id"`
	SourceType   string `json:"source_type"`
	SourceID     string `json:"source_id"`
	TargetType   string `json:"target_type"`
	TargetOrgID  int64  `json:"target_org_id"`
	TargetTeamID int64  `json:"target_team_id"`
}

// EnterpriseWeComAuthzReconcileResult represents a dry-run or apply reconciliation result.
// swagger:model
type EnterpriseWeComAuthzReconcileResult struct {
	Additions         []EnterpriseWeComAuthzMembershipChange `json:"additions"`
	Removals          []EnterpriseWeComAuthzMembershipChange `json:"removals"`
	ProtectedRemovals []EnterpriseWeComAuthzMembershipChange `json:"protected_removals"`
	Skipped           []EnterpriseWeComAuthzSkippedIdentity  `json:"skipped"`
	Errors            []string                               `json:"errors"`
}
