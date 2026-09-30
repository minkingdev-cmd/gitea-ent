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
