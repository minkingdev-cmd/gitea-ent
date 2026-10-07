// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package structs

import "time"

// EnterpriseProtectedPathConfig 为累加规则，不覆盖上级规则。
// swagger:model
type EnterpriseProtectedPathConfig struct {
	PathPattern    string   `json:"path_pattern"`
	BranchPattern  string   `json:"branch_pattern,omitempty"`
	RequiredRoleID int64    `json:"required_role_id"`
	CheckContexts  []string `json:"check_contexts,omitempty"`
	Enabled        bool     `json:"enabled"`
}

// PutEnterpriseProtectedPathRuleOption 创建使用 revision 0，修改使用当前版本。
// swagger:model
type PutEnterpriseProtectedPathRuleOption struct {
	// required: true
	Config EnterpriseProtectedPathConfig `json:"config"`
	// required: true
	ExpectedRevision int64 `json:"expected_revision"`
}

// EnterpriseProtectedPathRule 仅供当前作用域管理 authority 查询。
// swagger:model
type EnterpriseProtectedPathRule struct {
	ID                  int64                         `json:"id"`
	Scope               EnterpriseFeatureScope        `json:"scope"`
	OwnerID             int64                         `json:"owner_id"`
	Config              EnterpriseProtectedPathConfig `json:"config"`
	ConfigSchemaVersion int                           `json:"config_schema_version"`
	Revision            int64                         `json:"revision"`
	CreatedBy           int64                         `json:"created_by"`
	UpdatedBy           int64                         `json:"updated_by"`
	Created             time.Time                     `json:"created"`
	Updated             time.Time                     `json:"updated"`
}

// EnterpriseMergeGateEvaluation 仅供本仓库及 PR 的当前管理 authority 查询。
// swagger:model
type EnterpriseMergeGateEvaluation struct {
	ID                int64            `json:"id"`
	OperationID       string           `json:"operation_id"`
	Attempt           int              `json:"attempt"`
	Phase             string           `json:"phase"`
	RepoID            int64            `json:"repo_id"`
	PullID            int64            `json:"pull_id"`
	ActorID           int64            `json:"actor_id"`
	Source            string           `json:"source"`
	Mode              string           `json:"mode"`
	HeadSHA           string           `json:"head_sha"`
	BaseSHA           string           `json:"base_sha"`
	MergedSHA         string           `json:"merged_sha"`
	CandidateDecision string           `json:"candidate_decision"`
	AdmissionDecision string           `json:"admission_decision"`
	ExecutionState    string           `json:"execution_state"`
	SnapshotVersion   int              `json:"snapshot_version"`
	SnapshotHash      string           `json:"snapshot_hash"`
	Reasons           []map[string]any `json:"reasons"`
	Snapshot          map[string]any   `json:"snapshot"`
	BypassRequested   bool             `json:"bypass_requested"`
	BypassUsed        bool             `json:"bypass_used"`
	BypassReason      string           `json:"bypass_reason"`
	Created           time.Time        `json:"created"`
	Started           *time.Time       `json:"started,omitempty"`
	Terminal          *time.Time       `json:"terminal,omitempty"`
}

// EnterpriseMergeGateReason 不包含上级策略标识、context 或自由文本。
// swagger:model
type EnterpriseMergeGateReason struct {
	Code           string `json:"code"`
	Source         string `json:"source"`
	State          string `json:"state"`
	MessageKey     string `json:"message_key"`
	Tone           string `json:"tone"`
	BypassCategory string `json:"bypass_category,omitempty"`
}

// EnterpriseMergeGatePreview 是当前 PR 的安全解释，不是执行许可。
// swagger:model
type EnterpriseMergeGatePreview struct {
	SnapshotVersion   int                         `json:"snapshot_version"`
	Mode              string                      `json:"mode"`
	Phase             string                      `json:"phase"`
	PreviewOnly       bool                        `json:"preview_only"`
	CandidateDecision string                      `json:"candidate_decision"`
	AdmissionDecision string                      `json:"admission_decision"`
	HeadSHA           string                      `json:"head_sha"`
	BaseSHA           string                      `json:"base_sha"`
	Reasons           []EnterpriseMergeGateReason `json:"reasons"`
	CanBypass         bool                        `json:"can_bypass"`
	CanSchedule       bool                        `json:"can_schedule"`
}
