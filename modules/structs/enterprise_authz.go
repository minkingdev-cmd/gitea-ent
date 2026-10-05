// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package structs

import "time"

// EnterpriseAuthzScope 由服务器根据 URL 确定。
// swagger:model
type EnterpriseAuthzScope struct {
	Type string `json:"type"`
	ID   int64  `json:"id"`
}

// EnterpriseAuthzCondition 有界 glob 条件，字段间 AND，候选间 OR，路径须全部匹配。
// swagger:model
type EnterpriseAuthzCondition struct {
	BranchPattern  []string `json:"branch_pattern,omitempty"`
	PathPattern    []string `json:"path_pattern,omitempty"`
	RequestSources []string `json:"request_sources,omitempty"`
}

// EnterpriseAuthzPermission 仅支持 allow；condition 省略表示无条件。
// swagger:model
type EnterpriseAuthzPermission struct {
	// required: true
	Action string `json:"action"`
	// required: true
	Effect    string                    `json:"effect"`
	Condition *EnterpriseAuthzCondition `json:"condition,omitempty"`
}

// CreateEnterpriseAuthzRoleOption permissions 省略时复制源权限，否则使用显式集合。
// swagger:model
type CreateEnterpriseAuthzRoleOption struct {
	// required: true
	Name           string                       `json:"name"`
	Description    string                       `json:"description,omitempty"`
	CopyFromRoleID int64                        `json:"copy_from_role_id,omitempty"`
	Permissions    *[]EnterpriseAuthzPermission `json:"permissions,omitempty"`
}

// EditEnterpriseAuthzRoleOption 省略 permissions 保持原集合，空数组清空。
// swagger:model
type EditEnterpriseAuthzRoleOption struct {
	ExpectedRevision int64                        `json:"expected_revision"`
	Name             *string                      `json:"name,omitempty"`
	Description      *string                      `json:"description,omitempty"`
	Permissions      *[]EnterpriseAuthzPermission `json:"permissions,omitempty"`
}

// EnterpriseAuthzRole 是有权管理者可见的角色定义。
// swagger:model
type EnterpriseAuthzRole struct {
	ID          int64                       `json:"id"`
	Scope       EnterpriseAuthzScope        `json:"scope"`
	Key         string                      `json:"key"`
	Name        string                      `json:"name"`
	Description string                      `json:"description"`
	IsBuiltin   bool                        `json:"is_builtin"`
	Revision    int64                       `json:"revision"`
	CreatedBy   int64                       `json:"created_by"`
	Created     time.Time                   `json:"created"`
	Updated     time.Time                   `json:"updated"`
	Permissions []EnterpriseAuthzPermission `json:"permissions"`
}

// PutEnterpriseAuthzBindingOption repo 不是授权主体。
// swagger:model
type PutEnterpriseAuthzBindingOption struct {
	SubjectType string `json:"subject_type"`
	SubjectID   int64  `json:"subject_id"`
	RoleID      int64  `json:"role_id"`
}

// EnterpriseAuthzBinding 保留旧 owner 绑定以便显式解除，不代表其仍生效。
// swagger:model
type EnterpriseAuthzBinding struct {
	ID           int64                `json:"id"`
	SubjectType  string               `json:"subject_type"`
	SubjectID    int64                `json:"subject_id"`
	Scope        EnterpriseAuthzScope `json:"scope"`
	ScopeOwnerID int64                `json:"scope_owner_id"`
	RoleID       int64                `json:"role_id"`
	CreatedBy    int64                `json:"created_by"`
	Created      time.Time            `json:"created"`
}

// EnterpriseAuthzAction 描述当前 action 接线能力，不表示完整安全守卫已通过。
// swagger:model
type EnterpriseAuthzAction struct {
	Key              string   `json:"key"`
	Description      string   `json:"description"`
	Units            []string `json:"units"`
	Risk             string   `json:"risk"`
	Mutating         bool     `json:"mutating"`
	Observed         bool     `json:"observed"`
	UnitsAny         bool     `json:"units_any"`
	EnforceSupported bool     `json:"enforce_supported"`
}

// EnterpriseAuthzActionCatalog 是不可修改的 action 目录。
// swagger:model
type EnterpriseAuthzActionCatalog struct {
	Version int                     `json:"version"`
	Actions []EnterpriseAuthzAction `json:"actions"`
}

// EvaluateEnterpriseAuthzOption source 固定 diagnostic；paths 需完整，省略表示未知。
// swagger:model
type EvaluateEnterpriseAuthzOption struct {
	Action string   `json:"action"`
	UserID int64    `json:"user_id,omitempty"`
	Branch string   `json:"branch,omitempty"`
	Paths  []string `json:"paths,omitempty"`
}

// EnterpriseAuthzRoleRevision 不包含角色名称、描述或其他主体。
// swagger:model
type EnterpriseAuthzRoleRevision struct {
	ID       int64 `json:"id"`
	Revision int64 `json:"revision"`
}

// EnterpriseAuthzBindingReference 不包含主体详情。
// swagger:model
type EnterpriseAuthzBindingReference struct {
	ID int64 `json:"id"`
}

// EnterpriseAuthzConditionResult 仅返回条件指纹和匹配结果，不返回路径或模式。
// swagger:model
type EnterpriseAuthzConditionResult struct {
	RoleID        int64  `json:"role_id"`
	BindingID     int64  `json:"binding_id"`
	Revision      int64  `json:"revision"`
	Action        string `json:"action"`
	Effect        string `json:"effect"`
	ConditionHash string `json:"condition_hash"`
	Result        string `json:"result"`
}

// EnterpriseAuthzExplanation 是裁剪后的候选权限来源，不表示安全守卫已通过。
// swagger:model
type EnterpriseAuthzExplanation struct {
	NativeActions         []string                          `json:"native_actions"`
	RoleActions           []string                          `json:"role_actions"`
	Reason                string                            `json:"reason"`
	CandidateOnly         bool                              `json:"candidate_only"`
	SafetyGuardsEvaluated bool                              `json:"safety_guards_evaluated"`
	Roles                 []EnterpriseAuthzRoleRevision     `json:"roles"`
	Bindings              []EnterpriseAuthzBindingReference `json:"bindings"`
	Conditions            []EnterpriseAuthzConditionResult  `json:"conditions"`
}

// EnterpriseAuthzDiagnostic 只诊断 action，不是真实操作决策。
// swagger:model
type EnterpriseAuthzDiagnostic struct {
	EnterpriseAuthzExplanation
	Action            string   `json:"action"`
	CandidateDecision string   `json:"candidate_decision"`
	MatchedRoleIDs    []int64  `json:"matched_role_ids"`
	MatchedBindingIDs []int64  `json:"matched_binding_ids"`
	MissingActions    []string `json:"missing_actions"`
}

// EnterpriseAuthzEffectivePermissions 不执行操作，不计算完整 merge/branch gate。
// swagger:model
type EnterpriseAuthzEffectivePermissions struct {
	EnterpriseAuthzExplanation
	UnresolvedActions []string `json:"unresolved_actions"`
}

// EnterpriseAuthzUnitMode 是原生 unit 权限快照。
// swagger:model
type EnterpriseAuthzUnitMode struct {
	Key  string `json:"key"`
	Mode int    `json:"mode"`
}

// EnterpriseAuthzCredentialCeiling 不返回凭据引用或内容。
// swagger:model
type EnterpriseAuthzCredentialCeiling struct {
	Read       bool `json:"read"`
	Write      bool `json:"write"`
	NativeOnly bool `json:"native_only"`
}

// EnterpriseAuthzDecisionSnapshot 是当时的安全权限摘要，不读取当前角色解释历史。
// swagger:model
type EnterpriseAuthzDecisionSnapshot struct {
	Features          []EnterpriseFeatureSnapshot      `json:"features,omitempty"`
	Archived          *bool                            `json:"archived,omitempty"`
	CatalogVersion    int                              `json:"catalog_version"`
	NativeMode        int                              `json:"native_mode"`
	UnitModes         []EnterpriseAuthzUnitMode        `json:"unit_modes"`
	CredentialCeiling EnterpriseAuthzCredentialCeiling `json:"credential_ceiling"`
	RoleEligible      bool                             `json:"role_eligible"`
	BranchKnown       bool                             `json:"branch_known"`
	PathsComplete     bool                             `json:"paths_complete"`
	PathCount         int                              `json:"path_count"`
	NativeActions     []string                         `json:"native_actions"`
	Roles             []EnterpriseAuthzRoleRevision    `json:"roles"`
	Conditions        []EnterpriseAuthzConditionResult `json:"conditions"`
}

// EnterpriseAuthzDecision 区分候选解释、实际授权及原生执行结果。
// swagger:model
type EnterpriseAuthzDecision struct {
	ID                    int64                            `json:"id"`
	ObservationID         string                           `json:"observation_id"`
	OperationID           string                           `json:"operation_id"`
	ActorID               int64                            `json:"actor_id"`
	RepoID                int64                            `json:"repo_id"`
	OwnerID               int64                            `json:"owner_id"`
	Action                string                           `json:"action"`
	RequestSource         string                           `json:"request_source"`
	DecisionMode          string                           `json:"decision_mode"`
	AuthorizationDecision string                           `json:"authorization_decision"`
	AuthorizationReason   string                           `json:"authorization_reason"`
	ExecutionStarted      bool                             `json:"execution_started"`
	CandidateDecision     string                           `json:"candidate_decision"`
	Reason                string                           `json:"reason"`
	MissingActions        []string                         `json:"missing_actions"`
	NativeOutcome         string                           `json:"native_outcome"`
	NativeStage           string                           `json:"native_stage"`
	Snapshot              *EnterpriseAuthzDecisionSnapshot `json:"snapshot"`
	// CandidateOnly 仅描述候选解释，不否定独立的真实授权字段。
	CandidateOnly         bool      `json:"candidate_only"`
	SafetyGuardsEvaluated bool      `json:"safety_guards_evaluated"`
	Created               time.Time `json:"created"`
}
