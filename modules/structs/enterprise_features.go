// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package structs

import "time"

// EnterpriseFeatureDefinition 描述能力，不表示外部工具已接入。
// swagger:model
type EnterpriseFeatureDefinition struct {
	Key                 string   `json:"key"`
	Description         string   `json:"description"`
	SupportedScopes     []string `json:"supported_scopes"`
	DefaultState        string   `json:"default_state"`
	CapabilityKind      string   `json:"capability_kind"`
	ConfigSchemaVersion int      `json:"config_schema_version"`
}

// EnterpriseFeatureCatalog 固定版本化目录。
// swagger:model
type EnterpriseFeatureCatalog struct {
	Version  int                           `json:"version"`
	Features []EnterpriseFeatureDefinition `json:"features"`
}

// EnterpriseFeatureConfig 仅允许非敏感的状态检查 context 名称。
// swagger:model
type EnterpriseFeatureConfig struct {
	CheckContexts []string `json:"check_contexts,omitempty"`
}

// PutEnterpriseFeatureGrantOption 使用单调版本 CAS；首次写入版本为 0。
// swagger:model
type PutEnterpriseFeatureGrantOption struct {
	// required: true
	State string `json:"state"`
	// required: true
	Config EnterpriseFeatureConfig `json:"config"`
	// required: true
	ExpectedRevision int64 `json:"expected_revision"`
}

// EnterpriseFeatureEffective 为原生 reader 的非敏感投影。
// swagger:model
type EnterpriseFeatureEffective struct {
	Key                 string `json:"key"`
	State               string `json:"state"`
	Source              string `json:"source"`
	Locked              bool   `json:"locked"`
	Conflict            bool   `json:"conflict"`
	CapabilityKind      string `json:"capability_kind"`
	NativeAvailable     bool   `json:"native_available"`
	Pending             bool   `json:"pending"`
	ConfigSchemaVersion int    `json:"config_schema_version"`
}

// EnterpriseFeatureScope 由 URL/current owner 决定。
// swagger:model
type EnterpriseFeatureScope struct {
	Scope string `json:"scope"`
	ID    int64  `json:"id"`
}

// EnterpriseFeatureGrant 的 inherited revision=0 表示未持久化。
// swagger:model
type EnterpriseFeatureGrant struct {
	Key       string                  `json:"key"`
	Scope     EnterpriseFeatureScope  `json:"scope"`
	State     string                  `json:"state"`
	Config    EnterpriseFeatureConfig `json:"config"`
	Revision  int64                   `json:"revision"`
	CreatedBy int64                   `json:"created_by"`
	UpdatedBy int64                   `json:"updated_by"`
	Created   time.Time               `json:"created"`
	Updated   time.Time               `json:"updated"`
}

// EnterpriseFeatureLayer 为有权管理者提供参与链。
// swagger:model
type EnterpriseFeatureLayer struct {
	Scope    string                  `json:"scope"`
	ID       int64                   `json:"id"`
	State    string                  `json:"state"`
	Config   EnterpriseFeatureConfig `json:"config"`
	Revision int64                   `json:"revision"`
}

// EnterpriseFeaturePolicy 为管理者的安全详细投影。
// swagger:model
type EnterpriseFeaturePolicy struct {
	Grant          EnterpriseFeatureGrant     `json:"grant"`
	Effective      EnterpriseFeatureEffective `json:"effective"`
	Config         EnterpriseFeatureConfig    `json:"config"`
	Chain          []EnterpriseFeatureLayer   `json:"chain"`
	LockedBy       *EnterpriseFeatureScope    `json:"locked_by,omitempty"`
	Conflicts      []EnterpriseFeatureScope   `json:"conflicts"`
	ChainHash      string                     `json:"chain_hash"`
	PolicyRevision int64                      `json:"policy_revision"`
}

// EnterpriseFeatureSnapshot 不含 config 原文或祖先/actor 标识。
// swagger:model
type EnterpriseFeatureSnapshot struct {
	Version             int    `json:"version"`
	Key                 string `json:"key"`
	State               string `json:"state"`
	Source              string `json:"source"`
	Locked              bool   `json:"locked"`
	Conflict            bool   `json:"conflict"`
	ChainHash           string `json:"chain_hash"`
	ConfigHash          string `json:"config_hash"`
	ContextCount        int    `json:"context_count"`
	CapabilityKind      string `json:"capability_kind"`
	NativeAvailable     bool   `json:"native_available"`
	Pending             bool   `json:"pending"`
	ConfigSchemaVersion int    `json:"config_schema_version"`
}
