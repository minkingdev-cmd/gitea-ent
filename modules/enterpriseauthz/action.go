// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"errors"
	"slices"
)

type Action string

const (
	CatalogVersion                = 1
	ViewMetadata           Action = "repo.view_metadata"
	ReadCode               Action = "repo.read_code"
	Clone                  Action = "repo.clone"
	CreateBranch           Action = "repo.create_branch"
	PushBranch             Action = "repo.push_branch"
	PushProtectedBranch    Action = "repo.push_protected_branch"
	CreatePullRequest      Action = "repo.create_pull_request"
	ReviewPullRequest      Action = "repo.review_pull_request"
	MergePullRequest       Action = "repo.merge_pull_request"
	ManageBranchProtection Action = "repo.manage_branch_protection"
	ManageCodeowners       Action = "repo.manage_codeowners"
	ManageWebhook          Action = "repo.manage_webhook"
	ManageCI               Action = "repo.manage_ci"
	ManageSecret           Action = "repo.manage_secret"
	ManageFeatureGrant     Action = "repo.manage_feature_grant"
	Migrate                Action = "repo.migrate"
	Transfer               Action = "repo.transfer"
	Archive                Action = "repo.archive"
	Delete                 Action = "repo.delete"
)

type ActionMetadata struct {
	Key         Action   `json:"key"`
	Description string   `json:"description"`
	Units       []string `json:"units"`
	Risk        string   `json:"risk"`
	Mutating    bool     `json:"mutating"`
	Observed    bool     `json:"observed"`
	UnitsAny    bool     `json:"units_any"`
}

var actions = []ActionMetadata{
	{ViewMetadata, "查看仓库元数据", nil, "low", false, true, false},
	{ReadCode, "读取代码", []string{"code"}, "low", false, true, false},
	{Clone, "克隆或获取代码", []string{"code"}, "low", false, true, false},
	{CreateBranch, "创建分支", []string{"code"}, "medium", true, true, false},
	{PushBranch, "推送普通分支", []string{"code"}, "medium", true, true, false},
	{PushProtectedBranch, "推送保护分支", []string{"code"}, "high", true, true, false},
	{CreatePullRequest, "创建合并请求", []string{"code", "pull_requests"}, "medium", true, true, false},
	{ReviewPullRequest, "评审合并请求", []string{"pull_requests"}, "medium", true, true, false},
	{MergePullRequest, "合并请求", []string{"code", "pull_requests"}, "high", true, true, false},
	{ManageBranchProtection, "管理分支保护", []string{"code"}, "high", true, true, false},
	{ManageCodeowners, "管理 CODEOWNERS", []string{"code"}, "high", true, true, false},
	{ManageWebhook, "管理仓库 webhook", nil, "high", true, true, false},
	{ManageCI, "管理 CI 设置", []string{"code", "actions"}, "high", true, true, true},
	{ManageSecret, "管理仓库 secret", []string{"actions"}, "high", true, true, false},
	{ManageFeatureGrant, "管理功能授权（仅目录和诊断）", nil, "high", true, false, false},
	{Migrate, "迁移到已创建的本地仓库", nil, "high", true, true, false},
	{Transfer, "转移仓库", nil, "high", true, true, false},
	{Archive, "归档仓库", nil, "high", true, true, false},
	{Delete, "删除仓库", nil, "high", true, true, false},
}

func Catalog() []ActionMetadata {
	result := slices.Clone(actions)
	for i := range result {
		result[i].Units = slices.Clone(result[i].Units)
	}
	return result
}

func LookupAction(key Action) (ActionMetadata, bool) {
	for _, a := range actions {
		if a.Key == key {
			a.Units = slices.Clone(a.Units)
			return a, true
		}
	}
	return ActionMetadata{}, false
}

func ValidatePermission(action Action, effect string) error {
	if _, ok := LookupAction(action); !ok {
		return errors.New("unknown_action")
	}
	if effect != "allow" {
		return errors.New("invalid_effect")
	}
	return nil
}

func BuiltinRoles() map[string][]Action {
	return map[string][]Action{
		"guest":               {ViewMetadata},
		"reporter":            {ViewMetadata, ReadCode, Clone},
		"developer":           {ViewMetadata, ReadCode, Clone, CreateBranch, PushBranch, CreatePullRequest},
		"reviewer":            {ViewMetadata, ReadCode, Clone, ReviewPullRequest},
		"maintainer":          {ViewMetadata, ReadCode, Clone, CreateBranch, PushBranch, CreatePullRequest, ReviewPullRequest, MergePullRequest, ManageWebhook, ManageCI},
		"security-maintainer": {ViewMetadata, ReadCode, Clone, ReviewPullRequest, ManageCodeowners, ManageCI},
		"owner":               {ViewMetadata, ReadCode, Clone, CreateBranch, PushBranch, PushProtectedBranch, CreatePullRequest, ReviewPullRequest, MergePullRequest, ManageBranchProtection, ManageCodeowners, ManageWebhook, ManageCI, ManageSecret, ManageFeatureGrant, Migrate, Transfer, Archive, Delete},
		"platform-admin":      {ViewMetadata, ReadCode, Clone, CreateBranch, PushBranch, PushProtectedBranch, CreatePullRequest, ReviewPullRequest, MergePullRequest, ManageBranchProtection, ManageCodeowners, ManageWebhook, ManageCI, ManageSecret, ManageFeatureGrant, Migrate, Transfer, Archive, Delete},
	}
}
