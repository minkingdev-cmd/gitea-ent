// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"encoding/json" //nolint:depguard // 严格解析保留配置原文。
	"errors"
	"net/http"

	authz_model "gitea.dev/models/enterpriseauthz"
	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/util"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
	pull_service "gitea.dev/services/pull"
)

func RequireMergeGateManagement(ctx *context.APIContext) {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseMergeGate.Enabled {
		ctx.APIErrorNotFound()
		return
	}
	if err := authz_service.CheckManagementAuthority(ctx, ctx.Doer, scope(ctx)); err != nil {
		mergeGateAPIError(ctx, err)
	}
}

func mergeGateAPIError(ctx *context.APIContext, err error) {
	if errors.Is(err, util.ErrPermissionDenied) || errors.Is(err, util.ErrNotExist) || errors.Is(err, authz_service.ErrInvalidPolicy) || errors.Is(err, authz_service.ErrRevisionConflict) {
		apiError(ctx, err)
		return
	}
	ctx.APIError(http.StatusServiceUnavailable, "merge_gate_policy_unavailable")
}

func protectedPathRuleDTO(rule *authz_model.ProtectedPathRule) (*api.EnterpriseProtectedPathRule, error) {
	if err := rule.Validate(); err != nil {
		return nil, authz_service.ErrPolicyStorage
	}
	config, _, err := authz.ParseProtectedPathConfig([]byte(rule.ConfigJSON))
	if err != nil {
		return nil, authz_service.ErrPolicyStorage
	}
	return &api.EnterpriseProtectedPathRule{ID: rule.ID, Scope: api.EnterpriseFeatureScope{Scope: authz_model.FeatureScopeName(rule.ScopeType), ID: rule.ScopeID}, OwnerID: rule.OwnerID, Config: api.EnterpriseProtectedPathConfig{PathPattern: config.PathPattern, BranchPattern: config.BranchPattern, RequiredRoleID: config.RequiredRoleID, CheckContexts: config.CheckContexts, Enabled: config.Enabled}, ConfigSchemaVersion: 1, Revision: rule.Revision, CreatedBy: rule.CreatedBy, UpdatedBy: rule.UpdatedBy, Created: rule.CreatedUnix.AsTime(), Updated: rule.UpdatedUnix.AsTime()}, nil
}

func parseProtectedPathInput(fields map[string]json.RawMessage) (authz_service.ProtectedPathRuleInput, error) {
	input := authz_service.ProtectedPathRuleInput{Config: fields["config"]}
	if len(fields) != 2 || field(fields, "expected_revision", &input.ExpectedRevision) != nil || input.ExpectedRevision < 0 {
		return input, authz_service.ErrInvalidPolicy
	}
	if _, _, err := authz.ParseProtectedPathConfig(input.Config); err != nil {
		return input, authz_service.ErrInvalidPolicy
	}
	return input, nil
}

func ListProtectedPathRules(ctx *context.APIContext) {
	options, err := pagination(ctx)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	rules, count, err := authz_service.ListProtectedPathRules(ctx, ctx.Doer, scope(ctx), options)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	result := make([]*api.EnterpriseProtectedPathRule, 0, len(rules))
	for i := range rules {
		dto, err := protectedPathRuleDTO(&rules[i])
		if err != nil {
			mergeGateAPIError(ctx, err)
			return
		}
		result = append(result, dto)
	}
	total(ctx, count)
	ctx.JSON(http.StatusOK, result)
}

func GetProtectedPathRule(ctx *context.APIContext) {
	identifier, err := id(ctx)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	rule, err := authz_service.GetProtectedPathRule(ctx, ctx.Doer, scope(ctx), identifier)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	if rule.Deleted {
		ctx.APIErrorNotFound()
		return
	}
	dto, err := protectedPathRuleDTO(rule)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, dto)
}

func CreateProtectedPathRule(ctx *context.APIContext) { putProtectedPathRule(ctx, false) }
func UpdateProtectedPathRule(ctx *context.APIContext) { putProtectedPathRule(ctx, true) }

func putProtectedPathRule(ctx *context.APIContext, update bool) {
	var identifier int64
	var err error
	if update {
		identifier, err = id(ctx)
		if err != nil {
			mergeGateAPIError(ctx, err)
			return
		}
	}
	fields, err := readBody(ctx, "config", "expected_revision")
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	input, err := parseProtectedPathInput(fields)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	rule, err := authz_service.PutProtectedPathRule(ctx, ctx.Doer, scope(ctx), identifier, input)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	dto, err := protectedPathRuleDTO(rule)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	status := http.StatusCreated
	if update {
		status = http.StatusOK
	}
	ctx.JSON(status, dto)
}

func DeleteProtectedPathRule(ctx *context.APIContext) {
	identifier, err := id(ctx)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	revision, err := queryInt(ctx, "expected_revision")
	if err != nil || revision <= 0 {
		mergeGateAPIError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	if err := authz_service.DeleteProtectedPathRule(ctx, ctx.Doer, scope(ctx), identifier, revision); err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

func mergeGateHistoryPull(ctx *context.APIContext) (*issues_model.PullRequest, error) {
	index := ctx.PathParamInt64("index")
	if index <= 0 {
		return nil, authz_service.ErrInvalidPolicy
	}
	return issues_model.GetPullRequestByIndex(ctx, ctx.Repo.Repository.ID, index)
}

func mergeGateEvaluationDTO(record *authz_model.MergeGateEvaluation) (*api.EnterpriseMergeGateEvaluation, error) {
	if record.Validate() != nil {
		return nil, authz_service.ErrPolicyStorage
	}
	dto := &api.EnterpriseMergeGateEvaluation{ID: record.ID, OperationID: record.OperationID, Attempt: record.Attempt, Phase: record.Phase, RepoID: record.RepoID, PullID: record.PullID, ActorID: record.ActorID, Source: record.Source, Mode: record.Mode, HeadSHA: record.HeadSHA, BaseSHA: record.BaseSHA, MergedSHA: record.MergedSHA, CandidateDecision: record.CandidateDecision, AdmissionDecision: record.AdmissionDecision, ExecutionState: record.ExecutionState, SnapshotVersion: record.SnapshotVersion, SnapshotHash: record.SnapshotHash, BypassRequested: record.BypassRequested, BypassUsed: record.BypassUsed, BypassReason: record.BypassReason, Created: record.CreatedUnix.AsTime()}
	if record.StartedUnix != 0 {
		started := record.StartedUnix.AsTime()
		dto.Started = &started
	}
	if record.TerminalUnix != 0 {
		terminal := record.TerminalUnix.AsTime()
		dto.Terminal = &terminal
	}
	if json.Unmarshal([]byte(record.ReasonsJSON), &dto.Reasons) != nil || json.Unmarshal([]byte(record.SnapshotJSON), &dto.Snapshot) != nil {
		return nil, authz_service.ErrPolicyStorage
	}
	return dto, nil
}

func ListMergeGateEvaluations(ctx *context.APIContext) {
	pr, err := mergeGateHistoryPull(ctx)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	options, err := pagination(ctx)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	records, count, err := authz_service.ListMergeGateEvaluations(ctx, ctx.Doer, ctx.Repo.Repository.ID, pr.ID, options)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	result := make([]*api.EnterpriseMergeGateEvaluation, 0, len(records))
	for i := range records {
		dto, err := mergeGateEvaluationDTO(&records[i])
		if err != nil {
			mergeGateAPIError(ctx, err)
			return
		}
		result = append(result, dto)
	}
	total(ctx, count)
	ctx.JSON(http.StatusOK, result)
}

func GetMergeGateEvaluation(ctx *context.APIContext) {
	pr, err := mergeGateHistoryPull(ctx)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	identifier, err := id(ctx)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	record, err := authz_service.GetMergeGateEvaluation(ctx, ctx.Doer, ctx.Repo.Repository.ID, pr.ID, identifier)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	dto, err := mergeGateEvaluationDTO(record)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, dto)
}

func PreviewMergeGate(ctx *context.APIContext) {
	if !setting.EnterpriseMergeGate.Enabled {
		ctx.APIErrorNotFound()
		return
	}
	pr, err := mergeGateHistoryPull(ctx)
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	result, err := pull_service.PreviewMergeGate(ctx, ctx.Doer, ctx.Repo.Repository.ID, pr.ID, repo_model.MergeStyle(ctx.FormString("style")), ctx.FormString("commit_id"))
	if err != nil {
		mergeGateAPIError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, result)
}

func RequireMergeGateReader(ctx *context.APIContext) {
	if !setting.EnterpriseMergeGate.Enabled {
		ctx.APIErrorNotFound()
		return
	}
	if !ctx.Repo.Permission.CanRead(unit.TypeCode) || !ctx.Repo.Permission.CanRead(unit.TypePullRequests) {
		ctx.APIErrorNotFound()
		return
	}
	if err := authz_service.CheckCargoIndexFeature(ctx, ctx.Repo.Repository); err != nil {
		mergeGateAPIError(ctx, err)
	}
}
