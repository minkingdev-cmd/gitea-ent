// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"encoding/json" //nolint:depguard // 严格解析保留 config 原文。
	"errors"
	"net/http"
	"slices"

	authz_model "gitea.dev/models/enterpriseauthz"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/util"
	"gitea.dev/routers/common"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func RequireFeatureReader(ctx *context.APIContext) {
	if !setting.EnterpriseAuthz.Enabled {
		ctx.APIErrorNotFound()
		return
	}
	if ctx.Doer == nil || !ctx.Doer.IsActive || ctx.Doer.ProhibitLogin || ctx.Doer.IsRestricted || ctx.Doer.ExtDoerData != nil || !common.RepoCredentialCeiling(ctx.Base, ctx.Doer).Read || !ctx.Repo.Permission.HasAnyUnitAccessOrPublicAccess() {
		apiError(ctx, util.ErrPermissionDenied)
	}
}

func FeatureCatalog(ctx *context.APIContext) {
	result := api.EnterpriseFeatureCatalog{Version: authz.FeatureCatalogVersion, Features: []api.EnterpriseFeatureDefinition{}}
	for _, entry := range authz.FeatureCatalog() {
		result.Features = append(result.Features, api.EnterpriseFeatureDefinition{Key: string(entry.Key), Description: entry.Description, SupportedScopes: entry.SupportedScopes, DefaultState: string(entry.DefaultState), CapabilityKind: entry.CapabilityKind, ConfigSchemaVersion: entry.ConfigSchemaVersion})
	}
	ctx.JSON(http.StatusOK, result)
}

func featureEffectiveDTO(policy *authz_service.FeaturePolicy) api.EnterpriseFeatureEffective {
	metadata, _ := authz.LookupFeature(policy.Effective.Key)
	return api.EnterpriseFeatureEffective{Key: string(policy.Effective.Key), State: string(policy.Effective.State), Source: policy.Effective.Source.Scope, Locked: policy.Effective.LockedBy != nil, Conflict: len(policy.Effective.Conflicts) > 0, CapabilityKind: policy.Effective.CapabilityKind, NativeAvailable: policy.NativeAvailable, Pending: policy.Pending, ConfigSchemaVersion: metadata.ConfigSchemaVersion}
}

func featurePolicyDTO(policy *authz_service.FeaturePolicy) (*api.EnterpriseFeaturePolicy, error) {
	config, _, err := authz.ParseFeatureConfig(policy.Grant.FeatureKey, policy.Grant.State, []byte(policy.Grant.ConfigJSON))
	if err != nil {
		return nil, authz_service.ErrPolicyStorage
	}
	g := policy.Grant
	result := &api.EnterpriseFeaturePolicy{Grant: api.EnterpriseFeatureGrant{Key: string(g.FeatureKey), Scope: api.EnterpriseFeatureScope{Scope: authz_model.FeatureScopeName(g.ScopeType), ID: g.ScopeID}, State: string(g.State), Config: api.EnterpriseFeatureConfig{CheckContexts: config.CheckContexts}, Revision: g.Revision, CreatedBy: g.CreatedBy, UpdatedBy: g.UpdatedBy, Created: g.CreatedUnix.AsTime(), Updated: g.UpdatedUnix.AsTime()}, Effective: featureEffectiveDTO(policy), Config: api.EnterpriseFeatureConfig{CheckContexts: slices.Clone(policy.Effective.Config.CheckContexts)}, Chain: []api.EnterpriseFeatureLayer{}, Conflicts: []api.EnterpriseFeatureScope{}, ChainHash: policy.Hash, PolicyRevision: policy.PolicyRevision}
	for _, layer := range policy.Chain {
		result.Chain = append(result.Chain, api.EnterpriseFeatureLayer{Scope: layer.Scope, ID: layer.ID, State: string(layer.State), Revision: layer.Revision, Config: api.EnterpriseFeatureConfig{CheckContexts: slices.Clone(layer.Config.CheckContexts)}})
	}
	if lock := policy.Effective.LockedBy; lock != nil {
		result.LockedBy = &api.EnterpriseFeatureScope{Scope: lock.Scope, ID: lock.ID}
	}
	for _, conflict := range policy.Effective.Conflicts {
		result.Conflicts = append(result.Conflicts, api.EnterpriseFeatureScope{Scope: conflict.Scope, ID: conflict.ID})
	}
	return result, nil
}

func ListFeatures(ctx *context.APIContext) {
	options, err := pagination(ctx)
	if err != nil {
		apiError(ctx, err)
		return
	}
	policies, err := authz_service.ListFeaturePolicies(ctx, ctx.Doer, scope(ctx), scope(ctx).Type != authz_model.ScopeRepo)
	if err != nil {
		apiError(ctx, err)
		return
	}
	limit := options.Limit
	if limit == 0 {
		limit = 20
	}
	offset := min((max(1, options.Page)-1)*limit, len(policies))
	end := min(offset+limit, len(policies))
	total(ctx, int64(len(policies)))
	if scope(ctx).Type == authz_model.ScopeRepo {
		result := make([]api.EnterpriseFeatureEffective, 0)
		for _, policy := range policies[offset:end] {
			result = append(result, featureEffectiveDTO(policy))
		}
		ctx.JSON(http.StatusOK, result)
		return
	}
	result := make([]*api.EnterpriseFeaturePolicy, 0)
	for _, policy := range policies[offset:end] {
		dto, err := featurePolicyDTO(policy)
		if err != nil {
			apiError(ctx, err)
			return
		}
		result = append(result, dto)
	}
	ctx.JSON(http.StatusOK, result)
}

func GetFeature(ctx *context.APIContext) {
	policy, err := authz_service.GetFeaturePolicy(ctx, authz.FeatureKey(ctx.PathParam("key")), scope(ctx))
	if err != nil {
		apiError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, featureEffectiveDTO(policy))
}

func GetFeatureGrant(ctx *context.APIContext) {
	policy, err := authz_service.GetManagedFeaturePolicy(ctx, ctx.Doer, authz.FeatureKey(ctx.PathParam("key")), scope(ctx))
	if err != nil {
		apiError(ctx, err)
		return
	}
	dto, err := featurePolicyDTO(policy)
	if err != nil {
		apiError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, dto)
}

func parseFeatureInput(key authz.FeatureKey, fields map[string]json.RawMessage) (authz_service.FeatureGrantInput, error) {
	input := authz_service.FeatureGrantInput{Config: fields["config"]}
	if len(fields) != 3 || field(fields, "state", &input.State) != nil || field(fields, "expected_revision", &input.ExpectedRevision) != nil || input.ExpectedRevision < 0 {
		return input, authz_service.ErrInvalidPolicy
	}
	if _, _, err := authz.ParseFeatureConfig(key, input.State, input.Config); err != nil {
		return input, authz_service.ErrInvalidPolicy
	}
	return input, nil
}

func PutFeatureGrant(ctx *context.APIContext) {
	fields, ok := body(ctx, "state", "config", "expected_revision")
	if !ok {
		return
	}
	key := authz.FeatureKey(ctx.PathParam("key"))
	input, err := parseFeatureInput(key, fields)
	if err != nil {
		apiError(ctx, err)
		return
	}
	policy, err := authz_service.PutFeatureGrant(ctx, ctx.Doer, scope(ctx), key, input)
	if err != nil {
		apiError(ctx, err)
		return
	}
	dto, err := featurePolicyDTO(policy)
	if err != nil {
		apiError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, dto)
}

func ResetFeatureGrant(ctx *context.APIContext) {
	if _, exists := ctx.Req.URL.Query()["expected_revision"]; !exists {
		apiError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	revision, err := queryInt(ctx, "expected_revision")
	if err != nil || revision < 0 {
		apiError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	if err := authz_service.ResetFeatureGrant(ctx, ctx.Doer, scope(ctx), authz.FeatureKey(ctx.PathParam("key")), revision); err != nil {
		apiError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

func FeatureBusinessError(ctx *context.APIContext, err error) {
	if execution, ok := errors.AsType[*authz_service.ExecutionError](err); ok {
		ctx.APIError(execution.Status, execution.Reason)
		return
	}
	ctx.APIError(http.StatusServiceUnavailable, "feature_policy_unavailable")
}
