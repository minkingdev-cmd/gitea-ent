// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
)

type MergeGateFeatureRequirements struct {
	Contexts []authz.MergeGateContext
	Facts    []authz.MergeGateFact
	Policies []api.EnterpriseFeatureSnapshot
}

func CollectMergeGateFeatureRequirements(ctx context.Context, repoID int64) (MergeGateFeatureRequirements, error) {
	var result MergeGateFeatureRequirements
	if !setting.EnterpriseMergeGate.Enabled {
		return result, nil
	}
	read := func(tx context.Context) error {
		for _, metadata := range authz.FeatureCatalog() {
			if metadata.CapabilityKind != "policy_only" && metadata.Key != authz.FeaturePullRequests && metadata.Key != authz.FeatureRequiredStatusChecks {
				continue
			}
			policy, err := featurePolicy(tx, metadata.Key, authz_model.Scope{Type: authz_model.ScopeRepo, ID: repoID})
			if err != nil {
				return ErrPolicyStorage
			}
			result.Policies = append(result.Policies, featureSnapshot(policy))
			if metadata.Key == authz.FeaturePullRequests && policy.Effective.State == authz.FeatureDisabled {
				result.Facts = append(result.Facts, authz.MergeGateFact{Code: "feature_disabled", Source: "feature", Context: string(metadata.Key), State: "failed"})
			}
			if policy.Effective.State != authz.FeatureRequired {
				continue
			}
			if metadata.CapabilityKind == "native_gate" && policy.Pending {
				result.Facts = append(result.Facts, authz.MergeGateFact{Code: "feature_native_pending", Source: "feature", Context: string(metadata.Key), State: "failed"})
			}
			if metadata.Key == authz.FeaturePullRequests {
				continue
			}
			if len(policy.Effective.Config.CheckContexts) == 0 {
				result.Facts = append(result.Facts, authz.MergeGateFact{Code: "required_contexts_empty", Source: "feature", Context: string(metadata.Key), State: "failed"})
			}
			for _, context := range policy.Effective.Config.CheckContexts {
				result.Contexts = append(result.Contexts, authz.MergeGateContext{Context: context, Source: "feature"})
			}
		}
		return nil
	}
	var err error
	if db.InTransaction(ctx) {
		err = read(ctx)
	} else {
		err = db.WithIndependentReadTx(ctx, read)
	}
	if err != nil {
		return MergeGateFeatureRequirements{}, err
	}
	return result, nil
}
