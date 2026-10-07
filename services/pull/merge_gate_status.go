// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"errors"
	"slices"

	"gitea.dev/models/db"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	authz_service "gitea.dev/services/enterpriseauthz"
)

type mergeGateStatusFacts struct {
	Contexts []authz.MergeGateContext        `json:"contexts"`
	Statuses []authz.MergeGateStatus         `json:"statuses"`
	Facts    []authz.MergeGateFact           `json:"facts"`
	Features []api.EnterpriseFeatureSnapshot `json:"features"`
}

func collectMergeGateStatuses(ctx context.Context, pr *issues_model.PullRequest, headSHA string, pathContexts []authz.MergeGateContext) (mergeGateStatusFacts, error) {
	var result mergeGateStatusFacts
	if !setting.EnterpriseMergeGate.Enabled {
		return result, nil
	}
	if pr == nil || pr.BaseRepoID <= 0 || !git.IsStringValidObjectID(nil, headSHA) || git.IsEmptyCommitID(headSHA) {
		return result, errors.New("merge_gate_status_context_invalid")
	}
	err := func(tx context.Context) error {
		current := *pr
		current.BaseRepo = nil
		if err := current.LoadBaseRepo(tx); err != nil {
			return err
		}
		pb, err := git_model.GetFirstMatchProtectedBranchRule(tx, current.BaseRepoID, current.BaseBranch)
		if err != nil {
			return err
		}
		native, err := EffectiveRequiredContexts(tx, current.BaseRepo, pb)
		if err != nil {
			return err
		}
		if pb != nil && pb.EnableStatusCheck && len(native) == 0 {
			result.Contexts = append(result.Contexts, authz.MergeGateContext{Context: "*", Source: "native", AllStatuses: true})
		}
		for _, pattern := range native {
			result.Contexts = append(result.Contexts, authz.MergeGateContext{Context: pattern, Source: "native", Pattern: true})
		}
		features, err := authz_service.CollectMergeGateFeatureRequirements(tx, current.BaseRepoID)
		if err != nil {
			return err
		}
		result.Features = features.Policies
		result.Contexts = append(result.Contexts, features.Contexts...)
		result.Contexts = append(result.Contexts, pathContexts...)
		result.Facts = features.Facts
		if len(result.Contexts) > authz.MaxMergeGateFacts {
			return errors.New("merge_gate_contexts_limit_exceeded")
		}
		statuses, err := git_model.GetLatestCommitStatus(tx, current.BaseRepoID, headSHA, db.ListOptionsAll)
		if err != nil {
			return err
		}
		if len(statuses) > authz.MaxMergeGateFacts {
			return errors.New("merge_gate_statuses_limit_exceeded")
		}
		for _, status := range statuses {
			result.Statuses = append(result.Statuses, authz.MergeGateStatus{ID: status.ID, RepoID: status.RepoID, SHA: status.SHA, Context: status.Context, ContextHash: status.ContextHash, State: string(status.State), CreatorID: status.CreatorID})
		}
		slices.SortFunc(result.Statuses, func(a, b authz.MergeGateStatus) int {
			if a.ID < b.ID {
				return -1
			}
			if a.ID > b.ID {
				return 1
			}
			return 0
		})
		result.Facts = append(result.Facts, authz.EvaluateMergeGateContexts(current.BaseRepoID, headSHA, result.Contexts, result.Statuses)...)
		if len(result.Facts) > authz.MaxMergeGateFacts {
			return errors.New("merge_gate_facts_limit_exceeded")
		}
		return nil
	}
	var readErr error
	if db.InTransaction(ctx) {
		readErr = err(ctx)
	} else {
		readErr = db.WithIndependentReadTx(ctx, err)
	}
	if readErr != nil {
		return mergeGateStatusFacts{}, readErr
	}
	return result, nil
}
