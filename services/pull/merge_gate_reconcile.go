// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"errors"
	"time"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	issues_model "gitea.dev/models/issues"
	"gitea.dev/modules/git"
	"gitea.dev/modules/globallock"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/timeutil"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func ReconcileMergeGateEvaluations(ctx context.Context) error {
	if !setting.EnterpriseMergeGate.Enabled {
		return nil
	}
	var failures []error
	cursor := int64(0)
	for {
		var records []*authz_model.MergeGateEvaluation
		err := db.GetEngine(ctx).In("execution_state", []string{"started", "unknown"}).Where("started_unix < ?", timeutil.TimeStampNow().AddDuration(-10*time.Minute)).And("id > ?", cursor).Asc("id").Limit(100).Find(&records)
		if err != nil {
			return err
		}
		if len(records) == 0 {
			break
		}
		for _, record := range records {
			cursor = record.ID
			bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
			err := globallock.LockAndDo(bounded, getPullWorkingLockKey(record.PullID), func(ctx context.Context) error {
				fresh := new(authz_model.MergeGateEvaluation)
				found, err := db.GetEngine(ctx).ID(record.ID).Get(fresh)
				if err != nil || !found {
					return err
				}
				return reconcileMergeGateEvaluation(ctx, fresh)
			})
			cancel()
			if err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}

func reconcileMergeGateEvaluation(ctx context.Context, record *authz_model.MergeGateEvaluation) error {
	if record.ExecutionState != "started" && record.ExecutionState != "unknown" {
		return nil
	}
	if err := record.Validate(); err != nil {
		return err
	}
	var snapshot mergeGateSnapshot
	if err := json.Unmarshal([]byte(record.SnapshotJSON), &snapshot); err != nil {
		return err
	}
	state, sha := "unknown", ""
	pr, err := issues_model.GetPullRequestByID(ctx, record.PullID)
	if err != nil && !issues_model.IsErrPullRequestNotExist(err) {
		return err
	}
	if err == nil && pr.BaseRepoID == record.RepoID && snapshot.RepoID == record.RepoID && snapshot.PullID == record.PullID && pr.BaseBranch == snapshot.Branch && pr.HasMerged && pr.MergedCommitID == snapshot.ResultSHA && git.IsStringValidObjectID(nil, snapshot.ResultSHA) && !git.IsEmptyCommitID(snapshot.ResultSHA) {
		if err := pr.LoadBaseRepo(ctx); err != nil {
			return err
		}
		repo, err := git.OpenRepository(ctx, pr.BaseRepo)
		if err != nil {
			return err
		}
		defer repo.Close()
		present, err := repo.IsCommitInBranch(ctx, snapshot.ResultSHA, snapshot.Branch)
		if err != nil {
			return err
		}
		proof, err := authz_service.HasMergeGateMarker(ctx, record, snapshot.ResultSHA)
		if err != nil {
			return err
		}
		if present && proof {
			state, sha = "succeeded", snapshot.ResultSHA
		}
	}
	if state == record.ExecutionState {
		return nil
	}
	return authz_service.FinishMergeGateEvaluation(ctx, record, state, sha)
}
