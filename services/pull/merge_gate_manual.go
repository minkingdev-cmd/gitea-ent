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
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func prepareManualMergeGateGit(ctx context.Context, pr *issues_model.PullRequest, commitID string, automatic bool) (*mergeGateGitContext, error) {
	if !git.IsStringValidObjectID(nil, commitID) || git.IsEmptyCommitID(commitID) {
		return nil, errors.New("manual_merge_commit_unproven")
	}
	if err := pr.LoadBaseRepo(ctx); err != nil {
		return nil, err
	}
	repo, err := git.OpenRepository(ctx, pr.BaseRepo)
	if err != nil {
		return nil, err
	}
	defer repo.Close()
	targetSHA, err := repo.GetBranchCommitID(ctx, pr.BaseBranch)
	if err != nil {
		return nil, err
	}
	present, err := repo.IsCommitInBranch(ctx, commitID, pr.BaseBranch)
	if err != nil {
		return nil, err
	}
	if !present {
		return nil, errors.New("manual_merge_pusher_unproven")
	}
	headSHA, err := repo.GetRefCommitID(ctx, pr.GetGitHeadRefName())
	if err != nil {
		return nil, err
	}
	commit, err := repo.GetCommit(ctx, commitID)
	if err != nil {
		return nil, err
	}
	head, err := repo.GetCommit(ctx, headSHA)
	if err != nil {
		return nil, err
	}
	included, err := commit.HasPreviousCommit(ctx, repo, head.ID)
	if err != nil || !included && commitID != headSHA {
		return nil, errors.New("manual_merge_head_unproven")
	}
	baseSHA, pusherID := "", int64(0)
	var attribution *authz_service.MergeGateQueueAttribution
	bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cursor := int64(0)
	for baseSHA == "" {
		var records []authz_model.MergeGateEvaluation
		query := db.GetEngine(bounded).Where("repo_id=? AND pull_id=? AND phase=? AND head_sha=?", pr.BaseRepoID, pr.ID, "manual_recognition", headSHA).In("source", []string{"git_http", "ssh"})
		if cursor > 0 {
			query = query.And("id<?", cursor)
		}
		if err := query.Desc("id").Limit(100).Find(&records); err != nil {
			return nil, err
		}
		if len(records) == 0 {
			break
		}
		for _, record := range records {
			cursor = record.ID
			var snapshot mergeGateSnapshot
			if record.Validate() == nil && json.Unmarshal([]byte(record.SnapshotJSON), &snapshot) == nil && snapshot.ManualPushProof && snapshot.ResultSHA == commitID && snapshot.PusherID == record.ActorID && snapshot.HeadSHA == headSHA {
				baseSHA, pusherID, attribution = record.BaseSHA, record.ActorID, snapshot.CredentialAttribution
				break
			}
		}
	}
	if baseSHA == "" || pusherID <= 0 {
		return nil, errors.New("manual_merge_base_unproven")
	}
	mergeBase, err := git.MergeBase(ctx, pr.BaseRepo, baseSHA, headSHA)
	if err != nil {
		return nil, err
	}
	paths, err := collectMergeGatePaths(ctx, pr.BaseRepo, mergeBase, headSHA)
	if err != nil || len(paths) == 0 {
		return nil, errMergeGatePathsIncomplete
	}
	return &mergeGateGitContext{Repo: pr.BaseRepo, HeadSHA: headSHA, BaseSHA: baseSHA, Paths: paths, Manual: true, TargetSHA: targetSHA, PusherID: pusherID, ManualAutomatic: automatic, CredentialAttribution: attribution}, nil
}

func RecordManualMergePush(ctx context.Context, actor *user_model.User, repo *repo_model.Repository, branch, oldSHA, newSHA, source string, ceiling authz_service.CredentialCeiling) error {
	if !setting.EnterpriseMergeGate.Enabled {
		return nil
	}
	if actor == nil || actor.ID <= 0 || actor.ExtDoerData != nil || source != "git_http" && source != "ssh" || !git.IsStringValidObjectID(nil, oldSHA) || git.IsEmptyCommitID(oldSHA) || !git.IsStringValidObjectID(nil, newSHA) || git.IsEmptyCommitID(newSHA) {
		return nil
	}
	attribution, err := authz_service.NewMergeGateReceiveAttribution(ctx, actor.ID, repo, source, ceiling)
	if err != nil {
		return err
	}
	pulls, err := issues_model.GetUnmergedPullRequestsByBaseInfo(ctx, repo.ID, branch)
	if err != nil {
		return err
	}
	gitRepo, err := git.OpenRepository(ctx, repo)
	if err != nil {
		return err
	}
	defer gitRepo.Close()
	merged, err := gitRepo.GetCommit(ctx, newSHA)
	if err != nil {
		return err
	}
	for _, pr := range pulls {
		headSHA, err := gitRepo.GetRefCommitID(ctx, pr.GetGitHeadRefName())
		if err != nil {
			return err
		}
		head, err := gitRepo.GetCommit(ctx, headSHA)
		if err != nil {
			return err
		}
		included, err := merged.HasPreviousCommit(ctx, gitRepo, head.ID)
		if err != nil {
			return err
		}
		if !included && newSHA != headSHA {
			continue
		}
		mergeBase, err := git.MergeBase(ctx, repo, oldSHA, headSHA)
		if err != nil {
			return err
		}
		paths, err := collectMergeGatePaths(ctx, repo, mergeBase, headSHA)
		if err != nil {
			return err
		}
		if len(paths) == 0 {
			continue
		}
		pr.BaseRepo = repo
		bound, _ := authz_service.WithObservationContext(authz_service.WithOperation(ctx), authz_service.EvaluateInput{Actor: actor, Repo: repo, Action: "repo.merge_pull_request", Credential: ceiling, ConditionContext: authz.ConditionContext{Source: source, Branch: branch, BranchKnown: true}})
		current := &mergeGateGitContext{Repo: repo, HeadSHA: headSHA, BaseSHA: oldSHA, Paths: paths, Manual: true, TargetSHA: newSHA, PusherID: actor.ID, PushProof: true, CredentialAttribution: attribution}
		_, err = admitMergeGate(bound, pr, actor, repo_model.MergeStyleManuallyMerged, MergeOptions{}, false, current, newSHA, false, "manual_recognition", "capture")
		if rejected, ok := errors.AsType[*authz_service.ExecutionError](err); ok && rejected.Reason != "merge_gate_evidence_persist_failed" {
			continue
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func recordUnprovenManualMerge(ctx context.Context, pr *issues_model.PullRequest, resultSHA string) error {
	ctx, cancel := context.WithTimeout(authz_service.WithOperation(ctx), 5*time.Second)
	defer cancel()
	head, err := git.GetFullCommitID(ctx, pr.BaseRepo, pr.GetGitHeadRefName())
	if err != nil {
		return err
	}
	evaluation := mergeGateEvaluation{Snapshot: mergeGateSnapshot{Version: authz.MergeGateSnapshotVersion, RepoID: pr.BaseRepoID, OwnerID: pr.BaseRepo.OwnerID, PullID: pr.ID, IssueID: pr.IssueID, HeadSHA: head, ResultSHA: resultSHA, Branch: pr.BaseBranch, GitAlreadyPresent: true, Facts: []authz.MergeGateFact{{Code: "paths_incomplete", Source: "gate", State: "error"}, {Code: "actor_invalid", Source: "gate", State: "error"}}}}
	if err := sealMergeGateEvaluation(&evaluation); err != nil {
		return err
	}
	reasons, err := json.Marshal(struct{ Blocking, Bypassed []authz.MergeGateFact }{Blocking: evaluation.Snapshot.Facts})
	if err != nil {
		return err
	}
	return db.WithIndependentTx(ctx, func(tx context.Context) error {
		previous := new(authz_model.MergeGateEvaluation)
		found, err := db.GetEngine(tx).Where("repo_id=? AND pull_id=? AND phase=? AND source=? AND actor_id=?", pr.BaseRepoID, pr.ID, "manual_recognition", "auto_merge", 0).Desc("id").Get(previous)
		if err != nil {
			return err
		}
		if found && previous.Validate() == nil && previous.SnapshotHash == evaluation.Hash {
			return nil
		}
		record := &authz_model.MergeGateEvaluation{OperationID: authz_service.MergeGateOperationID(ctx), Attempt: 1, Phase: "manual_recognition", RepoID: pr.BaseRepoID, PullID: pr.ID, IssueID: pr.IssueID, Source: "auto_merge", Mode: "enforce", HeadSHA: head, CandidateDecision: "error", AdmissionDecision: "error", ReasonsJSON: string(reasons), SnapshotJSON: evaluation.JSON, SnapshotHash: evaluation.Hash, SnapshotVersion: authz.MergeGateSnapshotVersion, ExecutionState: "not_started"}
		return authz_service.PersistMergeGateEvaluationTx(tx, record, false)
	})
}
