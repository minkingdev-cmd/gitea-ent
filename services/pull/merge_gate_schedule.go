// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"errors"
	"net/http"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func PersistMergeGateScheduleTx(ctx context.Context, actor *user_model.User, pr *issues_model.PullRequest, queueID int64, style repo_model.MergeStyle, options MergeOptions) error {
	if !setting.EnterpriseMergeGate.Enabled {
		return nil
	}
	if !db.InTransaction(ctx) {
		return mergeGateExecutionError("merge_gate_evidence_persist_failed", http.StatusServiceUnavailable)
	}
	if err := pr.LoadBaseRepo(ctx); err != nil {
		return mergeGateExecutionError("merge_gate_unavailable", http.StatusServiceUnavailable)
	}
	if err := authz_service.LockMergeGatePolicyScopes(ctx, authz_model.Scope{Type: authz_model.ScopeRepo, ID: pr.BaseRepoID}); err != nil {
		return err
	}
	mode := "shadow"
	if setting.EnterpriseMergeGate.Enforce {
		mode = "enforce"
	}
	source, ceiling := authz_service.ExecutionAttributionForActor(ctx, actor, pr.BaseRepoID)
	var attribution *authz_service.MergeGateQueueAttribution
	credentialErr := db.WithSavepoint(ctx, func(snapshot context.Context) error {
		var err error
		attribution, err = authz_service.NewMergeGateQueueAttribution(snapshot, actor.ID, pr.BaseRepo, source, ceiling)
		return err
	})
	if errors.Is(credentialErr, db.ErrObservationTransactionUnavailable) {
		return mergeGateExecutionError("merge_gate_evidence_persist_failed", http.StatusServiceUnavailable)
	}
	if attribution != nil {
		ceiling = attribution.Credential
	}
	current, cancel, _ := prepareMergeGateGit(ctx, pr)
	defer cancel()
	evaluation, err := collectMergeGateEvaluation(ctx, pr, actor, style, mode, "schedule", source, ceiling, authz.MergeGateBypass{Requested: options.Force || options.BypassReason != "" || len(options.BypassCategories) > 0, Reason: options.BypassReason, Categories: options.BypassCategories}, current, "")
	if err != nil {
		return err
	}
	evaluation.Snapshot.CredentialAttribution = attribution
	if credentialErr != nil {
		fact := authz.MergeGateFact{Code: "facts_read_failed", Source: "credential", State: "error"}
		if errors.Is(credentialErr, authz_service.ErrMergeGateQueueUnattributed) {
			fact.Code, fact.State = "credential_denied", "failed"
		}
		evaluation.Snapshot.Facts = append(evaluation.Snapshot.Facts, fact)
	}
	if err := sealMergeGateEvaluation(&evaluation); err != nil {
		return err
	}
	evaluation.Result = authz.EvaluateMergeGate(authz.MergeGateInput{Mode: mode, Phase: "schedule", Facts: evaluation.Snapshot.Facts, Bypass: evaluation.Bypass})
	reasons, err := json.Marshal(struct{ Blocking, Bypassed []authz.MergeGateFact }{evaluation.Result.BlockingReasons, evaluation.Result.BypassedReasons})
	if err != nil {
		return err
	}
	record := &authz_model.MergeGateEvaluation{OperationID: authz_service.MergeGateOperationID(ctx), Attempt: 1, Phase: "schedule", RepoID: pr.BaseRepoID, PullID: pr.ID, IssueID: evaluation.Snapshot.IssueID, ActorID: actor.ID, ScheduledMergeID: queueID, Source: source, Mode: mode, HeadSHA: evaluation.Snapshot.HeadSHA, BaseSHA: evaluation.Snapshot.BaseSHA, CandidateDecision: evaluation.Result.CandidateDecision, AdmissionDecision: evaluation.Result.AdmissionDecision, ReasonsJSON: string(reasons), SnapshotJSON: evaluation.JSON, SnapshotHash: evaluation.Hash, SnapshotVersion: authz.MergeGateSnapshotVersion, BypassRequested: evaluation.Result.BypassRequested, ExecutionState: "not_started"}
	if err := authz_service.PersistMergeGateEvaluationTx(ctx, record, false); err != nil {
		return mergeGateExecutionError("merge_gate_evidence_persist_failed", http.StatusServiceUnavailable)
	}
	if mode == "enforce" && evaluation.Result.CandidateDecision != "allow" && !evaluation.Result.Waiting {
		result := evaluation.Result
		result.AdmissionDecision = result.CandidateDecision
		return mergeGateRejection(result)
	}
	return nil
}

func PersistDeniedMergeGateSchedule(ctx context.Context, actor *user_model.User, pr *issues_model.PullRequest, style repo_model.MergeStyle, options MergeOptions) error {
	var rejection error
	err := db.WithIndependentTx(authz_service.ExecutionParentContext(ctx), func(tx context.Context) error {
		rejection = PersistMergeGateScheduleTx(tx, actor, pr, 0, style, options)
		if typed, ok := errors.AsType[*authz_service.ExecutionError](rejection); ok && typed.Reason != "merge_gate_evidence_persist_failed" {
			return nil
		}
		return rejection
	})
	if err != nil {
		return mergeGateExecutionError("merge_gate_evidence_persist_failed", http.StatusServiceUnavailable)
	}
	return rejection
}
