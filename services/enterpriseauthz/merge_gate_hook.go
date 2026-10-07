// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
)

type mergeGateHookKey struct{}

type mergeGateHookBinding struct {
	EvaluationID int64  `json:"evaluation_id"`
	OperationID  string `json:"operation_id"`
	RepoID       int64  `json:"repo_id"`
	ActorID      int64  `json:"actor_id"`
	BranchHash   string `json:"branch_hash"`
	BaseSHA      string `json:"base_sha"`
	ResultSHA    string `json:"result_sha"`
	SnapshotHash string `json:"snapshot_hash"`
}

func WithMergeGateHookAdmission(ctx context.Context, record *authz_model.MergeGateEvaluation, branch, resultSHA string) context.Context {
	if record == nil || record.ID <= 0 || record.ExecutionState != "started" || record.OperationID != MergeGateOperationID(ctx) {
		return ctx
	}
	binding := mergeGateHookBinding{EvaluationID: record.ID, OperationID: record.OperationID, RepoID: record.RepoID, ActorID: record.ActorID, BranchHash: hookBranchHash(branch), BaseSHA: record.BaseSHA, ResultSHA: resultSHA, SnapshotHash: record.SnapshotHash}
	return context.WithValue(ctx, mergeGateHookKey{}, binding)
}

func ValidateMergeGateHook(ctx context.Context, operation *HookOperation, ref git.RefName, oldSHA, newSHA string) error {
	if !setting.EnterpriseMergeGate.Enabled || !setting.EnterpriseMergeGate.Enforce || operation == nil {
		return nil
	}
	binding := operation.payload.MergeGate
	if binding == nil {
		if ref.IsBranch() && operation.Owns("repo.merge_pull_request", ref.BranchName()) {
			return errors.New("merge_gate_hook_unadmitted")
		}
		return nil
	}
	if !ref.IsBranch() || binding.BranchHash != hookBranchHash(ref.BranchName()) || binding.BaseSHA != oldSHA || binding.ResultSHA != newSHA || binding.OperationID != operation.payload.OperationID || binding.RepoID != operation.payload.RepoID || binding.ActorID != operation.payload.ActorID {
		return errors.New("merge_gate_hook_mismatch")
	}
	record := new(authz_model.MergeGateEvaluation)
	found, err := db.GetEngine(ctx).ID(binding.EvaluationID).Get(record)
	if err != nil {
		return err
	}
	if !found || record.Validate() != nil || record.ExecutionState != "started" || record.OperationID != binding.OperationID || record.RepoID != binding.RepoID || record.ActorID != binding.ActorID || record.BaseSHA != binding.BaseSHA || record.SnapshotHash != binding.SnapshotHash || record.AdmissionDecision != "allow" && record.AdmissionDecision != "bypass" {
		return errors.New("merge_gate_hook_unadmitted")
	}
	var snapshot struct {
		ResultSHA string `json:"result_sha"`
	}
	if json.Unmarshal([]byte(record.SnapshotJSON), &snapshot) != nil || snapshot.ResultSHA != newSHA {
		return errors.New("merge_gate_hook_mismatch")
	}
	return nil
}
