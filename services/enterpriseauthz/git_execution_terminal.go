// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
)

func CompleteGitExecution(ctx context.Context, operation *HookOperation, input GitExecutionInput) {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce || operation == nil || input.Actor == nil || input.Repo == nil || !input.Ref.IsBranch() || !validHookInput(operation, EvaluateInput{Actor: input.Actor, Repo: input.Repo, Credential: input.Credential, ConditionContext: authz.ConditionContext{Source: input.Source}}) {
		return
	}
	input.Merge = false
	hash := sha256.Sum256([]byte(gitExecutionIntent(input)))
	intentHash := hex.EncodeToString(hash[:])
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), observationBudget)
	defer cancel()
	if input.GitRepo == nil {
		return
	}
	actual, refErr := git.GetBranchCommitID(bounded, input.GitRepo, input.Ref.BranchName())
	format := git.ObjectFormatFromName(input.Repo.ObjectFormatName)
	if input.Repo.ObjectFormatName == "" {
		format = git.Sha1ObjectFormat
	}
	deleted := input.NewCommitID == format.EmptyObjectID().String()
	if (deleted && !errors.Is(refErr, util.ErrNotExist)) || (!deleted && (refErr != nil || actual != input.NewCommitID)) {
		return
	}
	err := db.WithIndependentTx(bounded, func(tx context.Context) error {
		var records []authz_model.DecisionRecord
		if err := db.GetEngine(tx).Where("operation_id = ? AND actor_id = ? AND repo_id = ? AND request_source = ? AND decision_mode = ? AND native_outcome = ?", operation.payload.OperationID, input.Actor.ID, input.Repo.ID, input.Source, "enforce", "unknown").And("snapshot_json LIKE ?", "%\"intent_hash\":\""+intentHash+"\"%").Limit(3).Find(&records); err != nil {
			return err
		}
		selected := make([]authz_model.DecisionRecord, 0, 2)
		for _, record := range records {
			var snapshot roleSnapshot
			if json.Unmarshal([]byte(record.SnapshotJSON), &snapshot) != nil || snapshot.IntentHash != intentHash {
				continue
			}
			for _, previous := range selected {
				if previous.Action == record.Action {
					return errors.New("evidence_persist_failed")
				}
			}
			if record.AuthorizationDecision != "allow" && record.AuthorizationDecision != "fallback" {
				return errors.New("invalid_execution_context")
			}
			selected = append(selected, record)
		}
		for i := range selected {
			record := &selected[i]
			if !record.ExecutionStarted {
				record.AuthorizationDecision, record.AuthorizationReason = "fallback", "evidence_persist_failed"
			}
			record.ExecutionStarted = true
			record.NativeOutcome, record.NativeStage = "success", "transport"
			if err := finalizeExecutionRecord(tx, record); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		reportExecutionFailure("evidence_persist_failed")
	}
}
