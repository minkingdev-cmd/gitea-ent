// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/log"
	"gitea.dev/modules/setting"
	"gitea.dev/services/audit"
)

func RecordMergeGateMarkerTx(ctx context.Context, repoID, pullID, actorID int64, branch, resultSHA string) error {
	if !setting.EnterpriseMergeGate.Enabled {
		return nil
	}
	if !db.InTransaction(ctx) {
		return errors.New("merge_gate_evidence_persist_failed")
	}
	save := func(ctx context.Context) error {
		record := new(authz_model.MergeGateEvaluation)
		found, err := db.GetEngine(ctx).Where("operation_id=? AND repo_id=? AND pull_id=? AND actor_id=? AND execution_state=?", MergeGateOperationID(ctx), repoID, pullID, actorID, "started").In("phase", []string{"admission", "auto_admission", "manual_recognition"}).Get(record)
		if err != nil {
			return err
		}
		if !found || record.Validate() != nil {
			return errors.New("merge_gate_marker_unadmitted")
		}
		var snapshot struct {
			Branch    string `json:"branch"`
			ResultSHA string `json:"result_sha"`
		}
		if json.Unmarshal([]byte(record.SnapshotJSON), &snapshot) != nil || snapshot.Branch != branch || snapshot.ResultSHA != resultSHA || setting.Audit.RecordOutput != setting.AuditRecordOutputDatabase {
			return errors.New("merge_gate_marker_unadmitted")
		}
		metadata := mergeGateAuditMetadata(record)
		metadata["result_sha"] = resultSHA
		return audit.RecordEvent(ctx, audit.RecordParams{Action: audit_model.EnterpriseMergeGateMarker, Actor: audit_model.EntityRef{Type: audit_model.ScopeUser, ID: actorID}, Scope: audit_model.EntityRef{Type: audit_model.ScopeRepository, ID: repoID}, Metadata: metadata})
	}
	if !setting.EnterpriseMergeGate.Enforce {
		if err := db.WithSavepoint(ctx, save); err != nil {
			log.Warn("Enterprise merge gate shadow marker evidence unavailable")
		}
		return nil
	}
	return save(ctx)
}

func HasMergeGateMarker(ctx context.Context, record *authz_model.MergeGateEvaluation, resultSHA string) (bool, error) {
	cursor := int64(0)
	for {
		var events []audit_model.Event
		err := db.GetEngine(ctx).Where("action=? AND scope_type=? AND scope_id=? AND actor_id=? AND id>?", audit_model.EnterpriseMergeGateMarker, audit_model.ScopeRepository, record.RepoID, record.ActorID, cursor).Asc("id").Limit(100).Find(&events)
		if err != nil {
			return false, err
		}
		if len(events) == 0 {
			return false, nil
		}
		for _, event := range events {
			cursor = event.ID
			var metadata struct {
				EvaluationID int64  `json:"evaluation_id"`
				OperationID  string `json:"operation_id"`
				PullID       int64  `json:"pull_id"`
				SnapshotHash string `json:"snapshot_hash"`
				ResultSHA    string `json:"result_sha"`
			}
			if json.Unmarshal([]byte(event.Metadata), &metadata) == nil && metadata.EvaluationID == record.ID && metadata.OperationID == record.OperationID && metadata.PullID == record.PullID && metadata.SnapshotHash == record.SnapshotHash && metadata.ResultSHA == resultSHA {
				return true, nil
			}
		}
	}
}
