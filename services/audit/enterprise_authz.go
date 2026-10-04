// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"context"
	"errors"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/modules/json"
)

func UpdateEnterpriseAuthzNativeResult(ctx context.Context, record *authz_model.DecisionRecord, mismatch *bool) error {
	if !db.InTransaction(ctx) {
		return errors.New("evidence_persist_failed")
	}
	events := make([]audit_model.Event, 0, 2)
	err := db.GetEngine(ctx).Where("action = ? AND actor_id = ? AND scope_type = ? AND scope_id = ?", audit_model.EnterpriseAuthzDecision, record.ActorID, audit_model.ScopeRepository, record.RepoID).And("metadata LIKE ?", "%"+record.ObservationID+"%").Limit(2).Find(&events)
	if err != nil || len(events) != 1 {
		return errors.New("evidence_persist_failed")
	}
	event := events[0]
	var identifiers struct {
		DecisionID    int64  `json:"decision_id"`
		ObservationID string `json:"observation_id"`
		OperationID   string `json:"operation_id"`
		NativeOutcome string `json:"native_outcome"`
	}
	if json.Unmarshal([]byte(event.Metadata), &identifiers) != nil || identifiers.DecisionID != record.ID || identifiers.ObservationID != record.ObservationID || identifiers.OperationID != record.OperationID || identifiers.NativeOutcome != "unknown" {
		return errors.New("evidence_persist_failed")
	}
	metadata := map[string]any{
		"decision_id": record.ID, "observation_id": record.ObservationID, "operation_id": record.OperationID,
		"repo_id": record.RepoID, "owner_id": record.OwnerID, "action": record.Action, "request_source": record.RequestSource,
		"candidate_decision": record.CandidateDecision, "reason": record.Reason, "native_outcome": record.NativeOutcome, "native_stage": record.NativeStage,
		"decision_mode": record.DecisionMode, "authorization_decision": record.AuthorizationDecision,
		"authorization_reason": record.AuthorizationReason, "execution_started": record.ExecutionStarted,
	}
	if mismatch != nil {
		metadata["mismatch"] = *mismatch
	}
	event.Metadata = audit_model.EncodeMetadata(metadata)
	event.Message = renderMessage(event.Action, event.Actor(), event.Scope(), metadata)
	count, err := db.GetEngine(ctx).ID(event.ID).Cols("metadata", "message").Update(&event)
	if err != nil || count != 1 {
		return errors.New("evidence_persist_failed")
	}
	return nil
}
