// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"

	"gitea.dev/models/db"
)

func InsertDecisionIfAbsent(ctx context.Context, record *DecisionRecord) (bool, error) {
	result, err := db.GetEngine(ctx).Exec("INSERT INTO `enterprise_authz_decision` (`observation_id`, `operation_id`, `actor_id`, `repo_id`, `owner_id`, `action`, `request_source`, `candidate_decision`, `reason`, `missing_actions`, `native_outcome`, `native_stage`, `snapshot_json`, `created_unix`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT (`observation_id`) DO NOTHING",
		record.ObservationID, record.OperationID, record.ActorID, record.RepoID, record.OwnerID, record.Action, record.RequestSource, record.CandidateDecision, record.Reason, record.MissingActions, record.NativeOutcome, record.NativeStage, record.SnapshotJSON, record.CreatedUnix)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil || count == 0 {
		return false, err
	}
	found := new(DecisionRecord)
	exists, err := db.GetEngine(ctx).Where("observation_id = ?", record.ObservationID).Get(found)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, errors.New("evidence_persist_failed")
	}
	*record = *found
	return true, nil
}
