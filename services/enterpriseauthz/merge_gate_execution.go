// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"
	"strconv"
	"strings"

	asymkey_model "gitea.dev/models/asymkey"
	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/perm"
	repo_model "gitea.dev/models/repo"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	"gitea.dev/services/audit"
)

func MergeGateOperationID(ctx context.Context) string {
	if state, ok := ctx.Value(operationKey{}).(*operationState); ok && state != nil {
		return state.id
	}
	return ""
}

func EvaluateMergeGateAction(ctx context.Context, input EvaluateInput) (Decision, error) {
	if !db.InTransaction(ctx) || input.Action != authz.MergePullRequest && input.Action != authz.BypassMergeGate {
		return Decision{}, errors.New("invalid_merge_gate_transaction")
	}
	return evaluate(ctx, input, true)
}

func RefreshMergeGateCredential(ctx context.Context, actorID int64, repo *repo_model.Repository, original CredentialCeiling) (CredentialCeiling, error) {
	result := original
	if original.NativeOnly || actorID <= 0 || repo == nil || original.PublicOnly && repo.IsPrivate || original.organizationID > 0 && original.organizationID != repo.OwnerID {
		result.Read, result.Write = false, false
		return result, nil
	}
	if original.Reference == "" {
		return result, nil
	}
	reference := safeCredentialReference(original.Reference)
	if reference == "" {
		result.Read, result.Write = false, false
		return result, nil
	}
	kind, rawID, _ := strings.Cut(reference, ":")
	id, _ := strconv.ParseInt(rawID, 10, 64)
	var scope auth_model.AccessTokenScope
	var err error
	switch kind {
	case "ssh-key":
		key, readErr := asymkey_model.GetPublicKeyByID(ctx, id)
		if asymkey_model.IsErrKeyNotExist(readErr) {
			result.Read, result.Write = false, false
			return result, nil
		}
		if readErr != nil {
			return CredentialCeiling{}, readErr
		}
		if key.OwnerID != actorID || key.Type != asymkey_model.KeyTypeUser {
			result.Read, result.Write = false, false
			return result, nil
		}
		result.Write = original.Write && original.Read && key.Mode >= perm.AccessModeWrite
		return result, nil
	case "access-token":
		token, readErr := auth_model.GetAccessTokenByID(ctx, id, actorID)
		err = readErr
		if err == nil {
			scope = token.Scope
		}
	case "oauth2-grant":
		grant, readErr := auth_model.GetOAuth2GrantByID(ctx, id)
		err = readErr
		if err == nil && (grant == nil || grant.UserID != actorID) {
			result.Read, result.Write = false, false
			return result, nil
		}
		if err == nil {
			scope = auth_model.AccessTokenScope(grant.Scope)
		}
	default:
		result.Read, result.Write = false, false
		return result, nil
	}
	if err != nil {
		if errors.Is(err, util.ErrNotExist) {
			result.Read, result.Write = false, false
			return result, nil
		}
		return CredentialCeiling{}, err
	}
	read, err := scope.HasScope(auth_model.AccessTokenScopeReadRepository)
	if err != nil {
		return CredentialCeiling{}, err
	}
	write, err := scope.HasScope(auth_model.AccessTokenScopeWriteRepository)
	if err != nil {
		return CredentialCeiling{}, err
	}
	publicOnly, err := scope.PublicOnly()
	if err != nil {
		return CredentialCeiling{}, err
	}
	result.PublicOnly = original.PublicOnly || publicOnly
	result.Read = original.Read && read && !(result.PublicOnly && repo.IsPrivate)
	result.Write = original.Write && write && result.Read
	return result, nil
}

func PersistMergeGateEvaluationTx(ctx context.Context, record *authz_model.MergeGateEvaluation, start bool) error {
	if !db.InTransaction(ctx) || setting.Audit.RecordOutput != setting.AuditRecordOutputDatabase || record == nil {
		return errors.New("merge_gate_evidence_persist_failed")
	}
	inserted, err := authz_model.InsertMergeGateEvaluation(ctx, record)
	if err != nil {
		return err
	}
	if !inserted {
		if !start && record.ExecutionState == "not_started" {
			return nil
		}
		return errors.New("merge_gate_operation_already_evaluated")
	}
	if start {
		if err := authz_model.TransitionMergeGateExecution(ctx, record.ID, "not_started", "started", ""); err != nil {
			return err
		}
		record.ExecutionState = "started"
	}
	return audit.RecordEvent(ctx, audit.RecordParams{Action: audit_model.EnterpriseMergeGateEvaluation, Actor: audit_model.EntityRef{Type: audit_model.ScopeUser, ID: record.ActorID}, Scope: audit_model.EntityRef{Type: audit_model.ScopeRepository, ID: record.RepoID}, Metadata: mergeGateAuditMetadata(record)})
}

func FinishMergeGateEvaluation(ctx context.Context, record *authz_model.MergeGateEvaluation, state, mergedSHA string) error {
	if record == nil {
		return nil
	}
	return db.WithIndependentTx(ctx, func(tx context.Context) error {
		if setting.Audit.RecordOutput != setting.AuditRecordOutputDatabase {
			return errors.New("merge_gate_evidence_persist_failed")
		}
		if err := authz_model.TransitionMergeGateExecution(tx, record.ID, record.ExecutionState, state, mergedSHA); err != nil {
			return err
		}
		result := *record
		result.ExecutionState, result.MergedSHA = state, mergedSHA
		return audit.RecordEvent(tx, audit.RecordParams{Action: audit_model.EnterpriseMergeGateExecution, Actor: audit_model.EntityRef{Type: audit_model.ScopeUser, ID: record.ActorID}, Scope: audit_model.EntityRef{Type: audit_model.ScopeRepository, ID: record.RepoID}, Metadata: mergeGateAuditMetadata(&result)})
	})
}

func mergeGateAuditMetadata(record *authz_model.MergeGateEvaluation) map[string]any {
	return map[string]any{"evaluation_id": record.ID, "operation_id": record.OperationID, "attempt": record.Attempt, "phase": record.Phase, "pull_id": record.PullID, "source": record.Source, "mode": record.Mode, "candidate_decision": record.CandidateDecision, "admission_decision": record.AdmissionDecision, "execution_state": record.ExecutionState, "snapshot_version": record.SnapshotVersion, "snapshot_hash": record.SnapshotHash, "head_sha": record.HeadSHA, "base_sha": record.BaseSHA, "merged_sha": record.MergedSHA, "bypass_requested": record.BypassRequested, "bypass_used": record.BypassUsed}
}
