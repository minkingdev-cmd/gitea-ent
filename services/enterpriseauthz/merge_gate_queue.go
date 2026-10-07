// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	pull_model "gitea.dev/models/pull"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/modules/json"
	"gitea.dev/modules/log"
	"gitea.dev/modules/setting"
	"gitea.dev/services/audit"
)

var ErrMergeGateQueueUnattributed = errors.New("merge_gate_queue_unattributed")

type MergeGateQueueAttribution struct {
	Kind           string            `json:"kind"`
	RepoID         int64             `json:"repo_id"`
	ActorID        int64             `json:"actor_id"`
	Credential     CredentialCeiling `json:"credential"`
	Generation     string            `json:"generation,omitempty"`
	OrganizationID int64             `json:"organization_id,omitempty"`
}

type mergeGateQueueKey struct{}

func WithMergeGateAutoQueue(ctx context.Context, queueID int64) context.Context {
	return context.WithValue(ctx, mergeGateQueueKey{}, queueID)
}

func MergeGateAutoQueueID(ctx context.Context) int64 {
	id, _ := ctx.Value(mergeGateQueueKey{}).(int64)
	return id
}

func NewMergeGateQueueAttribution(ctx context.Context, actorID int64, repo *repo_model.Repository, source string, ceiling CredentialCeiling) (*MergeGateQueueAttribution, error) {
	if actorID <= 0 || repo == nil || ceiling.NativeOnly || !ceiling.Read || !ceiling.Write || source != "web" && source != "api" {
		return nil, ErrMergeGateQueueUnattributed
	}
	current, err := RefreshMergeGateCredential(ctx, actorID, repo, ceiling)
	if err != nil {
		return nil, err
	}
	if !current.Read || !current.Write {
		return nil, ErrMergeGateQueueUnattributed
	}
	kind := "session_delegation"
	generation := ""
	if current.Reference != "" {
		kind, _, _ = strings.Cut(current.Reference, ":")
		if kind != "access-token" && kind != "oauth2-grant" {
			return nil, ErrMergeGateQueueUnattributed
		}
		generation, err = mergeGateCredentialGeneration(ctx, actorID, current.Reference)
		if err != nil {
			return nil, err
		}
	}
	return &MergeGateQueueAttribution{Kind: kind, ActorID: actorID, RepoID: repo.ID, Credential: current, Generation: generation, OrganizationID: ceiling.organizationID}, nil
}

func mergeGateCredentialGeneration(ctx context.Context, actorID int64, reference string) (string, error) {
	kind, raw, _ := strings.Cut(reference, ":")
	if kind != "access-token" {
		return "", nil
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return "", err
	}
	token, err := auth_model.GetAccessTokenByID(ctx, id, actorID)
	if err != nil {
		return "", err
	}
	if setting.InternalToken == "" {
		return "", errors.New("merge_gate_generation_unavailable")
	}
	mac := hmac.New(sha256.New, []byte(setting.InternalToken))
	_, _ = mac.Write([]byte("gitea.merge-gate.credential-generation\x00" + token.TokenHash))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func MergeGateAutoCredential(ctx context.Context, queueID, pullID, actorID int64, repo *repo_model.Repository) (CredentialCeiling, error) {
	denied := CredentialCeiling{}
	if queueID <= 0 || repo == nil {
		return denied, nil
	}
	queue := new(pull_model.AutoMerge)
	found, err := db.GetEngine(ctx).ID(queueID).Where("pull_id=? AND doer_id=?", pullID, actorID).Get(queue)
	if err != nil || !found {
		return denied, err
	}
	record := new(authz_model.MergeGateEvaluation)
	found, err = db.GetEngine(ctx).Where("scheduled_merge_id=? AND pull_id=? AND repo_id=? AND actor_id=? AND phase=?", queue.ID, pullID, repo.ID, actorID, "schedule").Desc("id").Get(record)
	if err != nil || !found {
		return denied, err
	}
	var snapshot struct {
		Attribution *MergeGateQueueAttribution `json:"credential_attribution"`
	}
	if record.Validate() != nil || json.Unmarshal([]byte(record.SnapshotJSON), &snapshot) != nil || snapshot.Attribution == nil {
		return denied, nil
	}
	attribution := snapshot.Attribution
	if attribution.ActorID != actorID || attribution.RepoID != repo.ID || attribution.Credential.NativeOnly {
		return denied, nil
	}
	switch attribution.Kind {
	case "session_delegation":
		if attribution.Credential.Reference != "" || record.Source != "web" && record.Source != "api" {
			return denied, nil
		}
	case "access-token", "oauth2-grant":
		if !strings.HasPrefix(attribution.Credential.Reference, attribution.Kind+":") {
			return denied, nil
		}
		generation, err := mergeGateCredentialGeneration(ctx, actorID, attribution.Credential.Reference)
		if err != nil {
			current, refreshErr := RefreshMergeGateCredential(ctx, actorID, repo, attribution.Credential)
			if refreshErr == nil && !current.Read {
				return denied, nil
			}
			return denied, err
		}
		if !hmac.Equal([]byte(generation), []byte(attribution.Generation)) {
			return denied, nil
		}
	default:
		return denied, nil
	}
	original := attribution.Credential
	original.organizationID = attribution.OrganizationID
	return RefreshMergeGateCredential(ctx, actorID, repo, original)
}

func CancelMergeGateSchedulesTx(ctx context.Context, pullID int64) error {
	if !setting.EnterpriseMergeGate.Enabled {
		return nil
	}
	if !db.InTransaction(ctx) {
		return errors.New("merge_gate_evidence_persist_failed")
	}
	if !setting.EnterpriseMergeGate.Enforce {
		if err := db.WithSavepoint(ctx, func(tx context.Context) error { return cancelMergeGateSchedulesTx(tx, pullID) }); err != nil {
			log.Warn("Enterprise merge gate shadow cancellation evidence unavailable")
		}
		return nil
	}
	return cancelMergeGateSchedulesTx(ctx, pullID)
}

func cancelMergeGateSchedulesTx(ctx context.Context, pullID int64) error {
	if !setting.EnterpriseMergeGate.Enabled {
		return nil
	}
	if !db.InTransaction(ctx) {
		return errors.New("merge_gate_evidence_persist_failed")
	}
	var records []*authz_model.MergeGateEvaluation
	if err := db.GetEngine(ctx).Where("pull_id=? AND phase=? AND execution_state=?", pullID, "schedule", "not_started").Find(&records); err != nil {
		return err
	}
	for _, record := range records {
		if err := authz_model.TransitionMergeGateExecution(ctx, record.ID, "not_started", "cancelled", ""); err != nil {
			return err
		}
		record.ExecutionState = "cancelled"
		if err := audit.RecordEvent(ctx, audit.RecordParams{Action: audit_model.EnterpriseMergeGateExecution, Actor: audit_model.EntityRef{Type: audit_model.ScopeUser, ID: record.ActorID}, Scope: audit_model.EntityRef{Type: audit_model.ScopeRepository, ID: record.RepoID}, Metadata: mergeGateAuditMetadata(record)}); err != nil {
			return err
		}
	}
	return nil
}

func NewMergeGateReceiveAttribution(ctx context.Context, actorID int64, repo *repo_model.Repository, source string, original CredentialCeiling) (*MergeGateQueueAttribution, error) {
	if actorID <= 0 || repo == nil || source != "git_http" && source != "ssh" || original.NativeOnly || !original.Read || !original.Write {
		return nil, errors.New("merge_gate_receive_unattributed")
	}
	current, err := RefreshMergeGateCredential(ctx, actorID, repo, original)
	if err != nil {
		return nil, err
	}
	if !current.Read || !current.Write {
		return nil, errors.New("merge_gate_receive_unattributed")
	}
	generation, err := mergeGateCredentialGeneration(ctx, actorID, current.Reference)
	if err != nil {
		return nil, err
	}
	return &MergeGateQueueAttribution{Kind: "receive_delegation", ActorID: actorID, RepoID: repo.ID, Credential: current, Generation: generation, OrganizationID: original.organizationID}, nil
}

func MergeGateReceiveCredential(ctx context.Context, attribution *MergeGateQueueAttribution, actorID int64, repo *repo_model.Repository) (CredentialCeiling, error) {
	denied := CredentialCeiling{}
	if attribution == nil || repo == nil || attribution.Kind != "receive_delegation" || attribution.ActorID != actorID || attribution.RepoID != repo.ID {
		return denied, nil
	}
	original := attribution.Credential
	original.organizationID = attribution.OrganizationID
	current, err := RefreshMergeGateCredential(ctx, actorID, repo, original)
	if err != nil || !current.Read {
		return denied, err
	}
	generation, err := mergeGateCredentialGeneration(ctx, actorID, current.Reference)
	if err != nil {
		return denied, err
	}
	if !hmac.Equal([]byte(generation), []byte(attribution.Generation)) {
		return denied, nil
	}
	current.organizationID = attribution.OrganizationID
	return current, nil
}
