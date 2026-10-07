// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"gitea.dev/models/db"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/timeutil"
)

var ErrMergeGateRevision = errors.New("merge_gate_revision_conflict")

type ProtectedPathRule struct {
	ID             int64              `xorm:"pk autoincr"`
	ScopeType      ScopeType          `xorm:"VARCHAR(16) NOT NULL INDEX(scope_rule)"`
	ScopeID        int64              `xorm:"NOT NULL INDEX(scope_rule)"`
	OwnerID        int64              `xorm:"NOT NULL"`
	RequiredRoleID int64              `xorm:"NOT NULL INDEX"`
	ConfigJSON     string             `xorm:"TEXT NOT NULL"`
	Enabled        bool               `xorm:"NOT NULL"`
	Deleted        bool               `xorm:"NOT NULL DEFAULT false INDEX(scope_rule)"`
	Revision       int64              `xorm:"NOT NULL"`
	CreatedBy      int64              `xorm:"NOT NULL"`
	UpdatedBy      int64              `xorm:"NOT NULL"`
	CreatedUnix    timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix    timeutil.TimeStamp `xorm:"updated"`
}

func (*ProtectedPathRule) TableName() string { return "enterprise_protected_path_rule" }
func (r *ProtectedPathRule) Scope() Scope    { return Scope{r.ScopeType, r.ScopeID} }

func (r *ProtectedPathRule) Validate() error {
	config, canonical, err := authz.ParseProtectedPathConfig([]byte(r.ConfigJSON))
	if err != nil || !r.Scope().Valid() || canonical != r.ConfigJSON || config.RequiredRoleID != r.RequiredRoleID || r.OwnerID < 0 || r.ScopeType == ScopeSystem && r.OwnerID != 0 || r.ScopeType != ScopeSystem && r.OwnerID <= 0 || r.Revision <= 0 || r.CreatedBy <= 0 || r.UpdatedBy <= 0 || !r.Deleted && r.Enabled != config.Enabled || r.Deleted && r.Enabled {
		return errors.New("invalid_protected_path_rule")
	}
	return nil
}

func SaveProtectedPathRule(ctx context.Context, rule *ProtectedPathRule, expectedRevision int64) error {
	if !db.InTransaction(ctx) {
		return errors.New("policy_mutation_requires_transaction")
	}
	if expectedRevision < 0 {
		return ErrMergeGateRevision
	}
	if rule.ID == 0 {
		if expectedRevision != 0 || rule.Deleted {
			return ErrMergeGateRevision
		}
		rule.Revision = 1
		if err := rule.Validate(); err != nil {
			return err
		}
		return db.Insert(ctx, rule)
	}
	stored := new(ProtectedPathRule)
	exists, err := db.GetEngine(ctx).ID(rule.ID).Get(stored)
	if err != nil {
		return err
	}
	if !exists || stored.Scope() != rule.Scope() || stored.Revision != expectedRevision || stored.Deleted {
		return ErrMergeGateRevision
	}
	rule.CreatedBy, rule.CreatedUnix, rule.Revision = stored.CreatedBy, stored.CreatedUnix, expectedRevision
	if err := rule.Validate(); err != nil {
		return err
	}
	if stored.ConfigJSON == rule.ConfigJSON && stored.OwnerID == rule.OwnerID && stored.Enabled == rule.Enabled && stored.Deleted == rule.Deleted {
		*rule = *stored
		return nil
	}
	rule.Revision++
	count, err := db.GetEngine(ctx).Where("id=? AND revision=? AND deleted=?", rule.ID, expectedRevision, false).Cols("owner_id", "required_role_id", "config_json", "enabled", "deleted", "revision", "updated_by").Update(rule)
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrMergeGateRevision
	}
	return nil
}

type MergeGateEvaluation struct {
	ID                int64              `xorm:"pk autoincr"`
	OperationID       string             `xorm:"VARCHAR(64) NOT NULL UNIQUE(operation_attempt_phase) INDEX"`
	Attempt           int                `xorm:"NOT NULL UNIQUE(operation_attempt_phase)"`
	Phase             string             `xorm:"VARCHAR(32) NOT NULL UNIQUE(operation_attempt_phase)"`
	RepoID            int64              `xorm:"NOT NULL INDEX(repo_pull_time)"`
	PullID            int64              `xorm:"NOT NULL INDEX(repo_pull_time)"`
	IssueID           int64              `xorm:"NOT NULL"`
	ActorID           int64              `xorm:"NOT NULL INDEX"`
	ScheduledMergeID  int64              `xorm:"NOT NULL DEFAULT 0 INDEX"`
	Source            string             `xorm:"VARCHAR(32) NOT NULL"`
	Mode              string             `xorm:"VARCHAR(16) NOT NULL"`
	HeadSHA           string             `xorm:"VARCHAR(64) NOT NULL"`
	BaseSHA           string             `xorm:"VARCHAR(64) NOT NULL"`
	MergedSHA         string             `xorm:"VARCHAR(64) NOT NULL"`
	CandidateDecision string             `xorm:"VARCHAR(16) NOT NULL"`
	AdmissionDecision string             `xorm:"VARCHAR(16) NOT NULL"`
	ReasonsJSON       string             `xorm:"TEXT NOT NULL"`
	SnapshotJSON      string             `xorm:"LONGTEXT NOT NULL"`
	SnapshotVersion   int                `xorm:"NOT NULL"`
	SnapshotHash      string             `xorm:"VARCHAR(64) NOT NULL"`
	BypassRequested   bool               `xorm:"NOT NULL DEFAULT false"`
	BypassUsed        bool               `xorm:"NOT NULL DEFAULT false"`
	BypassReason      string             `xorm:"TEXT NOT NULL"`
	ExecutionState    string             `xorm:"VARCHAR(16) NOT NULL INDEX(reconcile)"`
	CreatedUnix       timeutil.TimeStamp `xorm:"created INDEX(repo_pull_time)"`
	StartedUnix       timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0 INDEX(reconcile)"`
	TerminalUnix      timeutil.TimeStamp `xorm:"NOT NULL DEFAULT 0"`
}

func (*MergeGateEvaluation) TableName() string { return "enterprise_merge_gate_evaluation" }

func (e *MergeGateEvaluation) Validate() error {
	var snapshot struct {
		Version int `json:"snapshot_version"`
	}
	if json.Unmarshal([]byte(e.SnapshotJSON), &snapshot) != nil || snapshot.Version != e.SnapshotVersion {
		return errors.New("invalid_merge_gate_snapshot_version")
	}
	hash := sha256.Sum256([]byte(e.SnapshotJSON))
	if e.OperationID == "" || len(e.OperationID) > 64 || e.Attempt < 1 || e.RepoID <= 0 || e.PullID <= 0 || e.IssueID <= 0 || (e.ActorID <= 0 && !(e.ActorID == 0 && e.Phase == "manual_recognition" && e.Source == "auto_merge" && e.CandidateDecision == "error" && e.ExecutionState == "not_started" && !e.BypassRequested)) || !authz.ValidSource(e.Source) || !slices.Contains([]string{"shadow", "enforce"}, e.Mode) || !slices.Contains([]string{"schedule", "admission", "auto_admission", "manual_recognition"}, e.Phase) || !slices.Contains([]string{"allow", "deny", "error", "bypass"}, e.CandidateDecision) || !slices.Contains([]string{"allow", "deny", "error", "bypass", "not_admitted", "not_enforced"}, e.AdmissionDecision) || !slices.Contains([]string{"not_started", "started", "succeeded", "failed", "cancelled", "unknown"}, e.ExecutionState) || e.SnapshotVersion != authz.MergeGateSnapshotVersion || len(e.SnapshotJSON) > authz.MaxSnapshotBytes || !json.Valid([]byte(e.SnapshotJSON)) || !json.Valid([]byte(e.ReasonsJSON)) || len(e.ReasonsJSON) > authz.MaxSnapshotBytes || e.SnapshotHash != hex.EncodeToString(hash[:]) {
		return errors.New("invalid_merge_gate_evaluation")
	}
	if !utf8.ValidString(e.OperationID) || strings.ContainsFunc(e.OperationID, unicode.IsControl) || e.ScheduledMergeID < 0 || !mergeGateSHA(e.HeadSHA, true) || !mergeGateSHA(e.BaseSHA, true) || !mergeGateSHA(e.MergedSHA, true) || (e.CandidateDecision == "allow" || e.CandidateDecision == "bypass") && (e.HeadSHA == "" || e.BaseSHA == "") {
		return errors.New("invalid_merge_gate_evaluation")
	}
	expectedAdmission := e.CandidateDecision
	if e.Phase == "schedule" {
		expectedAdmission = "not_admitted"
	}
	if e.Mode == "shadow" {
		expectedAdmission = "not_enforced"
	}
	if e.AdmissionDecision != expectedAdmission || e.BypassUsed != (e.AdmissionDecision == "bypass") || e.BypassUsed && !e.BypassRequested || (e.Phase == "schedule" || e.Phase == "auto_admission") && e.CandidateDecision == "bypass" || !utf8.ValidString(e.BypassReason) || len(e.BypassReason) > 1024 || strings.ContainsFunc(e.BypassReason, unicode.IsControl) || e.BypassUsed && strings.TrimSpace(e.BypassReason) == "" {
		return errors.New("invalid_merge_gate_evaluation")
	}
	return nil
}

func mergeGateSHA(value string, emptyAllowed bool) bool {
	if value == "" {
		return emptyAllowed
	}
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	return !strings.ContainsFunc(value, func(c rune) bool { return c < '0' || c > '9' && c < 'a' || c > 'f' })
}

func mergeGateImmutable(e MergeGateEvaluation) string {
	e.ID, e.CreatedUnix, e.StartedUnix, e.TerminalUnix = 0, 0, 0, 0
	e.ExecutionState, e.MergedSHA = "", ""
	raw, _ := json.Marshal(e)
	return string(raw)
}

func InsertMergeGateEvaluation(ctx context.Context, record *MergeGateEvaluation) (bool, error) {
	if err := record.Validate(); err != nil {
		return false, err
	}
	if record.ExecutionState != "not_started" || record.StartedUnix != 0 || record.TerminalUnix != 0 || record.MergedSHA != "" {
		return false, errors.New("invalid_initial_execution_state")
	}
	if record.CreatedUnix == 0 {
		record.CreatedUnix = timeutil.TimeStampNow()
	}
	columns := []string{"operation_id", "attempt", "phase", "repo_id", "pull_id", "issue_id", "actor_id", "scheduled_merge_id", "source", "mode", "head_sha", "base_sha", "merged_sha", "candidate_decision", "admission_decision", "reasons_json", "snapshot_json", "snapshot_version", "snapshot_hash", "bypass_requested", "bypass_used", "bypass_reason", "execution_state", "created_unix", "started_unix", "terminal_unix"}
	values := []any{record.OperationID, record.Attempt, record.Phase, record.RepoID, record.PullID, record.IssueID, record.ActorID, record.ScheduledMergeID, record.Source, record.Mode, record.HeadSHA, record.BaseSHA, record.MergedSHA, record.CandidateDecision, record.AdmissionDecision, record.ReasonsJSON, record.SnapshotJSON, record.SnapshotVersion, record.SnapshotHash, record.BypassRequested, record.BypassUsed, record.BypassReason, record.ExecutionState, record.CreatedUnix, record.StartedUnix, record.TerminalUnix}
	query := "INSERT INTO `enterprise_merge_gate_evaluation` (`" + strings.Join(columns, "`, `") + "`) VALUES (" + strings.TrimSuffix(strings.Repeat("?,", len(columns)), ",") + ") ON CONFLICT (`operation_id`, `attempt`, `phase`) DO NOTHING"
	result, err := db.Exec(ctx, append([]any{query}, values...)...)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	stored := new(MergeGateEvaluation)
	exists, err := db.GetEngine(ctx).Where("operation_id=? AND attempt=? AND phase=?", record.OperationID, record.Attempt, record.Phase).Get(stored)
	if err != nil {
		return false, err
	}
	if !exists || mergeGateImmutable(*stored) != mergeGateImmutable(*record) {
		return false, errors.New("merge_gate_operation_conflict")
	}
	*record = *stored
	return count == 1, nil
}

func TransitionMergeGateExecution(ctx context.Context, id int64, expected, next, mergedSHA string) error {
	valid := expected == "not_started" && (next == "started" || next == "cancelled") || expected == "started" && slices.Contains([]string{"succeeded", "failed", "unknown"}, next) || expected == "unknown" && slices.Contains([]string{"succeeded", "failed"}, next)
	if !valid || id <= 0 || next == "succeeded" && !mergeGateSHA(mergedSHA, false) || next != "succeeded" && mergedSHA != "" {
		return errors.New("invalid_execution_transition")
	}
	updates := map[string]any{"execution_state": next}
	if next == "started" {
		updates["started_unix"] = timeutil.TimeStampNow()
	} else if next != "unknown" {
		updates["terminal_unix"] = timeutil.TimeStampNow()
	}
	if next == "succeeded" {
		updates["merged_sha"] = mergedSHA
	}
	session := db.GetEngine(ctx).Table(new(MergeGateEvaluation)).Where("id=? AND execution_state=?", id, expected)
	if next == "started" {
		session = session.In("admission_decision", []string{"allow", "bypass", "not_enforced"})
	}
	count, err := session.Update(updates)
	if err != nil {
		return err
	}
	if count != 1 {
		return ErrMergeGateRevision
	}
	return nil
}

func init() {
	db.RegisterModel(new(ProtectedPathRule))
	db.RegisterModel(new(MergeGateEvaluation))
}
