// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	access_model "gitea.dev/models/perm/access"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/log"
	"gitea.dev/modules/metrics"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/timeutil"
	"gitea.dev/services/audit"
)

const observationBudget = 200 * time.Millisecond

type (
	NativeOutcome string
	NativeStage   string
)

const (
	NativeSuccess      NativeOutcome = "success"
	NativeDenied       NativeOutcome = "denied"
	NativeFailed       NativeOutcome = "failed"
	NativeUnknown      NativeOutcome = "unknown"
	StageOperation     NativeStage   = "operation"
	StageAuthorization NativeStage   = "authorization"
	StageTransport     NativeStage   = "transport"
	StagePreReceive    NativeStage   = "pre_receive"
	StageMigration     NativeStage   = "migration"
)

type (
	operationKey   struct{}
	operationState struct {
		id                     string
		hook                   *HookOperation
		mutex                  sync.Mutex
		observations           map[[32]byte]*Observation
		migrationFailure       sync.Once
		migrationTargetCreated atomic.Bool
	}
)

type Observation struct {
	record              authz_model.DecisionRecord
	credential          string
	ceiling             CredentialCeiling
	condition           authz.ConditionContext
	targetOwnerID       int64
	hookExisting        bool
	transferTargetOwner atomic.Int64
	remaining           time.Duration
	ready               chan struct{}
	evaluationFailed    bool
	once                sync.Once
}

var operationCreation sync.Mutex

func WithOperation(ctx context.Context) context.Context {
	if !setting.EnterpriseAuthz.Enabled || ctx.Value(operationKey{}) != nil {
		return ctx
	}
	if store := reqctx.FromContext(ctx); store != nil {
		operationCreation.Lock()
		defer operationCreation.Unlock()
		if ctx.Value(operationKey{}) != nil {
			return ctx
		}
		state := &operationState{id: rand.Text(), observations: make(map[[32]byte]*Observation)}
		store.SetContextValue(operationKey{}, state)
		return ctx
	}
	state := &operationState{id: rand.Text(), observations: make(map[[32]byte]*Observation)}
	return context.WithValue(ctx, operationKey{}, state)
}

func BeginObservation(ctx context.Context, input EvaluateInput) (context.Context, *Observation) {
	return beginObservation(ctx, input, observationBudget)
}

func BeginResolvedObservation(ctx context.Context, input EvaluateInput, resolve func(context.Context) (*access_model.Permission, error)) (context.Context, *Observation) {
	return BeginPreparedObservation(ctx, input, func(ctx context.Context, input EvaluateInput) (EvaluateInput, error) {
		permission, err := resolve(ctx)
		input.Permission = permission
		return input, err
	})
}

func BeginPreparedObservation(ctx context.Context, input EvaluateInput, prepare func(context.Context, EvaluateInput) (EvaluateInput, error)) (context.Context, *Observation) {
	if !setting.EnterpriseAuthz.Enabled {
		return ctx, nil
	}
	if input.Repo == nil || input.Repo.ID <= 0 {
		return ctx, nil
	}
	ctx = WithOperation(ctx)
	state, ok := ctx.Value(operationKey{}).(*operationState)
	if !ok || state == nil {
		reportObservationFailure("", input.Repo.ID, input.Action, "invalid_observation_context")
		return ctx, nil
	}
	if db.InTransaction(ctx) {
		reportObservationFailure(state.id, input.Repo.ID, input.Action, "business_transaction_active")
		return ctx, nil
	}
	started := time.Now()
	bounded, cancel := context.WithTimeout(ctx, observationBudget)
	defer cancel()
	input, err := prepare(bounded, input)
	if err != nil {
		reportObservationFailure(state.id, input.Repo.ID, input.Action, safeObservationReason(bounded, err, "observation_failed"))
		return ctx, nil
	}
	_, observation := beginObservation(bounded, input, max(0, observationBudget-time.Since(started)))
	return ctx, observation
}

func beginObservation(ctx context.Context, input EvaluateInput, budget time.Duration) (context.Context, *Observation) {
	if !setting.EnterpriseAuthz.Enabled {
		return ctx, nil
	}
	if input.Repo == nil || input.Repo.ID <= 0 || input.Permission == nil || !input.Permission.HasAnyUnitAccessOrPublicAccess() {
		return ctx, nil
	}
	started := time.Now()
	ctx = WithOperation(ctx)
	state, ok := ctx.Value(operationKey{}).(*operationState)
	if !ok || state == nil {
		reportObservationFailure("", input.Repo.ID, input.Action, "invalid_observation_context")
		return ctx, nil
	}
	if ctx.Err() != nil {
		reportObservationFailure(state.id, input.Repo.ID, input.Action, safeObservationReason(ctx, ctx.Err(), "observation_failed"))
		return ctx, nil
	}
	if db.InTransaction(ctx) {
		reportObservationFailure(state.id, input.Repo.ID, input.Action, "business_transaction_active")
		return ctx, nil
	}
	if _, ok := authz.LookupAction(input.Action); !ok || !authz.ValidSource(input.ConditionContext.Source) || input.ConditionContext.Source == "diagnostic" {
		reportObservationFailure(state.id, input.Repo.ID, input.Action, "invalid_observation_context")
		return ctx, nil
	}
	if state.hook != nil && !validHookInput(state.hook, input) {
		reportObservationFailure(state.id, input.Repo.ID, input.Action, "invalid_observation_context")
		return ctx, nil
	}
	data, _ := json.Marshal(struct {
		ActorID, RepoID int64
		Action          authz.Action
		Context         authz.ConditionContext
		Target          string
	}{actorID(input), input.Repo.ID, input.Action, input.ConditionContext, input.observationTarget})
	key := sha256.Sum256(data)
	evaluationCtx, cancel := context.WithTimeout(ctx, max(0, budget-time.Since(started)))
	defer cancel()
	state.mutex.Lock()
	if observation, exists := state.observations[key]; exists {
		state.mutex.Unlock()
		select {
		case <-observation.ready:
			return ctx, observation
		case <-evaluationCtx.Done():
			reportObservationFailure(state.id, input.Repo.ID, input.Action, safeObservationReason(evaluationCtx, evaluationCtx.Err(), "observation_failed"))
			return ctx, nil
		}
	}
	observation := &Observation{
		record: authz_model.DecisionRecord{
			ObservationID: rand.Text(), OperationID: state.id, ActorID: actorID(input),
			RepoID: input.Repo.ID, OwnerID: input.Repo.OwnerID, Action: input.Action,
			RequestSource: input.ConditionContext.Source,
		},
		credential: safeCredentialReference(input.Credential.Reference), ceiling: input.Credential, condition: input.ConditionContext, targetOwnerID: input.TargetOwnerID, ready: make(chan struct{}),
	}
	if state.hook != nil {
		observation.record.ObservationID = hookObservationID(state.hook, input.Action, observationTarget(input))
	}
	observation.ceiling.Actions = slices.Clone(input.Credential.Actions)
	state.observations[key] = observation
	state.mutex.Unlock()
	defer close(observation.ready)
	if state.hook != nil {
		existing := new(authz_model.DecisionRecord)
		found, err := db.GetEngine(evaluationCtx).Where("observation_id = ?", observation.record.ObservationID).Get(existing)
		if err != nil {
			observation.evaluationFailed = true
			reportObservationFailure(state.id, input.Repo.ID, input.Action, safeObservationReason(evaluationCtx, err, "evidence_persist_failed"))
			return ctx, nil
		}
		if found {
			observation.record = *existing
			observation.hookExisting = true
			observation.remaining = budget - time.Since(started)
			return ctx, observation
		}
	}
	decision, err := Evaluate(evaluationCtx, input)
	observation.record.OwnerID = decision.ownerID
	observation.evaluationFailed = err != nil
	if err != nil {
		reportObservationFailure(state.id, input.Repo.ID, input.Action, safeObservationReason(evaluationCtx, err, decision.Reason))
	}
	if decision.Snapshot == "" {
		data, _ := json.Marshal(baseSnapshot(input, decision.NativeActions))
		decision.Snapshot = string(data)
	}
	missing, _ := json.Marshal(decision.MissingActions)
	observation.record.CandidateDecision, observation.record.Reason = decision.CandidateDecision, decision.Reason
	observation.record.MissingActions, observation.record.SnapshotJSON = string(missing), decision.Snapshot
	observation.remaining = budget - time.Since(started)
	return ctx, observation
}

func ObserveGuardDenial(ctx context.Context, input EvaluateInput, target func(context.Context) (bool, error)) {
	observeResolvedRejection(ctx, input, target, NativeDenied, StageAuthorization)
}

func ObserveValidationFailure(ctx context.Context, input EvaluateInput, target func(context.Context) (bool, error)) {
	observeResolvedRejection(ctx, input, target, NativeFailed, StageOperation)
}

func observeResolvedRejection(ctx context.Context, input EvaluateInput, target func(context.Context) (bool, error), outcome NativeOutcome, stage NativeStage) {
	if !setting.EnterpriseAuthz.Enabled || input.Repo == nil || input.Permission == nil || !input.Credential.Read || !input.Credential.Write || !input.Permission.HasAnyUnitAccessOrPublicAccess() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, observationBudget)
	defer cancel()
	if target != nil {
		valid, err := target(ctx)
		if err != nil {
			reportObservationFailure("", input.Repo.ID, input.Action, safeObservationReason(ctx, err, "target_lookup_failed"))
			return
		}
		if !valid {
			return
		}
	}
	ctx, observation := BeginObservation(ctx, input)
	observation.Finish(ctx, outcome, stage)
}

func actorID(input EvaluateInput) int64 {
	if input.Actor != nil {
		return input.Actor.ID
	}
	return 0
}

func (o *Observation) FinishTransfer(ctx context.Context, outcome NativeOutcome, targetOwnerID int64) {
	if o != nil && o.record.Action == authz.Transfer && targetOwnerID > 0 {
		o.transferTargetOwner.CompareAndSwap(0, targetOwnerID)
	}
	o.Finish(ctx, outcome, StageOperation)
}

func (o *Observation) Finish(ctx context.Context, outcome NativeOutcome, stage NativeStage) {
	if o == nil || !setting.EnterpriseAuthz.Enabled {
		return
	}
	o.once.Do(func() {
		if executionReplacesObservation(ctx, o) {
			return
		}
		if o.remaining <= 0 {
			if !o.evaluationFailed {
				reportObservationFailure(o.record.OperationID, o.record.RepoID, o.record.Action, "observation_timeout")
			}
			return
		}
		evidenceCtx, cancel := context.WithTimeout(ctx, o.remaining)
		defer cancel()
		if !slices.Contains([]NativeOutcome{NativeSuccess, NativeDenied, NativeFailed, NativeUnknown}, outcome) {
			outcome = NativeUnknown
		}
		if !slices.Contains([]NativeStage{StageOperation, StageAuthorization, StageTransport, StagePreReceive, StageMigration}, stage) {
			stage = StageOperation
			outcome = NativeUnknown
		}
		// 通过认证不代表 Git 传输完成。
		if stage == StageAuthorization && outcome == NativeSuccess {
			outcome = NativeUnknown
		}
		if targetOwnerID := o.transferTargetOwner.Load(); targetOwnerID > 0 {
			var snapshot roleSnapshot
			if err := json.Unmarshal([]byte(o.record.SnapshotJSON), &snapshot); err != nil {
				reportObservationFailure(o.record.OperationID, o.record.RepoID, o.record.Action, "invalid_observation_context")
				return
			}
			snapshot.TargetOwnerID = targetOwnerID
			data, err := json.Marshal(snapshot)
			if err != nil || len(data) > authz.MaxSnapshotBytes {
				reportObservationFailure(o.record.OperationID, o.record.RepoID, o.record.Action, "snapshot_limit_exceeded")
				return
			}
			o.record.SnapshotJSON = string(data)
		}
		o.record.NativeOutcome, o.record.NativeStage = string(outcome), string(stage)
		o.record.CreatedUnix = timeutil.TimeStampNow()
		var err error
		if o.hookExisting {
			if outcome == NativeUnknown {
				return
			}
			if !validImportedObservationStage(o.record.Action, stage) {
				reportObservationFailure(o.record.OperationID, o.record.RepoID, o.record.Action, "invalid_observation_context")
				return
			}
			err = db.WithIndependentTx(evidenceCtx, func(tx context.Context) error { return finalizeHookRecord(tx, &o.record) })
		} else {
			err = persistObservation(evidenceCtx, &o.record, o.credential)
		}
		if err != nil {
			reportObservationFailure(o.record.OperationID, o.record.RepoID, o.record.Action, safeObservationReason(evidenceCtx, err, "evidence_persist_failed"))
		}
	})
}

func persistObservation(ctx context.Context, record *authz_model.DecisionRecord, credential string) error {
	if setting.Audit.RecordOutput != setting.AuditRecordOutputDatabase {
		return errors.New("database_audit_required")
	}
	return db.WithIndependentTx(ctx, func(tx context.Context) error {
		return persistObservationTx(tx, record, credential)
	})
}

func persistObservationTx(tx context.Context, record *authz_model.DecisionRecord, credential string) error {
	inserted, err := authz_model.InsertDecisionIfAbsent(tx, record)
	if err != nil {
		return errors.New("evidence_persist_failed")
	}
	if !inserted {
		return nil
	}
	auditCtx, persisted := audit.WithRequiredPersistence(tx)
	metadata := map[string]any{
		"decision_id": record.ID, "observation_id": record.ObservationID, "operation_id": record.OperationID,
		"repo_id": record.RepoID, "owner_id": record.OwnerID, "action": record.Action,
		"request_source": record.RequestSource, "candidate_decision": record.CandidateDecision,
		"reason": record.Reason, "native_outcome": record.NativeOutcome, "native_stage": record.NativeStage,
		"decision_mode": record.DecisionMode, "authorization_decision": record.AuthorizationDecision,
		"authorization_reason": record.AuthorizationReason, "execution_started": record.ExecutionStarted,
	}
	if mismatch, known := NativeMismatch(record.CandidateDecision, NativeOutcome(record.NativeOutcome)); known && record.DecisionMode == "shadow" {
		metadata["mismatch"] = mismatch
	}
	if err := audit.RecordEvent(auditCtx, audit.RecordParams{
		Action:          audit_model.EnterpriseAuthzDecision,
		Actor:           audit_model.EntityRef{Type: audit_model.ScopeUser, ID: record.ActorID},
		ActorCredential: credential,
		Impersonator:    safeAuditImpersonator(auditCtx, record.ActorID),
		Scope:           audit_model.EntityRef{Type: audit_model.ScopeRepository, ID: record.RepoID},
		Metadata:        metadata, TimestampUnix: record.CreatedUnix,
	}); err != nil {
		return errors.New("evidence_persist_failed")
	}
	if persisted() != nil {
		return errors.New("evidence_persist_failed")
	}
	return nil
}

func NativeMismatch(candidate string, native NativeOutcome) (mismatch, known bool) {
	if candidate != "allow" && candidate != "deny" || native != NativeSuccess && native != NativeDenied {
		return false, false
	}
	return candidate == "allow" && native == NativeDenied || candidate == "deny" && native == NativeSuccess, true
}

func safeObservationReason(ctx context.Context, err error, fallback string) string {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return "observation_canceled"
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "observation_timeout"
	case errors.Is(err, db.ErrIndependentTransactionInUse):
		return "business_transaction_active"
	}
	if slices.Contains([]string{"policy_read_failed", "snapshot_limit_exceeded", "database_audit_required", "evidence_persist_failed", "invalid_observation_context"}, fallback) {
		return fallback
	}
	return "observation_failed"
}

var observationWarnings = struct {
	sync.Mutex
	last map[string]time.Time
}{last: make(map[string]time.Time)}

func reportObservationFailure(operationID string, repoID int64, action authz.Action, reason string) {
	metrics.EnterpriseAuthzObservationFailed.WithLabelValues(reason).Inc()
	reportAuthorizationGap(operationID, repoID, action, reason)
}

func reportAuthorizationGap(operationID string, repoID int64, action authz.Action, reason string) {
	observationWarnings.Lock()
	now := time.Now()
	warn := now.Sub(observationWarnings.last[reason]) >= time.Minute
	if warn {
		observationWarnings.last[reason] = now
	}
	observationWarnings.Unlock()
	if !warn {
		return
	}
	if _, ok := authz.LookupAction(action); !ok {
		action = ""
	}
	log.Warn("enterprise_authz_evidence_gap operation=%s repo=%d action=%s reason=%s", operationID, repoID, action, reason)
}

func ObservePreparedGuardDenials(ctx context.Context, input EvaluateInput, prepare func(context.Context, EvaluateInput) ([]EvaluateInput, error)) {
	if !setting.EnterpriseAuthz.Enabled || input.Repo == nil || input.Permission == nil || !input.Credential.Read || !input.Credential.Write || !input.Permission.HasAnyUnitAccessOrPublicAccess() {
		return
	}
	bounded, cancel := context.WithTimeout(ctx, observationBudget)
	defer cancel()
	bounded = WithOperation(bounded)
	state, _ := bounded.Value(operationKey{}).(*operationState)
	if state == nil {
		reportObservationFailure("", input.Repo.ID, input.Action, "invalid_observation_context")
		return
	}
	inputs, err := prepare(bounded, input)
	if err != nil {
		reportObservationFailure(state.id, input.Repo.ID, input.Action, safeObservationReason(bounded, err, "target_lookup_failed"))
		return
	}
	if len(inputs) > len(authz.Catalog()) {
		reportObservationFailure(state.id, input.Repo.ID, input.Action, "invalid_observation_context")
		return
	}
	observations := make([]*Observation, 0, len(inputs))
	for _, input := range inputs {
		_, observation := BeginObservation(bounded, input)
		observations = append(observations, observation)
	}
	for _, observation := range observations {
		observation.Finish(bounded, NativeDenied, StageAuthorization)
	}
}
