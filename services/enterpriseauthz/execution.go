// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/metrics"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/timeutil"
	"gitea.dev/services/audit"
)

const (
	executionBudget          = time.Second
	maxExecutionRepositories = 1000
)

type ExecutionInput struct {
	EvaluateInput
	Intent                string
	registrationTokenID   int64
	registrationTokenHash [32]byte
	registrationCheck     func(context.Context, ExecutionInput) (Decision, error)
	resolve               func(context.Context, ExecutionInput) ([]ExecutionInput, error)
}

type ExecutionError struct {
	Reason string
	Status int
}

func (e *ExecutionError) Error() string { return e.Reason }

type (
	admissionKey        struct{}
	executionAttemptKey struct{}
)

type executionAttempt struct {
	mutex  sync.RWMutex
	inputs []ExecutionInput
}

type Admission struct {
	mutex             sync.Mutex
	records           []authz_model.DecisionRecord
	inputs            []ExecutionInput
	keys              [][32]byte
	preparedKeys      [][32]byte
	preparedInputs    []ExecutionInput
	operationID       string
	deadline          time.Time
	started, finished bool
	fallback          bool
}

func executionKey(input ExecutionInput) [32]byte {
	data, _ := json.Marshal(struct {
		ActorID, RepoID, OwnerID, TargetOwnerID, CredentialOrganizationID int64
		Action                                                            authz.Action
		Credential                                                        CredentialCeiling
		Context                                                           authz.ConditionContext
		Intent                                                            string
	}{actorID(input.EvaluateInput), input.Repo.ID, input.Repo.OwnerID, input.TargetOwnerID, input.Credential.organizationID, input.Action, input.Credential, input.ConditionContext, input.Intent})
	return sha256.Sum256(data)
}

func BeginExecution(ctx context.Context, inputs []ExecutionInput) (context.Context, *Admission, error) {
	return BeginPreparedExecution(ctx, func(context.Context) ([]ExecutionInput, error) { return inputs, nil })
}

func BeginPreparedExecution(ctx context.Context, prepare func(context.Context) ([]ExecutionInput, error)) (context.Context, *Admission, error) {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return ctx, nil, nil
	}
	started := time.Now()
	defer func() { metrics.EnterpriseAuthzExecutionDuration.Observe(time.Since(started).Seconds()) }()
	bounded, cancel := context.WithTimeout(ctx, executionBudget)
	defer cancel()
	reject := func(reason string, status int) (context.Context, *Admission, error) {
		reportExecutionFailure(reason)
		return ctx, nil, &ExecutionError{Reason: reason, Status: status}
	}
	if ctx.Err() != nil {
		return reject("execution_canceled", http.StatusForbidden)
	}
	if db.InTransaction(ctx) || prepare == nil {
		return reject("invalid_execution_context", http.StatusForbidden)
	}
	inputs, err := prepare(bounded)
	if err != nil {
		reason, recoverable := executionReason(ctx, bounded, err)
		if recoverable && !setting.EnterpriseAuthz.FailClosedOnError {
			reportExecutionFailure(reason)
			return ctx, nil, nil
		}
		return reject(reason, executionStatus(err, recoverable))
	}
	filtered := make([]ExecutionInput, 0, len(inputs))
	keys := make([][32]byte, 0, len(inputs))
	repos := make(map[int64]struct{})
	for _, input := range inputs {
		entry, known := authz.LookupAction(input.Action)
		if !known {
			return reject("invalid_execution_context", http.StatusForbidden)
		}
		if !entry.EnforceSupported && input.resolve == nil {
			continue
		}
		if input.Actor != nil && input.Actor.ExtDoerData != nil && !isActionsExecutionActor(input) && !isDeployExecutionActor(input) {
			return reject("invalid_execution_context", http.StatusForbidden)
		}
		if input.resolve == nil && ((input.Actor == nil || input.Actor.ID <= 0) && input.registrationTokenID <= 0 && !isActionsExecutionActor(input) && !isDeployExecutionActor(input) || !authz.ValidSource(input.ConditionContext.Source) || input.ConditionContext.Source == "diagnostic" || input.ConditionContext.Source == "system" && input.registrationTokenID <= 0) || input.Repo == nil || input.Repo.ID <= 0 || input.Intent == "" || len(input.Intent) > 2048 {
			return reject("invalid_execution_context", http.StatusForbidden)
		}
		if input.Credential.organizationID > 0 && input.Repo.OwnerID != input.Credential.organizationID {
			return reject("invalid_execution_context", http.StatusForbidden)
		}
		if input.Action == authz.ManageCodeowners && !input.ConditionContext.PathsComplete {
			return reject("invalid_execution_context", http.StatusForbidden)
		}
		if len(input.ConditionContext.Paths) > authz.MaxContextPaths {
			return reject("context_limit_exceeded", http.StatusForbidden)
		}
		repos[input.Repo.ID] = struct{}{}
		if len(repos) > maxExecutionRepositories {
			return reject("context_limit_exceeded", http.StatusForbidden)
		}
		key := executionKey(input)
		if slices.Contains(keys, key) {
			continue
		}
		repoCopy := *input.Repo
		input.Repo = &repoCopy
		if input.Actor != nil {
			actorCopy := *input.Actor
			input.Actor = &actorCopy
		}
		input.ConditionContext.Paths = slices.Clone(input.ConditionContext.Paths)
		input.Credential.Actions = slices.Clone(input.Credential.Actions)
		filtered, keys = append(filtered, input), append(keys, key)
	}
	if len(filtered) == 0 {
		return ctx, nil, nil
	}
	admission := &Admission{inputs: filtered, keys: keys, preparedKeys: slices.Clone(keys), preparedInputs: slices.Clone(filtered), deadline: started.Add(executionBudget)}
	ctx = WithOperation(ctx)
	attempt := &executionAttempt{inputs: filtered}
	if store := reqctx.FromContext(ctx); store != nil {
		store.SetContextValue(executionAttemptKey{}, attempt)
	} else {
		ctx = context.WithValue(ctx, executionAttemptKey{}, attempt)
	}
	operationID := rand.Text()
	if state, ok := ctx.Value(operationKey{}).(*operationState); ok {
		operationID = state.id
	}
	admission.operationID = operationID
	deniedReason, failureReason := "", ""
	recoverable := false
	failureStatus := http.StatusForbidden
	readErr := db.WithIndependentReadTx(bounded, func(tx context.Context) error {
		resolved := make([]ExecutionInput, 0, len(filtered))
		for _, input := range filtered {
			if input.resolve != nil {
				expanded, err := input.resolve(tx, input)
				if err != nil {
					newReason, newRecoverable := executionReason(ctx, bounded, err)
					if failureReason == "" || recoverable && !newRecoverable {
						failureReason, recoverable = newReason, newRecoverable
						failureStatus = executionStatus(err, newRecoverable)
					}
					continue
				}
				resolved = append(resolved, expanded...)
			} else {
				resolved = append(resolved, input)
			}
		}
		filtered = resolved
		admission.inputs = resolved
		attempt.mutex.Lock()
		attempt.inputs = resolved
		attempt.mutex.Unlock()
		admission.keys = nil
		for _, input := range resolved {
			admission.keys = append(admission.keys, executionKey(input))
			decision, evalErr := evaluateExecution(tx, input)
			if decision.CandidateDecision == "deny" && deniedReason == "" {
				deniedReason = decision.Reason
			}
			if evalErr != nil {
				newReason, newRecoverable := executionReason(ctx, bounded, evalErr)
				if failureReason == "" || recoverable && !newRecoverable {
					failureReason, recoverable = newReason, newRecoverable
					failureStatus = executionStatus(evalErr, newRecoverable)
				}
			}
			if decision.Snapshot == "" {
				data, _ := json.Marshal(baseSnapshot(input.EvaluateInput, decision.NativeActions))
				decision.Snapshot = string(data)
			}
			var snapshot roleSnapshot
			if err := json.Unmarshal([]byte(decision.Snapshot), &snapshot); err == nil {
				hash := sha256.Sum256([]byte(input.Intent))
				snapshot.IntentHash = hex.EncodeToString(hash[:])
				data, _ := json.Marshal(snapshot)
				decision.Snapshot = string(data)
			}
			missing, _ := json.Marshal(decision.MissingActions)
			admission.records = append(admission.records, authz_model.DecisionRecord{
				ObservationID: rand.Text(), OperationID: operationID, ActorID: actorID(input.EvaluateInput), RepoID: input.Repo.ID,
				OwnerID: decision.ownerID, Action: input.Action, RequestSource: input.ConditionContext.Source,
				CandidateDecision: decision.CandidateDecision, Reason: decision.Reason, MissingActions: string(missing), SnapshotJSON: decision.Snapshot,
				DecisionMode: "enforce", NativeOutcome: "unknown", NativeStage: string(StageOperation), CreatedUnix: timeutil.TimeStampNow(),
			})
		}
		return nil
	})
	if readErr != nil {
		if _, typed := errors.AsType[*ExecutionError](readErr); !typed && !errors.Is(readErr, db.ErrIndependentTransactionInUse) {
			readErr = errors.New("policy_read_failed")
		}
		newReason, newRecoverable := executionReason(ctx, bounded, readErr)
		if failureReason == "" || recoverable && !newRecoverable {
			failureReason, recoverable = newReason, newRecoverable
			failureStatus = executionStatus(readErr, newRecoverable)
		}
	}
	if ctx.Err() != nil {
		failureReason, recoverable = "execution_canceled", false
		failureStatus = http.StatusForbidden
	}
	if len(admission.records) == 0 && failureReason == "" {
		return context.WithValue(ctx, admissionKey{}, admission), admission, nil
	}
	result, reason := "allow", ""
	status := 0
	switch {
	case deniedReason != "":
		result, reason, status = "deny", deniedReason, http.StatusForbidden
	case failureReason != "":
		result, reason, status = "error", failureReason, failureStatus
		if recoverable {
			status = http.StatusServiceUnavailable
			if !setting.EnterpriseAuthz.FailClosedOnError {
				result, status = "fallback", 0
			}
		}
	}
	for i := range admission.records {
		record := &admission.records[i]
		metrics.EnterpriseAuthzExecutionDecision.WithLabelValues(string(record.Action), result).Inc()
		record.AuthorizationDecision, record.AuthorizationReason = result, reason
		if reason == "" {
			record.AuthorizationReason = record.Reason
		}
	}
	evidenceErr := db.WithIndependentTx(bounded, func(tx context.Context) error {
		if setting.Audit.RecordOutput != setting.AuditRecordOutputDatabase {
			return errors.New("evidence_persist_failed")
		}
		for i := range admission.records {
			if err := persistObservationTx(tx, &admission.records[i], safeCredentialReference(filtered[i].Credential.Reference)); err != nil {
				return err
			}
		}
		return nil
	})
	if evidenceErr != nil {
		reportExecutionFailure("evidence_persist_failed")
		if status == 0 && !setting.EnterpriseAuthz.FailClosedOnError {
			admission.records = nil
			admission.fallback = true
			return context.WithValue(ctx, admissionKey{}, admission), admission, nil
		}
		if status == 0 {
			reason, status = "evidence_persist_failed", http.StatusServiceUnavailable
		}
	}
	if status != 0 {
		return reject(reason, status)
	}
	admission.fallback = result == "fallback"
	return context.WithValue(ctx, admissionKey{}, admission), admission, nil
}

func evaluateExecution(ctx context.Context, input ExecutionInput) (Decision, error) {
	if isActionsExecutionActor(input) {
		return authenticatedActionsExecutionActor(ctx, input)
	}
	if isDeployExecutionActor(input) {
		return authenticatedDeployExecutionActor(ctx, input)
	}
	if input.registrationTokenID > 0 {
		if input.registrationCheck == nil {
			return Decision{Action: input.Action, CandidateDecision: "error", Reason: "invalid_evaluation_context", CandidateOnly: true, ownerID: input.Repo.OwnerID}, &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
		}
		return input.registrationCheck(ctx, input)
	}
	failure := Decision{Action: input.Action, CandidateDecision: "error", Reason: "policy_read_failed", CandidateOnly: true, ownerID: input.Repo.OwnerID}
	currentRepo, err := repo_model.GetRepositoryByID(ctx, input.Repo.ID)
	if repo_model.IsErrRepoNotExist(err) {
		failure.Reason = "invalid_evaluation_context"
		return failure, &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	}
	if err != nil {
		return failure, &ExecutionError{Reason: "policy_read_failed", Status: http.StatusServiceUnavailable}
	}
	if input.Repo.OwnerID != currentRepo.OwnerID {
		failure.Reason = "invalid_evaluation_context"
		return failure, &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	}
	actor, err := user_model.GetUserByID(ctx, input.Actor.ID)
	if user_model.IsErrUserNotExist(err) {
		failure.CandidateDecision, failure.Reason = "deny", "actor_inactive"
		return failure, nil
	}
	if err != nil {
		return failure, &ExecutionError{Reason: "policy_read_failed", Status: http.StatusServiceUnavailable}
	}
	actor.ExtDoerData = input.Actor.ExtDoerData
	if !actor.IsActive || actor.ProhibitLogin {
		failure.CandidateDecision, failure.Reason = "deny", "actor_inactive"
		return failure, nil
	}
	if actor.IsAdmin {
		trusted, err := access_model.HasSystemManagementAuthority(ctx, actor)
		if err != nil {
			return failure, &ExecutionError{Reason: "policy_read_failed", Status: http.StatusServiceUnavailable}
		}
		actor.IsAdmin = trusted
	}
	permission, err := access_model.GetDoerRepoPermission(ctx, currentRepo, actor)
	if err != nil {
		return failure, &ExecutionError{Reason: "policy_read_failed", Status: http.StatusServiceUnavailable}
	}
	nativeAllowed := true
	switch input.Action {
	case authz.ManageBranchProtection, authz.ManageWebhook, authz.ManageCI, authz.ManageSecret:
		nativeAllowed = permission.IsAdmin()
		if input.Action == authz.ManageSecret && input.ConditionContext.Source == "api" {
			nativeAllowed = permission.IsOwner()
		}
	}
	if !nativeAllowed {
		failure.CandidateDecision, failure.Reason = "deny", "native_visibility_denied"
		return failure, nil
	}
	input.Actor, input.Repo, input.Permission = actor, currentRepo, &permission
	return evaluate(ctx, input.EvaluateInput, true)
}

func executionReason(parent, bounded context.Context, err error) (string, bool) {
	if parent.Err() != nil {
		return "execution_canceled", false
	}
	if rejection, ok := errors.AsType[*ExecutionError](err); ok {
		if !slices.Contains([]string{"invalid_execution_context", "context_limit_exceeded", "execution_canceled", "actor_inactive", "native_visibility_denied", "policy_read_failed", "evidence_persist_failed", "execution_timeout"}, rejection.Reason) {
			return "invalid_execution_context", false
		}
		return rejection.Reason, false
	}
	if errors.Is(bounded.Err(), context.DeadlineExceeded) {
		return "execution_timeout", true
	}
	if errors.Is(err, db.ErrIndependentTransactionInUse) {
		return "invalid_execution_context", false
	}
	if err != nil && err.Error() == "snapshot_limit_exceeded" {
		return "context_limit_exceeded", false
	}
	if err != nil && slices.Contains([]string{"policy_read_failed", "evidence_persist_failed"}, err.Error()) {
		return err.Error(), true
	}
	return "invalid_execution_context", false
}

func executionStatus(err error, recoverable bool) int {
	if rejection, ok := errors.AsType[*ExecutionError](err); ok && rejection.Status == http.StatusServiceUnavailable {
		return http.StatusServiceUnavailable
	}
	if recoverable {
		return http.StatusServiceUnavailable
	}
	return http.StatusForbidden
}

func (a *Admission) Start(ctx context.Context) error {
	if a == nil {
		return nil
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.finished || ctx.Value(admissionKey{}) != a {
		return &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	}
	if a.started {
		return nil
	}
	if ctx.Err() != nil {
		return &ExecutionError{Reason: "execution_canceled", Status: http.StatusForbidden}
	}
	bounded, cancel := context.WithDeadline(ctx, a.deadline)
	defer cancel()
	err := db.WithIndependentTx(bounded, func(tx context.Context) error {
		for i := range a.records {
			record := &a.records[i]
			record.ExecutionStarted = true
			count, err := db.GetEngine(tx).ID(record.ID).Where("execution_started = ? AND native_outcome = ?", false, "unknown").Cols("execution_started").Update(record)
			if err != nil || count != 1 {
				return errors.New("evidence_persist_failed")
			}
			if err := audit.UpdateEnterpriseAuthzNativeResult(tx, record, nil); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		reportExecutionFailure("evidence_persist_failed")
		if ctx.Err() != nil {
			return &ExecutionError{Reason: "execution_canceled", Status: http.StatusForbidden}
		}
		if setting.EnterpriseAuthz.FailClosedOnError {
			return &ExecutionError{Reason: "evidence_persist_failed", Status: http.StatusServiceUnavailable}
		}
		a.fallback = true
		for i := range a.records {
			a.records[i].AuthorizationDecision = "fallback"
			a.records[i].AuthorizationReason = "evidence_persist_failed"
			a.records[i].ExecutionStarted = true
		}
	}
	a.started = true
	return nil
}

func (a *Admission) Finish(ctx context.Context, outcome NativeOutcome, stage NativeStage) {
	if a == nil {
		return
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.finished || !a.started {
		return
	}
	a.finished = true
	if !slices.Contains([]NativeOutcome{NativeSuccess, NativeDenied, NativeFailed}, outcome) {
		return
	}
	if !slices.Contains([]NativeStage{StageOperation, StagePreReceive, StageTransport}, stage) {
		return
	}
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), observationBudget)
	defer cancel()
	err := db.WithIndependentTx(bounded, func(tx context.Context) error {
		for i := range a.records {
			record := &a.records[i]
			record.NativeOutcome, record.NativeStage = string(outcome), string(stage)
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

func finalizeExecutionRecord(tx context.Context, record *authz_model.DecisionRecord) error {
	changed, err := db.GetEngine(tx).ID(record.ID).Where("observation_id = ? AND operation_id = ? AND actor_id = ? AND repo_id = ? AND action = ? AND decision_mode = ? AND native_outcome = ?", record.ObservationID, record.OperationID, record.ActorID, record.RepoID, record.Action, "enforce", "unknown").Cols("native_outcome", "native_stage", "execution_started", "authorization_decision", "authorization_reason").Update(record)
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("evidence_persist_failed")
	}
	return audit.UpdateEnterpriseAuthzNativeResult(tx, record, nil)
}

func executionReplacesObservation(ctx context.Context, observation *Observation) bool {
	attempt, ok := ctx.Value(executionAttemptKey{}).(*executionAttempt)
	if !ok || attempt == nil {
		return false
	}
	attempt.mutex.RLock()
	defer attempt.mutex.RUnlock()
	for _, input := range attempt.inputs {
		left, _ := json.Marshal(input.Credential)
		right, _ := json.Marshal(observation.ceiling)
		if actorID(input.EvaluateInput) == observation.record.ActorID && input.Repo.ID == observation.record.RepoID && input.Action == observation.record.Action && input.ConditionContext.Source == observation.record.RequestSource && string(left) == string(right) && input.ConditionContext.Branch == observation.condition.Branch && input.ConditionContext.BranchKnown == observation.condition.BranchKnown && (observation.targetOwnerID == 0 || input.TargetOwnerID == observation.targetOwnerID) {
			return true
		}
	}
	return false
}

func RequireExecution(ctx context.Context, repoID int64, action authz.Action, intent string) error {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return nil
	}
	a, ok := ctx.Value(admissionKey{}).(*Admission)
	if !ok || a == nil {
		return &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if a.started && !a.finished {
		for _, input := range a.inputs {
			if input.Repo.ID == repoID && input.Action == action && input.Intent == intent {
				return nil
			}
		}
	}
	return &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
}

func reportExecutionFailure(reason string) {
	if !slices.Contains([]string{"missing_action", "condition_unresolved", "condition_not_matched", "native_visibility_denied", "actor_inactive", "invalid_execution_context", "policy_read_failed", "evidence_persist_failed", "execution_timeout", "execution_canceled", "context_limit_exceeded"}, reason) {
		reason = "invalid_execution_context"
	}
	metrics.EnterpriseAuthzExecutionFailed.WithLabelValues(reason).Inc()
	reportAuthorizationGap("", 0, "", reason)
}

func RequireExecutionTarget(ctx context.Context, repo *repo_model.Repository, action authz.Action, intent string) error {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return nil
	}
	if repo == nil {
		return &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	}
	if err := RequireExecution(ctx, repo.ID, action, intent); err != nil {
		return err
	}
	a, ok := ctx.Value(admissionKey{}).(*Admission)
	if !ok || a == nil {
		return &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()
	for _, input := range a.inputs {
		if input.Repo.ID == repo.ID && input.Repo.OwnerID == repo.OwnerID && input.Action == action && input.Intent == intent {
			return nil
		}
	}
	return &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
}

func RequireExecutionInput(ctx context.Context, input ExecutionInput) error {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return nil
	}
	if input.Actor == nil || input.Repo == nil {
		return &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	}
	if err := RequireExecution(ctx, input.Repo.ID, input.Action, input.Intent); err != nil {
		return err
	}
	a, ok := ctx.Value(admissionKey{}).(*Admission)
	if !ok || a == nil {
		return &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if slices.Contains(a.keys, executionKey(input)) {
		return nil
	}
	return &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
}

func HasExecution(ctx context.Context) bool {
	a, ok := ctx.Value(admissionKey{}).(*Admission)
	return ok && a != nil
}
