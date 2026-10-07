// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/services/audit"
)

const hookTicketLimit = 4096

var hookOperationNow = time.Now

type HookOwnedObservation struct {
	Action authz.Action
	Branch string
}

type hookOwnedObservation struct {
	Action     authz.Action `json:"action"`
	BranchHash string       `json:"branch_hash"`
}

type HookOperation struct{ payload hookOperationPayload }

type hookOperationPayload struct {
	Version       int                    `json:"version"`
	OperationID   string                 `json:"operation_id"`
	ActorID       int64                  `json:"actor_id"`
	RepoID        int64                  `json:"repo_id"`
	RequestSource string                 `json:"request_source"`
	Ceiling       CredentialCeiling      `json:"credential"`
	ActorExtHash  string                 `json:"actor_ext_hash"`
	ExpiresUnix   int64                  `json:"expires_unix"`
	Attribution   audit.Attribution      `json:"attribution"`
	Owned         []hookOwnedObservation `json:"owned,omitempty"`
	MergeGate     *mergeGateHookBinding  `json:"merge_gate,omitempty"`
}

func (o *HookOperation) Source() string { return o.payload.RequestSource }
func (o *HookOperation) Credential() CredentialCeiling {
	result := o.payload.Ceiling
	result.Actions = slices.Clone(result.Actions)
	return result
}

func (o *HookOperation) Owns(action authz.Action, branch string) bool {
	return slices.Contains(o.payload.Owned, hookOwnedObservation{Action: action, BranchHash: hookBranchHash(branch)})
}

func hookBranchHash(branch string) string {
	sum := sha256.Sum256([]byte(branch))
	return hex.EncodeToString(sum[:])
}

func NewHookOperationTicket(ctx context.Context, input EvaluateInput, owned []HookOwnedObservation) authz.HookOperationTicket {
	if !setting.EnterpriseAuthz.Enabled || input.Repo == nil || input.Repo.ID <= 0 || input.Actor == nil {
		return ""
	}
	ctx = WithOperation(ctx)
	state, _ := ctx.Value(operationKey{}).(*operationState)
	if state == nil || setting.InternalToken == "" || !authz.ValidSource(input.ConditionContext.Source) || input.ConditionContext.Source == "diagnostic" || len(owned) > 16 {
		reportObservationFailure("", input.Repo.ID, input.Action, "invalid_observation_context")
		return ""
	}
	ext := ""
	if input.Actor.ExtDoerData != nil {
		ext = input.Actor.ExtDoerData.EncodeToString()
	}
	ceiling := input.Credential
	ceiling.Reference = safeCredentialReference(ceiling.Reference)
	ceiling.Actions = slices.Clone(ceiling.Actions)
	operation := HookOperation{payload: hookOperationPayload{Version: 1, OperationID: state.id, ActorID: input.Actor.ID, RepoID: input.Repo.ID, RequestSource: input.ConditionContext.Source, Ceiling: ceiling, ActorExtHash: hookBranchHash(ext), ExpiresUnix: hookOperationNow().Add(24 * time.Hour).Unix(), Attribution: audit.AttributionFromContext(ctx)}}
	if setting.EnterpriseMergeGate.Enabled && setting.EnterpriseMergeGate.Enforce && slices.ContainsFunc(owned, func(entry HookOwnedObservation) bool { return entry.Action == authz.MergePullRequest }) {
		binding, ok := ctx.Value(mergeGateHookKey{}).(mergeGateHookBinding)
		if !ok || binding.OperationID != state.id || binding.RepoID != input.Repo.ID || binding.ActorID != input.Actor.ID || binding.BranchHash != hookBranchHash(input.ConditionContext.Branch) {
			return ""
		}
		operation.payload.MergeGate = &binding
	}
	for _, entry := range owned {
		if _, valid := authz.LookupAction(entry.Action); !valid || entry.Branch == "" {
			reportObservationFailure(state.id, input.Repo.ID, input.Action, "invalid_observation_context")
			return ""
		}
		operation.payload.Owned = append(operation.payload.Owned, hookOwnedObservation{Action: entry.Action, BranchHash: hookBranchHash(entry.Branch)})
	}
	data, err := json.Marshal(operation.payload)
	if err != nil {
		return ""
	}
	body := base64.RawURLEncoding.EncodeToString(data)
	signature := signHookTicket(body)
	ticket := authz.HookOperationTicket(body + "." + signature)
	if len(ticket) > hookTicketLimit {
		reportObservationFailure(state.id, input.Repo.ID, input.Action, "snapshot_limit_exceeded")
		return ""
	}
	return ticket
}

func signHookTicket(body string) string {
	mac := hmac.New(sha256.New, []byte(setting.InternalToken))
	_, _ = mac.Write([]byte("gitea.enterprise-authz.hook.v1\x00" + body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func RestoreHookOperation(ctx context.Context, ticket authz.HookOperationTicket, repoID, actorID int64, actorExt string) (context.Context, *HookOperation) {
	if !setting.EnterpriseAuthz.Enabled {
		return ctx, nil
	}
	invalid := func() (context.Context, *HookOperation) {
		reportObservationFailure("", repoID, "", "invalid_observation_context")
		return ctx, nil
	}
	if len(ticket) == 0 || len(ticket) > hookTicketLimit || setting.InternalToken == "" {
		return invalid()
	}
	body, signature, found := strings.Cut(string(ticket), ".")
	if !found || !hmac.Equal([]byte(signature), []byte(signHookTicket(body))) {
		return invalid()
	}
	data, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return invalid()
	}
	operation := new(HookOperation)
	if err = json.Unmarshal(data, &operation.payload); err != nil {
		return invalid()
	}
	now := hookOperationNow().Unix()
	if operation.payload.Version != 1 || operation.payload.RepoID != repoID || repoID <= 0 || operation.payload.ActorID != actorID || operation.payload.ActorExtHash != hookBranchHash(actorExt) || operation.payload.ExpiresUnix < now || operation.payload.ExpiresUnix > now+24*3600 || !authz.ValidSource(operation.payload.RequestSource) || operation.payload.RequestSource == "diagnostic" || len(operation.payload.OperationID) < 16 || len(operation.payload.OperationID) > 80 || len(operation.payload.Owned) > 16 || safeCredentialReference(operation.payload.Ceiling.Reference) != operation.payload.Ceiling.Reference {
		return invalid()
	}
	for _, r := range operation.payload.OperationID {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return invalid()
		}
	}
	for _, action := range operation.payload.Ceiling.Actions {
		if _, valid := authz.LookupAction(action); !valid {
			return invalid()
		}
	}
	for _, owned := range operation.payload.Owned {
		if _, valid := authz.LookupAction(owned.Action); !valid || len(owned.BranchHash) != 64 {
			return invalid()
		}
	}
	state := &operationState{id: operation.payload.OperationID, observations: make(map[[32]byte]*Observation), hook: operation}
	if existing, ok := ctx.Value(operationKey{}).(*operationState); ok && existing.id != state.id {
		return invalid()
	}
	if store := reqctx.FromContext(ctx); store != nil {
		store.SetContextValue(operationKey{}, state)
	} else {
		ctx = context.WithValue(ctx, operationKey{}, state)
	}
	ctx = audit.WithAttribution(ctx, operation.payload.Attribution)
	return ctx, operation
}

func hookObservationID(operation *HookOperation, action authz.Action, branch string) string {
	data, _ := json.Marshal(struct {
		OperationID        string
		ActorID, RepoID    int64
		Action             authz.Action
		Source, BranchHash string
	}{operation.payload.OperationID, operation.payload.ActorID, operation.payload.RepoID, action, operation.payload.RequestSource, hookBranchHash(branch)})
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func CompleteHookObservation(ctx context.Context, operation *HookOperation, action authz.Action, branch string, outcome NativeOutcome, stage NativeStage) {
	if !setting.EnterpriseAuthz.Enabled || operation == nil || operation.Owns(action, branch) {
		return
	}
	if !slices.Contains([]NativeOutcome{NativeSuccess, NativeDenied, NativeFailed}, outcome) || !validImportedObservationStage(action, stage) {
		return
	}
	bounded, cancel := context.WithTimeout(ctx, observationBudget)
	defer cancel()
	if db.InTransaction(ctx) {
		reportObservationFailure(operation.payload.OperationID, operation.payload.RepoID, action, "business_transaction_active")
		return
	}
	record := new(authz_model.DecisionRecord)
	found, err := db.GetEngine(bounded).Where("observation_id = ? AND operation_id = ? AND actor_id = ? AND repo_id = ? AND action = ? AND request_source = ?", hookObservationID(operation, action, branch), operation.payload.OperationID, operation.payload.ActorID, operation.payload.RepoID, action, operation.payload.RequestSource).Get(record)
	if err == nil && (!found || record.NativeOutcome != "unknown") {
		return
	}
	if err == nil {
		record.NativeOutcome, record.NativeStage = string(outcome), string(stage)
		err = db.WithIndependentTx(bounded, func(tx context.Context) error { return finalizeHookRecord(tx, record) })
	}

	if err != nil {
		reportObservationFailure(operation.payload.OperationID, operation.payload.RepoID, action, safeObservationReason(bounded, err, "evidence_persist_failed"))
	}
}

func validHookInput(operation *HookOperation, input EvaluateInput) bool {
	if input.Actor == nil || input.Repo == nil || input.Actor.ID != operation.payload.ActorID || input.Repo.ID != operation.payload.RepoID || input.ConditionContext.Source != operation.payload.RequestSource {
		return false
	}
	ext := ""
	if input.Actor.ExtDoerData != nil {
		ext = input.Actor.ExtDoerData.EncodeToString()
	}
	left, _ := json.Marshal(input.Credential)
	right, _ := json.Marshal(operation.payload.Ceiling)
	return hookBranchHash(ext) == operation.payload.ActorExtHash && string(left) == string(right)
}

func ManagedHookOperationTicket(ctx context.Context, actor *user_model.User, repo *repo_model.Repository, branch string, action authz.Action) authz.HookOperationTicket {
	if !setting.EnterpriseAuthz.Enabled {
		return ""
	}
	source := "system"
	ceiling := RequestCredentialCeiling(ctx, actor)
	owned := []HookOwnedObservation{{Action: action, Branch: branch}}
	if action == authz.PushBranch || action == authz.PushProtectedBranch {
		owned = []HookOwnedObservation{{Action: authz.PushBranch, Branch: branch}, {Action: authz.PushProtectedBranch, Branch: branch}}
	}
	if bound, ok := ctx.Value(boundObservationKey{}).(boundObservation); ok && bound.actorID == actor.ID && bound.repoID == repo.ID && bound.action == action && (!bound.branchKnown || bound.branch == branch) {
		source = bound.source
		ceiling = bound.credential
	} else {
		reportObservationFailure("", repo.ID, action, "invalid_observation_context")
	}
	return NewHookOperationTicket(ctx, EvaluateInput{Actor: actor, Repo: repo, Credential: ceiling, Action: action, ConditionContext: authz.ConditionContext{Source: source}}, owned)
}

func finalizeHookRecord(tx context.Context, record *authz_model.DecisionRecord) error {
	changed, err := db.GetEngine(tx).ID(record.ID).Where("observation_id = ? AND operation_id = ? AND actor_id = ? AND repo_id = ? AND action = ? AND request_source = ? AND native_outcome = ?", record.ObservationID, record.OperationID, record.ActorID, record.RepoID, record.Action, record.RequestSource, "unknown").Cols("native_outcome", "native_stage").Update(&authz_model.DecisionRecord{NativeOutcome: record.NativeOutcome, NativeStage: record.NativeStage})
	if err != nil || changed == 0 {
		return err
	}
	mismatch, known := NativeMismatch(record.CandidateDecision, NativeOutcome(record.NativeOutcome))
	var value *bool
	if known && (record.DecisionMode == "" || record.DecisionMode == "shadow") {
		value = &mismatch
	}
	return audit.UpdateEnterpriseAuthzNativeResult(tx, record, value)
}

func BeginHookBranchObservations(ctx context.Context, operation *HookOperation, input EvaluateInput, created bool) (context.Context, []*Observation) {
	if !setting.EnterpriseAuthz.Enabled || operation == nil || input.Permission == nil || !input.Permission.HasAnyUnitAccessOrPublicAccess() {
		return ctx, nil
	}
	branch := input.ConditionContext.Branch
	if !validHookInput(operation, input) || !input.ConditionContext.BranchKnown || branch == "" {
		reportObservationFailure(operation.payload.OperationID, operation.payload.RepoID, input.Action, "invalid_observation_context")
		return ctx, nil
	}
	if operation.Owns(authz.MergePullRequest, branch) || operation.Owns(authz.PushBranch, branch) && operation.Owns(authz.PushProtectedBranch, branch) {
		if created && !operation.Owns(authz.CreateBranch, branch) {
			reportObservationFailure(operation.payload.OperationID, operation.payload.RepoID, authz.CreateBranch, "invalid_observation_context")
		}
		return ctx, nil
	}
	actions := []authz.Action{authz.PushBranch, authz.PushProtectedBranch}
	if created {
		actions = append(actions, authz.CreateBranch)
	}
	if !slices.ContainsFunc(actions, func(action authz.Action) bool { return !operation.Owns(action, branch) }) {
		return ctx, nil
	}
	started := time.Now()
	bounded, cancel := context.WithTimeout(ctx, observationBudget)
	defer cancel()
	historyActions := []authz.Action{authz.CreateBranch, authz.PushBranch, authz.PushProtectedBranch}
	ids := make([]string, 0, len(historyActions))
	for _, action := range historyActions {
		if !operation.Owns(action, branch) {
			ids = append(ids, hookObservationID(operation, action, branch))
		}
	}
	records := make([]authz_model.DecisionRecord, 0, len(ids))
	err := db.GetEngine(bounded).Where("operation_id = ? AND actor_id = ? AND repo_id = ? AND request_source = ?", operation.payload.OperationID, operation.payload.ActorID, operation.payload.RepoID, operation.payload.RequestSource).In("observation_id", ids).Limit(len(ids)).Find(&records)
	if err != nil {
		reportObservationFailure(operation.payload.OperationID, operation.payload.RepoID, input.Action, safeObservationReason(bounded, err, "evidence_persist_failed"))
		return ctx, nil
	}
	observations := make([]*Observation, 0, 2)
	if len(records) > 0 {
		for _, record := range records {
			ready := make(chan struct{})
			close(ready)
			observations = append(observations, &Observation{record: record, credential: safeCredentialReference(operation.payload.Ceiling.Reference), ceiling: operation.Credential(), remaining: observationBudget - time.Since(started), ready: ready, hookExisting: true})
		}
		return ctx, observations
	}
	protected, err := git_model.GetFirstMatchProtectedBranchRule(bounded, input.Repo.ID, branch)
	if err != nil {
		reportObservationFailure(operation.payload.OperationID, operation.payload.RepoID, input.Action, safeObservationReason(bounded, err, "observation_failed"))
		return ctx, nil
	}
	input.Action = authz.PushBranch
	if protected != nil {
		input.Action = authz.PushProtectedBranch
	} else if created {
		input.Action = authz.CreateBranch
	}
	primaryAction := input.Action
	if !operation.Owns(primaryAction, branch) {
		_, observation := beginObservation(bounded, input, max(0, observationBudget-time.Since(started)))
		observations = append(observations, observation)
	}
	if created && primaryAction != authz.CreateBranch && !operation.Owns(authz.CreateBranch, branch) {
		input.Action = authz.CreateBranch
		_, observation := beginObservation(bounded, input, max(0, observationBudget-time.Since(started)))
		observations = append(observations, observation)
	}
	return ctx, observations
}

func validImportedObservationStage(action authz.Action, stage NativeStage) bool {
	return stage == StagePreReceive || stage == StageTransport || action == authz.Migrate && stage == StageMigration || action == authz.CreatePullRequest && stage == StageOperation
}

func observationTarget(input EvaluateInput) string {
	if input.observationTarget != "" {
		return input.observationTarget
	}
	return input.ConditionContext.Branch
}

func BeginHookPullRequestObservation(ctx context.Context, actor *user_model.User, repo *repo_model.Repository, targetBranch, ref string) (context.Context, *Observation) {
	state, ok := ctx.Value(operationKey{}).(*operationState)
	if !setting.EnterpriseAuthz.Enabled || !ok || state.hook == nil || actor == nil || repo == nil {
		return ctx, nil
	}
	input := EvaluateInput{Actor: actor, Repo: repo, Credential: state.hook.Credential(), Action: authz.CreatePullRequest, observationTarget: ref, ConditionContext: authz.ConditionContext{Source: state.hook.Source(), Branch: targetBranch, BranchKnown: targetBranch != ""}}
	return BeginResolvedObservation(ctx, input, func(ctx context.Context) (*access_model.Permission, error) {
		permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
		return &permission, err
	})
}
