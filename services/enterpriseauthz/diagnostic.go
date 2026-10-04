// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"unicode/utf8"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	"gitea.dev/services/audit"
)

type DiagnosticInput struct {
	Caller           *user_model.User
	TargetUserID     int64
	Repo             *repo_model.Repository
	Permission       *access_model.Permission
	Credential       CredentialCeiling
	Action           authz.Action
	ConditionContext authz.ConditionContext
}

type DiagnosticRole struct {
	ID       int64 `json:"id"`
	Revision int64 `json:"revision"`
}

type DiagnosticBinding struct {
	ID int64 `json:"id"`
}

type DiagnosticCondition struct {
	RoleID        int64        `json:"role_id"`
	BindingID     int64        `json:"binding_id"`
	Revision      int64        `json:"revision"`
	Action        authz.Action `json:"action"`
	Effect        string       `json:"effect"`
	ConditionHash string       `json:"condition_hash"`
	Result        string       `json:"result"`
}

type DiagnosticResult struct {
	Action                authz.Action          `json:"action"`
	CandidateDecision     string                `json:"candidate_decision"`
	Reason                string                `json:"reason"`
	NativeActions         []authz.Action        `json:"native_actions"`
	RoleActions           []authz.Action        `json:"role_actions"`
	MatchedRoleIDs        []int64               `json:"matched_role_ids"`
	MatchedBindingIDs     []int64               `json:"matched_binding_ids"`
	MissingActions        []authz.Action        `json:"missing_actions"`
	CandidateOnly         bool                  `json:"candidate_only"`
	SafetyGuardsEvaluated bool                  `json:"safety_guards_evaluated"`
	Roles                 []DiagnosticRole      `json:"roles"`
	Bindings              []DiagnosticBinding   `json:"bindings"`
	Conditions            []DiagnosticCondition `json:"conditions"`
}

type EffectivePermissionResult struct {
	NativeActions         []authz.Action        `json:"native_actions"`
	RoleActions           []authz.Action        `json:"role_actions"`
	UnresolvedActions     []authz.Action        `json:"unresolved_actions"`
	Reason                string                `json:"reason"`
	CandidateOnly         bool                  `json:"candidate_only"`
	SafetyGuardsEvaluated bool                  `json:"safety_guards_evaluated"`
	Roles                 []DiagnosticRole      `json:"roles"`
	Bindings              []DiagnosticBinding   `json:"bindings"`
	Conditions            []DiagnosticCondition `json:"conditions"`
}

func Diagnose(ctx context.Context, input DiagnosticInput) (DiagnosticResult, error) {
	evaluation, err := prepareDiagnostic(ctx, input)
	if err != nil {
		return DiagnosticResult{}, safePolicyError(err)
	}
	if _, ok := authz.LookupAction(input.Action); !ok {
		return DiagnosticResult{}, ErrInvalidPolicy
	}
	evaluation.Action = input.Action
	result, err := evaluateDiagnostic(ctx, input, evaluation, "action")
	if err != nil {
		return DiagnosticResult{}, safePolicyError(err)
	}
	return result, nil
}

func EffectivePermissions(ctx context.Context, input DiagnosticInput) (EffectivePermissionResult, error) {
	evaluation, err := prepareDiagnostic(ctx, input)
	if err != nil {
		return EffectivePermissionResult{}, safePolicyError(err)
	}
	evaluation.Action = authz.ViewMetadata
	result, err := evaluateDiagnostic(ctx, input, evaluation, "effective")
	if err != nil {
		return EffectivePermissionResult{}, safePolicyError(err)
	}
	effective := EffectivePermissionResult{
		NativeActions: result.NativeActions, RoleActions: result.RoleActions, Reason: result.Reason,
		CandidateOnly: result.CandidateOnly, SafetyGuardsEvaluated: result.SafetyGuardsEvaluated,
		Roles: result.Roles, Bindings: result.Bindings, Conditions: result.Conditions,
	}
	for _, entry := range result.Conditions {
		if entry.Result == string(authz.Unresolved) {
			effective.UnresolvedActions = append(effective.UnresolvedActions, entry.Action)
		}
	}
	slices.Sort(effective.UnresolvedActions)
	effective.UnresolvedActions = slices.Compact(effective.UnresolvedActions)
	return effective, nil
}

func prepareDiagnostic(ctx context.Context, input DiagnosticInput) (EvaluateInput, error) {
	if input.Caller == nil || input.Caller.ID == 0 || input.Caller.ID < 0 && input.Caller.ExtDoerData == nil || input.Permission == nil || !input.Credential.Read || !input.Permission.HasAnyUnitAccessOrPublicAccess() {
		return EvaluateInput{}, util.ErrPermissionDenied
	}
	if input.Repo == nil || input.Repo.ID <= 0 {
		return EvaluateInput{}, util.ErrNotExist
	}
	otherUser := input.TargetUserID != 0 && input.TargetUserID != input.Caller.ID
	if otherUser {
		if err := CheckManagementAuthority(ctx, input.Caller, authz_model.Scope{Type: authz_model.ScopeRepo, ID: input.Repo.ID}); err != nil {
			return EvaluateInput{}, safePolicyError(err)
		}
	}
	if !setting.EnterpriseAuthz.Enabled {
		return EvaluateInput{}, util.ErrNotExist
	}
	if err := validateDiagnosticContext(input); err != nil {
		return EvaluateInput{}, err
	}
	actor, permission := input.Caller, input.Permission
	if otherUser {
		var err error
		actor, err = user_model.GetUserByID(ctx, input.TargetUserID)
		if user_model.IsErrUserNotExist(err) || err == nil && !actor.IsIndividual() {
			return EvaluateInput{}, util.ErrNotExist
		}
		if err != nil {
			return EvaluateInput{}, ErrPolicyStorage
		}
		targetPermission, err := access_model.GetDoerRepoPermission(ctx, input.Repo, actor)
		if err != nil {
			return EvaluateInput{}, ErrPolicyStorage
		}
		if !targetPermission.HasAnyUnitAccessOrPublicAccess() {
			return EvaluateInput{}, util.ErrPermissionDenied
		}
		permission = &targetPermission
	}
	conditionContext := input.ConditionContext
	conditionContext.Source = "diagnostic"
	return EvaluateInput{Actor: actor, Repo: input.Repo, Permission: permission, Credential: input.Credential, ConditionContext: conditionContext}, nil
}

func validateDiagnosticContext(input DiagnosticInput) error {
	condition := input.ConditionContext
	if input.TargetUserID < 0 || len(condition.Paths) > authz.MaxContextPaths || !utf8.ValidString(condition.Branch) || !git.IsValidRefPattern(condition.Branch) {
		return ErrInvalidPolicy
	}
	total := len(condition.Branch)
	if total > authz.MaxBodyBytes {
		return ErrInvalidPolicy
	}
	for _, path := range condition.Paths {
		if path == "" || strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\\x00") || !utf8.ValidString(path) {
			return ErrInvalidPolicy
		}
		for part := range strings.SplitSeq(path, "/") {
			if part == ".." || part == "." || part == "" {
				return ErrInvalidPolicy
			}
		}
		total += len(path)
		if total > authz.MaxBodyBytes {
			return ErrInvalidPolicy
		}
	}
	return nil
}

func evaluateDiagnostic(ctx context.Context, input DiagnosticInput, evaluation EvaluateInput, kind string) (DiagnosticResult, error) {
	ctx, cancel := context.WithTimeout(ctx, observationBudget)
	defer cancel()
	decision, evaluationErr := Evaluate(ctx, evaluation)
	result, err := summarizeDiagnostic(decision, evaluation)
	if err != nil {
		return DiagnosticResult{}, ErrPolicyStorage
	}
	if err := recordDiagnostic(ctx, input, evaluation.Actor.ID, kind, result); err != nil {
		return DiagnosticResult{}, ErrPolicyStorage
	}
	if evaluationErr != nil {
		return DiagnosticResult{}, safePolicyError(evaluationErr)
	}
	return result, nil
}

func summarizeDiagnostic(decision Decision, input EvaluateInput) (DiagnosticResult, error) {
	result := DiagnosticResult{
		Action: decision.Action, CandidateDecision: decision.CandidateDecision, Reason: decision.Reason,
		NativeActions: decision.NativeActions, RoleActions: decision.RoleActions,
		MatchedRoleIDs: decision.MatchedRoleIDs, MatchedBindingIDs: decision.MatchedBindingIDs, MissingActions: decision.MissingActions,
		CandidateOnly: decision.CandidateOnly, SafetyGuardsEvaluated: decision.SafetyGuardsEvaluated,
	}
	if decision.Snapshot == "" {
		return result, nil
	}
	var snapshot roleSnapshot
	if err := json.Unmarshal([]byte(decision.Snapshot), &snapshot); err != nil {
		return DiagnosticResult{}, ErrPolicyStorage
	}
	roles := map[int64]int64{}
	bindings := map[int64]bool{}
	for _, entry := range snapshot.Roles {
		if !visibleAction(authz.Action(entry.Action), input.Permission, input.Credential, snapshot.Archived) {
			continue
		}
		roles[entry.RoleID] = entry.Revision
		bindings[entry.BindingID] = true
		result.Conditions = append(result.Conditions, DiagnosticCondition{
			RoleID: entry.RoleID, BindingID: entry.BindingID, Revision: entry.Revision,
			Action: authz.Action(entry.Action), Effect: entry.Effect, ConditionHash: entry.ConditionHash, Result: entry.Result,
		})
	}
	for id, revision := range roles {
		result.Roles = append(result.Roles, DiagnosticRole{ID: id, Revision: revision})
	}
	slices.SortFunc(result.Roles, func(a, b DiagnosticRole) int { return cmp.Compare(a.ID, b.ID) })
	for id := range bindings {
		result.Bindings = append(result.Bindings, DiagnosticBinding{ID: id})
	}
	slices.SortFunc(result.Bindings, func(a, b DiagnosticBinding) int { return cmp.Compare(a.ID, b.ID) })
	return result, nil
}

func recordDiagnostic(ctx context.Context, input DiagnosticInput, targetID int64, kind string, result DiagnosticResult) error {
	if setting.Audit.RecordOutput != setting.AuditRecordOutputDatabase {
		return ErrPolicyStorage
	}
	return db.WithIndependentTx(ctx, func(tx context.Context) error {
		auditCtx, persisted := audit.WithRequiredPersistence(tx)
		if err := audit.RecordEvent(auditCtx, audit.RecordParams{
			Action:          audit_model.EnterpriseAuthzDiagnostic,
			Actor:           audit_model.EntityRef{Type: audit_model.ScopeUser, ID: input.Caller.ID},
			ActorCredential: safeCredentialReference(input.Credential.Reference),
			Impersonator:    safeAuditImpersonator(auditCtx, input.Caller.ID),
			Scope:           audit_model.EntityRef{Type: audit_model.ScopeRepository, ID: input.Repo.ID},
			Metadata: map[string]any{
				"repo_id": input.Repo.ID, "target_user_id": targetID, "query_kind": kind,
				"action": result.Action, "candidate_decision": result.CandidateDecision, "reason": result.Reason,
				"native_actions": result.NativeActions, "role_actions": result.RoleActions,
			},
		}); err != nil {
			return ErrPolicyStorage
		}
		return persisted()
	})
}
