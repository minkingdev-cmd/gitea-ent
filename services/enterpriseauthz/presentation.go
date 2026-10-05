// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"encoding/hex"
	"slices"

	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/unit"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	api "gitea.dev/modules/structs"
)

func ActionsDTO(actions []authz.Action) []string {
	result := make([]string, 0, len(actions))
	for _, action := range actions {
		result = append(result, string(action))
	}
	return result
}

func RoleDTO(role *Role) (*api.EnterpriseAuthzRole, error) {
	d := role.Definition
	result := &api.EnterpriseAuthzRole{ID: d.ID, Scope: api.EnterpriseAuthzScope{Type: string(d.ScopeType), ID: d.ScopeID}, Name: d.Name, Description: d.Description, Revision: d.Revision, CreatedBy: d.CreatedBy, Created: d.CreatedUnix.AsTime(), Updated: d.UpdatedUnix.AsTime(), Permissions: []api.EnterpriseAuthzPermission{}}
	if d.BuiltinKey != nil {
		result.Key = *d.BuiltinKey
		result.IsBuiltin = true
	}
	for _, p := range role.Permissions {
		condition, _, hash, err := authz.ParseCondition([]byte(p.ConditionJSON))
		if err != nil || hash != p.ConditionHash || authz.ValidatePermission(p.Action, p.Effect) != nil {
			return nil, ErrPolicyStorage
		}
		permission := api.EnterpriseAuthzPermission{Action: string(p.Action), Effect: p.Effect}
		if condition != nil {
			permission.Condition = &api.EnterpriseAuthzCondition{BranchPattern: condition.BranchPattern, PathPattern: condition.PathPattern, RequestSources: condition.RequestSources}
		}
		result.Permissions = append(result.Permissions, permission)
	}
	return result, nil
}

func ExplanationDTO(native, roles []authz.Action, reason string, definitions []DiagnosticRole, bindings []DiagnosticBinding, conditions []DiagnosticCondition) api.EnterpriseAuthzExplanation {
	result := api.EnterpriseAuthzExplanation{NativeActions: ActionsDTO(native), RoleActions: ActionsDTO(roles), Reason: reason, CandidateOnly: true, Roles: []api.EnterpriseAuthzRoleRevision{}, Bindings: []api.EnterpriseAuthzBindingReference{}, Conditions: []api.EnterpriseAuthzConditionResult{}}
	for _, r := range definitions {
		result.Roles = append(result.Roles, api.EnterpriseAuthzRoleRevision{ID: r.ID, Revision: r.Revision})
	}
	for _, b := range bindings {
		result.Bindings = append(result.Bindings, api.EnterpriseAuthzBindingReference{ID: b.ID})
	}
	for _, c := range conditions {
		result.Conditions = append(result.Conditions, api.EnterpriseAuthzConditionResult{RoleID: c.RoleID, BindingID: c.BindingID, Revision: c.Revision, Action: string(c.Action), Effect: c.Effect, ConditionHash: c.ConditionHash, Result: c.Result})
	}
	return result
}

func validActions(actions []string) bool {
	for _, action := range actions {
		if _, ok := authz.LookupAction(authz.Action(action)); !ok {
			return false
		}
	}
	return len(actions) <= len(authz.Catalog())
}

func validCondition(c api.EnterpriseAuthzConditionResult) bool {
	if c.RoleID <= 0 || c.BindingID <= 0 || c.Revision <= 0 || authz.ValidatePermission(authz.Action(c.Action), c.Effect) != nil || !slices.Contains([]string{"matched", "not_matched", "unresolved"}, c.Result) {
		return false
	}
	decoded, err := hex.DecodeString(c.ConditionHash)
	return err == nil && len(decoded) == 32
}

func validObservationID(id string) bool {
	if len(id) != 26 {
		return false
	}
	for _, c := range id {
		if !(c >= 'A' && c <= 'Z' || c >= '2' && c <= '7') {
			return false
		}
	}
	return true
}

func validDecisionObservationID(id string) bool {
	if validObservationID(id) {
		return true
	}
	if len(id) != 64 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validAuthorizationReason(decision, reason string) bool {
	switch decision {
	case "allow":
		return slices.Contains([]string{"native_action", "role_action"}, reason)
	case "deny":
		return slices.Contains([]string{"missing_action", "condition_unresolved", "condition_not_matched", "native_visibility_denied", "actor_inactive"}, reason)
	case "error":
		return slices.Contains([]string{"policy_read_failed", "evidence_persist_failed", "execution_timeout", "execution_canceled", "invalid_execution_context", "context_limit_exceeded"}, reason)
	case "fallback":
		return slices.Contains([]string{"policy_read_failed", "evidence_persist_failed", "execution_timeout"}, reason)
	}
	return false
}

func decisionAuthorization(record *authz_model.DecisionRecord) (string, string, error) {
	mode, decision := record.DecisionMode, record.AuthorizationDecision
	if mode == "" && decision == "" {
		mode, decision = "shadow", "not_enforced"
	}
	if mode == "shadow" {
		if decision != "not_enforced" || record.AuthorizationReason != "" {
			return "", "", ErrPolicyStorage
		}
		return mode, decision, nil
	}
	if mode != "enforce" || !validAuthorizationReason(decision, record.AuthorizationReason) {
		return "", "", ErrPolicyStorage
	}
	if decision == "allow" && record.CandidateDecision != "allow" || (decision == "error" || decision == "fallback") && record.CandidateDecision == "deny" {
		return "", "", ErrPolicyStorage
	}

	if (decision == "deny" || decision == "error") && record.ExecutionStarted || !record.ExecutionStarted && record.NativeOutcome != "unknown" {
		return "", "", ErrPolicyStorage
	}
	return mode, decision, nil
}

func DecisionDTO(record *authz_model.DecisionRecord) (*api.EnterpriseAuthzDecision, error) {
	mode, decision, err := decisionAuthorization(record)
	if err != nil {
		return nil, err
	}
	if action, ok := authz.LookupAction(record.Action); !ok || mode == "enforce" && !action.EnforceSupported {
		return nil, ErrPolicyStorage
	}
	if !validDecisionObservationID(record.ObservationID) || !validObservationID(record.OperationID) || !authz.ValidSource(record.RequestSource) || record.RequestSource == "diagnostic" || !slices.Contains([]string{"allow", "deny", "error"}, record.CandidateDecision) || !slices.Contains([]string{"native_action", "role_action", "missing_action", "condition_unresolved", "condition_not_matched", "native_visibility_denied", "actor_inactive", "policy_read_failed", "snapshot_limit_exceeded", "observation_timeout", "observation_canceled", "invalid_evaluation_context", "unknown_action"}, record.Reason) || !slices.Contains([]string{"success", "denied", "failed", "unknown"}, record.NativeOutcome) || !slices.Contains([]string{"operation", "authorization", "transport", "pre_receive", "migration"}, record.NativeStage) {
		return nil, ErrPolicyStorage
	}
	var missing []string
	if len(record.MissingActions) > authz.MaxSnapshotBytes || json.Unmarshal([]byte(record.MissingActions), &missing) != nil || !validActions(missing) {
		return nil, ErrPolicyStorage
	}
	var snapshot struct {
		api.EnterpriseAuthzDecisionSnapshot
		Credential struct {
			api.EnterpriseAuthzCredentialCeiling
			Actions []string `json:"actions"`
		} `json:"credential"`
		Definitions []api.EnterpriseAuthzRoleRevision    `json:"definitions"`
		Results     []api.EnterpriseAuthzConditionResult `json:"roles"`
	}
	if len(record.SnapshotJSON) > authz.MaxSnapshotBytes || json.Unmarshal([]byte(record.SnapshotJSON), &snapshot) != nil || !authz.ActionInCatalog(snapshot.CatalogVersion, record.Action) || snapshot.NativeMode < 0 || snapshot.NativeMode > 4 || snapshot.PathCount < 0 {
		return nil, ErrPolicyStorage
	}
	if len(snapshot.Features) > len(authz.FeatureCatalog()) {
		return nil, ErrPolicyStorage
	}
	for _, feature := range snapshot.Features {
		metadata, known := authz.LookupFeature(authz.FeatureKey(feature.Key))
		chain, err1 := hex.DecodeString(feature.ChainHash)
		config, err2 := hex.DecodeString(feature.ConfigHash)
		if !known || feature.Version != 1 || feature.ConfigSchemaVersion != metadata.ConfigSchemaVersion || !authz.FeatureState(feature.State).Valid() || feature.State == string(authz.FeatureInherited) || feature.CapabilityKind != metadata.CapabilityKind || !slices.Contains([]string{"default", "global", "org", "repo"}, feature.Source) || err1 != nil || len(chain) != 32 || err2 != nil || len(config) != 32 || feature.ContextCount < 0 || feature.ContextCount > 192 {
			return nil, ErrPolicyStorage
		}
	}
	versionActions := [][]string{missing, snapshot.NativeActions, snapshot.Credential.Actions}
	for _, actions := range versionActions {
		if !validActions(actions) {
			return nil, ErrPolicyStorage
		}
		for _, action := range actions {
			if !authz.ActionInCatalog(snapshot.CatalogVersion, authz.Action(action)) {
				return nil, ErrPolicyStorage
			}
		}
	}
	for _, u := range snapshot.UnitModes {
		valid := false
		for _, typ := range unit.AllRepoUnitTypes {
			if unit.Units[typ].NameKey == u.Key {
				valid = true
				break
			}
		}
		if !valid || u.Mode < 0 || u.Mode > 4 {
			return nil, ErrPolicyStorage
		}
	}
	snapshot.CredentialCeiling = snapshot.Credential.EnterpriseAuthzCredentialCeiling
	for _, r := range snapshot.Definitions {
		if r.ID <= 0 || r.Revision <= 0 {
			return nil, ErrPolicyStorage
		}
	}
	for _, c := range snapshot.Results {
		if !validCondition(c) || !authz.ActionInCatalog(snapshot.CatalogVersion, authz.Action(c.Action)) {
			return nil, ErrPolicyStorage
		}
	}
	snapshot.EnterpriseAuthzDecisionSnapshot.Roles = snapshot.Definitions
	snapshot.Conditions = snapshot.Results
	return &api.EnterpriseAuthzDecision{ID: record.ID, ObservationID: record.ObservationID, OperationID: record.OperationID, ActorID: record.ActorID, RepoID: record.RepoID, OwnerID: record.OwnerID, Action: string(record.Action), RequestSource: record.RequestSource, DecisionMode: mode, AuthorizationDecision: decision, AuthorizationReason: record.AuthorizationReason, ExecutionStarted: record.ExecutionStarted, CandidateDecision: record.CandidateDecision, Reason: record.Reason, MissingActions: missing, NativeOutcome: record.NativeOutcome, NativeStage: record.NativeStage, Snapshot: &snapshot.EnterpriseAuthzDecisionSnapshot, CandidateOnly: true, Created: record.CreatedUnix.AsTime()}, nil
}
