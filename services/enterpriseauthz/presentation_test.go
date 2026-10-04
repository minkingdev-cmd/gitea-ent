// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"crypto/rand"
	"strings"
	"testing"

	authz_model "gitea.dev/models/enterpriseauthz"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"

	"github.com/stretchr/testify/require"
)

func TestPresentationDecisionDTOWhitelist(t *testing.T) {
	secret := "secret token OAuth code callback URL phone email private/path"
	base := authz_model.DecisionRecord{ID: 1, ObservationID: rand.Text(), OperationID: rand.Text(), ActorID: 2, RepoID: 1, OwnerID: 2, Action: authz.Clone, RequestSource: "api", CandidateDecision: "allow", Reason: "native_action", MissingActions: "[]", NativeOutcome: "success", NativeStage: "operation", SnapshotJSON: `{"catalog_version":1,"native_mode":1,"credential":{"read":true,"write":false,"reference":"` + secret + `"},"native_actions":["repo.clone"],"unknown":"` + secret + `","definitions":[{"id":1,"revision":2,"description":"` + secret + `"}],"roles":[]}`}
	dto, err := DecisionDTO(&base)
	require.NoError(t, err)
	encoded, err := json.Marshal(dto)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), secret)
	require.EqualValues(t, 2, dto.Snapshot.Roles[0].Revision)
	for _, change := range []func(*authz_model.DecisionRecord){
		func(r *authz_model.DecisionRecord) { r.Reason = secret }, func(r *authz_model.DecisionRecord) { r.NativeStage = secret }, func(r *authz_model.DecisionRecord) { r.MissingActions = `["` + secret + `"]` }, func(r *authz_model.DecisionRecord) { r.ObservationID = secret },
		func(r *authz_model.DecisionRecord) {
			r.SnapshotJSON = `{"catalog_version":1,"native_actions":["` + secret + `"]}`
		}, func(r *authz_model.DecisionRecord) {
			r.SnapshotJSON = `{"catalog_version":1,"unit_modes":[{"key":"` + secret + `","mode":1}]}`
		}, func(r *authz_model.DecisionRecord) {
			r.SnapshotJSON = `{"catalog_version":1,"roles":[{"role_id":1,"binding_id":1,"revision":1,"action":"repo.clone","effect":"allow","condition_hash":"` + strings.Repeat("a", 64) + `","result":"` + secret + `"}]}`
		},
	} {
		record := base
		change(&record)
		_, err := DecisionDTO(&record)
		require.ErrorIs(t, err, ErrPolicyStorage)
	}
}

func TestPresentationDecisionDTOProtocolObservationID(t *testing.T) {
	record := authz_model.DecisionRecord{ID: 1, ObservationID: strings.Repeat("ab", 32), OperationID: rand.Text(), ActorID: 2, RepoID: 1, OwnerID: 2, Action: authz.PushBranch, RequestSource: "ssh", CandidateDecision: "allow", Reason: "native_action", MissingActions: "[]", NativeOutcome: "success", NativeStage: "transport", SnapshotJSON: `{"catalog_version":1,"native_mode":1,"native_actions":["repo.push_branch"]}`}
	dto, err := DecisionDTO(&record)
	require.NoError(t, err)
	require.Equal(t, record.ObservationID, dto.ObservationID)
	record.OperationID = strings.Repeat("ab", 32)
	_, err = DecisionDTO(&record)
	require.ErrorIs(t, err, ErrPolicyStorage)
}

func TestPresentationRoleDTORejectsCorruptConditions(t *testing.T) {
	role := &Role{Definition: &authz_model.RoleDefinition{ID: 1, ScopeType: authz_model.ScopeSystem, Name: "<script>unsafe</script>", Revision: 2}}
	dto, err := RoleDTO(role)
	require.NoError(t, err)
	require.Equal(t, "<script>unsafe</script>", dto.Name)
	require.Empty(t, dto.Permissions)
	_, normalized, hash, err := authz.ParseCondition([]byte(`{"branch_pattern":["release/*"]}`))
	require.NoError(t, err)
	role.Permissions = []authz_model.RolePermission{{Action: authz.ReadCode, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}}
	dto, err = RoleDTO(role)
	require.NoError(t, err)
	require.Equal(t, []string{"release/*"}, dto.Permissions[0].Condition.BranchPattern)
	role.Permissions[0].ConditionHash = "bad"
	_, err = RoleDTO(role)
	require.ErrorIs(t, err, ErrPolicyStorage)
}

func TestPresentationExplanationIsCandidateOnly(t *testing.T) {
	dto := ExplanationDTO([]authz.Action{authz.ReadCode}, []authz.Action{authz.CreateBranch}, "role_action", []DiagnosticRole{{ID: 1, Revision: 2}}, []DiagnosticBinding{{ID: 3}}, []DiagnosticCondition{{RoleID: 1, BindingID: 3, Revision: 2, Action: authz.CreateBranch, Effect: "allow", Result: "matched"}})
	require.True(t, dto.CandidateOnly)
	require.Equal(t, []string{"repo.read_code"}, dto.NativeActions)
	require.Equal(t, []string{"repo.create_branch"}, dto.RoleActions)
	require.EqualValues(t, 2, dto.Roles[0].Revision)
	require.Equal(t, "matched", dto.Conditions[0].Result)
	require.Equal(t, []string{}, ActionsDTO(nil))
}

func TestPresentationDecisionCatalogVersions(t *testing.T) {
	for _, tc := range []struct {
		name, snapshot string
		action         authz.Action
		valid          bool
	}{
		{"v1", `{"catalog_version":1,"native_actions":["repo.clone"]}`, authz.Clone, true},
		{"v2", `{"catalog_version":2,"native_actions":["repo.manage_access"]}`, authz.Action("repo.manage_access"), true},
		{"future", `{"catalog_version":3,"native_actions":["repo.clone"]}`, authz.Clone, false},
		{"missing", `{"native_actions":["repo.clone"]}`, authz.Clone, false},
		{"v1 new action", `{"catalog_version":1,"native_actions":["repo.manage_access"]}`, authz.Clone, false},
		{"v1 new record action", `{"catalog_version":1,"native_actions":[]}`, authz.Action("repo.manage_access"), false},
		{"v1 new credential action", `{"catalog_version":1,"credential":{"actions":["repo.manage_access"]}}`, authz.Clone, false},
		{"v1 new condition action", `{"catalog_version":1,"roles":[{"role_id":1,"binding_id":1,"revision":1,"action":"repo.manage_access","effect":"allow","condition_hash":"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","result":"matched"}]}`, authz.Clone, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &authz_model.DecisionRecord{ObservationID: rand.Text(), OperationID: rand.Text(), Action: tc.action, RequestSource: "api", CandidateDecision: "allow", Reason: "native_action", MissingActions: "[]", NativeOutcome: "success", NativeStage: "operation", SnapshotJSON: tc.snapshot}
			_, err := DecisionDTO(r)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrPolicyStorage)
			}
		})
	}
}

func TestPresentationDecisionAuthorizationEvidence(t *testing.T) {
	base := authz_model.DecisionRecord{ObservationID: rand.Text(), OperationID: rand.Text(), Action: authz.Delete, RequestSource: "api", CandidateDecision: "deny", Reason: "missing_action", MissingActions: "[]", NativeOutcome: "unknown", NativeStage: "authorization", SnapshotJSON: `{"catalog_version":2}`}
	for _, tc := range []struct {
		name, mode, decision, reason, outcome string
		started, valid                        bool
	}{
		{"legacy", "", "", "", "success", false, true},
		{"shadow", "shadow", "not_enforced", "", "denied", false, true},
		{"denied", "enforce", "deny", "missing_action", "unknown", false, true},
		{"unresolved", "enforce", "deny", "condition_unresolved", "unknown", false, true},
		{"not matched", "enforce", "deny", "condition_not_matched", "unknown", false, true},
		{"visibility", "enforce", "deny", "native_visibility_denied", "unknown", false, true},
		{"inactive", "enforce", "deny", "actor_inactive", "unknown", false, true},
		{"invalid context", "enforce", "error", "invalid_execution_context", "unknown", false, true},
		{"canceled", "enforce", "error", "execution_canceled", "unknown", false, true},
		{"context limit", "enforce", "error", "context_limit_exceeded", "unknown", false, true},
		{"evidence unavailable", "enforce", "fallback", "evidence_persist_failed", "unknown", false, true},
		{"budget expired", "enforce", "fallback", "execution_timeout", "unknown", true, true},

		{"error", "enforce", "error", "policy_read_failed", "unknown", false, true},
		{"allowed pending", "enforce", "allow", "role_action", "unknown", false, true},
		{"allowed running", "enforce", "allow", "native_action", "unknown", true, true},
		{"allowed failed", "enforce", "allow", "role_action", "failed", true, true},
		{"fallback", "enforce", "fallback", "policy_read_failed", "success", true, true},
		{"unknown mode", "future", "allow", "native_action", "unknown", false, false},
		{"unknown decision", "enforce", "success", "native_action", "unknown", false, false},
		{"unsafe reason", "enforce", "deny", "<script>secret</script>", "unknown", false, false},
		{"enforce not enforced", "enforce", "not_enforced", "", "unknown", false, false},
		{"shadow allow", "shadow", "allow", "native_action", "success", true, false},
		{"partial legacy", "", "not_enforced", "", "unknown", false, false},
		{"denied executed", "enforce", "deny", "missing_action", "unknown", true, false},
		{"error native denied", "enforce", "error", "policy_read_failed", "denied", false, false},
		{"allow unstarted success", "enforce", "allow", "role_action", "success", false, false},
		{"fallback unstarted failed", "enforce", "fallback", "policy_read_failed", "failed", false, false},
		{"shadow reason", "shadow", "not_enforced", "native_action", "success", false, false},
		{"missing enforcement reason", "enforce", "deny", "", "unknown", false, false},
		{"allow denial reason", "enforce", "allow", "missing_action", "unknown", false, false},
		{"deny allowance reason", "enforce", "deny", "native_action", "unknown", false, false},
		{"error allowance reason", "enforce", "error", "role_action", "unknown", false, false},
		{"fallback denial reason", "enforce", "fallback", "missing_action", "unknown", false, false},
		{"fallback canceled", "enforce", "fallback", "execution_canceled", "unknown", false, false},
		{"fallback invalid context", "enforce", "fallback", "invalid_execution_context", "unknown", false, false},
		{"fallback context limit", "enforce", "fallback", "context_limit_exceeded", "unknown", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			record := base
			if tc.decision == "allow" || tc.decision == "error" || tc.decision == "fallback" {
				record.CandidateDecision = "allow"
			}
			record.DecisionMode, record.AuthorizationDecision, record.AuthorizationReason, record.ExecutionStarted, record.NativeOutcome = tc.mode, tc.decision, tc.reason, tc.started, tc.outcome
			dto, err := DecisionDTO(&record)
			if !tc.valid {
				require.ErrorIs(t, err, ErrPolicyStorage)
				return
			}
			require.NoError(t, err)
			encoded, err := json.Marshal(dto)
			require.NoError(t, err)
			var fields map[string]any
			require.NoError(t, json.Unmarshal(encoded, &fields))
			mode, decision := tc.mode, tc.decision
			if tc.name == "legacy" {
				mode, decision = "shadow", "not_enforced"
			}
			require.Equal(t, mode, fields["decision_mode"])
			require.Equal(t, decision, fields["authorization_decision"])
			require.Equal(t, tc.reason, fields["authorization_reason"])
			require.Equal(t, tc.started, fields["execution_started"])
			require.True(t, dto.CandidateOnly)
			require.False(t, dto.SafetyGuardsEvaluated)
		})
	}
}

func TestPresentationDecisionRejectsUnsupportedEnforcement(t *testing.T) {
	record := &authz_model.DecisionRecord{ObservationID: rand.Text(), OperationID: rand.Text(), Action: authz.Clone, RequestSource: "api", DecisionMode: "enforce", AuthorizationDecision: "allow", AuthorizationReason: "native_action", CandidateDecision: "allow", Reason: "native_action", MissingActions: "[]", NativeOutcome: "unknown", NativeStage: "authorization", SnapshotJSON: `{"catalog_version":2}`}
	_, err := DecisionDTO(record)
	require.ErrorIs(t, err, ErrPolicyStorage)
}

func TestPresentationDecisionAuthorizationPrecedence(t *testing.T) {
	base := authz_model.DecisionRecord{ObservationID: rand.Text(), OperationID: rand.Text(), Action: authz.Delete, RequestSource: "api", DecisionMode: "enforce", MissingActions: "[]", NativeOutcome: "unknown", NativeStage: "authorization", SnapshotJSON: `{"catalog_version":2}`}
	for _, tc := range []struct {
		candidate, decision, reason string
		valid                       bool
	}{
		{"allow", "allow", "native_action", true},
		{"deny", "allow", "role_action", false},
		{"error", "allow", "native_action", false},
		{"allow", "deny", "missing_action", true},
		{"error", "deny", "missing_action", true},
		{"deny", "error", "policy_read_failed", false},
		{"deny", "fallback", "policy_read_failed", false},
		{"allow", "error", "policy_read_failed", true},
		{"allow", "fallback", "policy_read_failed", true},
	} {
		t.Run(tc.candidate+"/"+tc.decision, func(t *testing.T) {
			record := base
			record.CandidateDecision, record.AuthorizationDecision, record.AuthorizationReason, record.Reason = tc.candidate, tc.decision, tc.reason, "native_action"
			_, err := DecisionDTO(&record)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrPolicyStorage)
			}
		})
	}
}
