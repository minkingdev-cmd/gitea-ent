// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"os"
	"slices"
	"strings"
	"testing"

	"gitea.dev/modules/json"

	"github.com/stretchr/testify/require"
)

func TestMergeGateEvaluation(t *testing.T) {
	facts := []MergeGateFact{
		{Code: "required_check", Source: "feature", Context: "security/gitleaks", State: "missing"},
		{Code: "required_approvals", Source: "native", State: "failed"},
		{Code: "sensitive_path_approval", Source: "path", ReferenceID: 12, State: "passed"},
	}
	input := MergeGateInput{Mode: "enforce", Phase: "admission", Facts: facts}
	result := EvaluateMergeGate(input)
	require.Equal(t, "deny", result.CandidateDecision)
	require.Equal(t, "deny", result.AdmissionDecision)
	require.Len(t, result.BlockingReasons, 2)
	require.Equal(t, "required_approvals", result.BlockingReasons[0].Code)
	require.Equal(t, "not_started", result.ExecutionState)

	input.Bypass = MergeGateBypass{Requested: true, Authorized: true, NativeAllowed: true, Reason: "Emergency rollback", Categories: []string{"required_check"}}
	result = EvaluateMergeGate(input)
	require.Equal(t, "deny", result.CandidateDecision)
	require.Len(t, result.BypassedReasons, 1)
	require.Len(t, result.BlockingReasons, 1)
	input.Bypass.Categories = append(input.Bypass.Categories, "required_approvals")
	result = EvaluateMergeGate(input)
	require.Equal(t, "bypass", result.AdmissionDecision)
	require.True(t, result.BypassUsed)
	input.Facts = append(slices.Clone(facts), MergeGateFact{Code: "feature_disabled", Source: "feature", State: "failed"})
	require.Equal(t, "deny", EvaluateMergeGate(input).AdmissionDecision)
	input.Facts = append(slices.Clone(facts), MergeGateFact{Code: "policy_read_failed", Source: "policy", State: "error"})
	require.Equal(t, "error", EvaluateMergeGate(input).AdmissionDecision)

	input.Facts = []MergeGateFact{{Code: "required_check", Source: "native", State: "passed"}}
	result = EvaluateMergeGate(input)
	require.Equal(t, "allow", result.AdmissionDecision)
	require.False(t, result.BypassUsed)
	require.True(t, result.BypassRequested)

	for _, phase := range []string{"schedule", "auto_admission"} {
		input.Phase = phase
		require.Equal(t, "deny", EvaluateMergeGate(input).CandidateDecision)
	}
	input.Bypass.Requested = false
	input.Phase = "schedule"
	input.Facts = facts
	result = EvaluateMergeGate(input)
	require.Equal(t, "deny", result.CandidateDecision)
	require.Equal(t, "not_admitted", result.AdmissionDecision)
	require.True(t, result.Waiting)
	input.Facts = append(slices.Clone(facts), MergeGateFact{Code: "missing_action", Source: "action", State: "failed"})
	require.False(t, EvaluateMergeGate(input).Waiting)

	input.Mode, input.Phase = "shadow", "preview"
	result = EvaluateMergeGate(input)
	require.Equal(t, "not_enforced", result.AdmissionDecision)
	require.True(t, result.PreviewOnly)
	input.Mode = "disabled"
	require.Equal(t, "not_evaluated", EvaluateMergeGate(input).CandidateDecision)
}

func TestMergeGateMandatoryAndModes(t *testing.T) {
	for _, descriptor := range MergeGateReasonCatalog() {
		for _, mode := range []string{"disabled", "shadow", "enforce"} {
			for _, phase := range []string{"preview", "schedule", "admission", "auto_admission", "manual_recognition"} {
				input := MergeGateInput{Mode: mode, Phase: phase, Facts: []MergeGateFact{{Code: descriptor.Code, State: "failed"}}, Bypass: MergeGateBypass{Requested: true, Authorized: true, NativeAllowed: true, Reason: "rollback", Categories: mergeGateBypassCategories}}
				result := EvaluateMergeGate(input)
				switch mode {
				case "disabled":
					require.Equal(t, "not_evaluated", result.CandidateDecision)
				case "shadow":
					require.Equal(t, "not_enforced", result.AdmissionDecision)
				case "enforce":
					if descriptor.BypassCategory == "" || phase == "schedule" || phase == "auto_admission" {
						require.Equal(t, "deny", result.CandidateDecision)
					} else {
						require.Equal(t, "bypass", result.CandidateDecision)
					}
					if phase == "preview" {
						require.Equal(t, "not_admitted", result.AdmissionDecision)
					}
				}
			}
		}
	}
	for _, bypass := range []MergeGateBypass{
		{Requested: true, Authorized: false, NativeAllowed: true, Reason: "rollback", Categories: []string{"required_check"}},
		{Requested: true, Authorized: true, NativeAllowed: false, Reason: "rollback", Categories: []string{"required_check"}},
	} {
		result := EvaluateMergeGate(MergeGateInput{Mode: "enforce", Phase: "admission", Bypass: bypass, Facts: []MergeGateFact{{Code: "required_check", State: "failure"}}})
		require.Equal(t, "deny", result.AdmissionDecision)
	}
	_, err := MarshalMergeGateSnapshot(strings.Repeat("x", MaxSnapshotBytes))
	require.Error(t, err)
}

func TestProtectedPathLimitsAndMatches(t *testing.T) {
	valid := ProtectedPathConfig{PathPattern: "k8s/**", BranchPattern: "release/*", RequiredRoleID: 3, Enabled: true}
	for _, change := range []func(*ProtectedPathConfig){
		func(c *ProtectedPathConfig) { c.PathPattern = strings.Repeat("x", 257) },
		func(c *ProtectedPathConfig) { c.BranchPattern = "bad\nref" },
		func(c *ProtectedPathConfig) { c.CheckContexts = []string{strings.Repeat("x", 129)} },
		func(c *ProtectedPathConfig) { c.CheckContexts = make([]string, 65) },
	} {
		invalid := valid
		change(&invalid)
		raw, err := json.Marshal(invalid)
		require.NoError(t, err)
		_, _, err = ParseProtectedPathConfig(raw)
		require.Error(t, err)
	}
	result, paths := valid.Match("release/v1", []string{"k8s/a", "src/a", "k8s/a"}, true)
	require.Equal(t, Matched, result)
	require.Equal(t, []string{"k8s/a"}, paths)
	for _, paths := range [][]string{{"../k8s/a"}, {"k8s/bad\nname"}, make([]string, MaxContextPaths+1)} {
		result, _ := valid.Match("release/v1", paths, true)
		require.Equal(t, Unresolved, result)
	}
	result, _ = valid.Match("main", []string{"k8s/a"}, true)
	require.Equal(t, NotMatched, result)
	result, _ = valid.Match("release/v1", []string{"k8s/a"}, false)
	require.Equal(t, Unresolved, result)
}

func TestMergeGateRejectsUnknownAndInvalidFacts(t *testing.T) {
	for _, fact := range []MergeGateFact{
		{Code: "unknown", State: "passed"},
		{Code: "required_check", State: "unknown"},
		{Code: "required_check", State: "error"},
		{Code: "paths_incomplete", State: "error"},
		{Code: "required_check", State: "passed", Context: strings.Repeat("x", 129)},
		{Code: "required_check", State: "passed", ReferenceID: -1},
	} {
		result := EvaluateMergeGate(MergeGateInput{Mode: "enforce", Phase: "admission", Facts: []MergeGateFact{fact}})
		require.NotEqual(t, "allow", result.AdmissionDecision)
		require.NotEqual(t, "bypass", result.AdmissionDecision)
	}
	for _, input := range []MergeGateInput{
		{Mode: "typo", Phase: "admission"},
		{Mode: "enforce", Phase: "typo"},
		{Mode: "enforce", Phase: "admission", Facts: make([]MergeGateFact, MaxMergeGateFacts+1)},
	} {
		require.Equal(t, "error", EvaluateMergeGate(input).CandidateDecision)
	}
}

func TestMergeGateBypassValidation(t *testing.T) {
	longReason := "  " + strings.Repeat("x", 1024) + "  "
	canonicalLimit, err := NormalizeMergeGateBypass(MergeGateBypass{Requested: true, Reason: longReason, Categories: []string{"required_check"}})
	require.NoError(t, err)
	require.Len(t, canonicalLimit.Reason, 1024, "the byte limit applies after trimming")
	for _, bypass := range []MergeGateBypass{
		{Requested: true, Reason: " ", Categories: []string{"required_check"}},
		{Requested: true, Reason: strings.Repeat("x", 1025), Categories: []string{"required_check"}},
		{Requested: true, Reason: "bad\nreason", Categories: []string{"required_check"}},
		{Requested: true, Reason: "valid", Categories: []string{"feature_disabled"}},
		{Requested: true, Reason: "valid"},
	} {
		_, err := NormalizeMergeGateBypass(bypass)
		require.Error(t, err)
	}
	input := MergeGateBypass{Requested: true, Reason: "  rollback  ", Categories: []string{"required_check", "required_check", "required_approvals"}}
	canonical, err := NormalizeMergeGateBypass(input)
	require.NoError(t, err)
	require.Equal(t, "rollback", canonical.Reason)
	require.Equal(t, []string{"required_approvals", "required_check"}, canonical.Categories)
}

func TestProtectedPathConfig(t *testing.T) {
	config, canonical, err := ParseProtectedPathConfig([]byte(`{"path_pattern":"k8s/**","required_role_id":3,"check_contexts":["z","a","a"]}`))
	require.NoError(t, err)
	require.True(t, config.Enabled)
	require.Equal(t, []string{"a", "z"}, config.CheckContexts)
	_, again, err := ParseProtectedPathConfig([]byte(canonical))
	require.NoError(t, err)
	require.Equal(t, canonical, again)
	for _, raw := range []string{
		`{}`, `null`, `{"path_pattern":"k8s/**","required_role_id":0}`,
		`{"path_pattern":"../secret","required_role_id":1}`,
		`{"path_pattern":"k8s/**","required_role_id":1,"token":"secret"}`,
		`{"path_pattern":"k8s/**","path_pattern":"**","required_role_id":1}`,
		`{"path_pattern":"k8s/**","required_role_id":1,"check_contexts":null}`,
		`{"path_pattern":"k8s/**","required_role_id":1,"enabled":null}`,
		`{"path_pattern":"k8s/**","required_role_id":1,"check_contexts":[""]}`,
		`{"path_pattern":"[","required_role_id":1}`,
	} {
		_, _, err := ParseProtectedPathConfig([]byte(raw))
		require.Error(t, err, raw)
	}
}

func TestMergeGateRequiredContexts(t *testing.T) {
	statuses := []MergeGateStatus{
		{ID: 1, RepoID: 7, SHA: "head", Context: "security/gitleaks", State: "success"},
		{ID: 3, RepoID: 7, SHA: "head", Context: "security/gitleaks", State: "failure"},
		{ID: 4, RepoID: 8, SHA: "head", Context: "security/gitleaks", State: "success"},
		{ID: 5, RepoID: 7, SHA: "old", Context: "security/gitleaks", State: "success"},
		{ID: 6, RepoID: 7, SHA: "head", Context: "ci/build", State: "success"},
	}
	requirements := []MergeGateContext{
		{Context: "security/gitleaks", Source: "feature"},
		{Context: "security/*", Source: "native", Pattern: true},
		{Context: "ci/*", Source: "path"},
		{Context: "ci/build", Source: "feature"},
	}
	facts := EvaluateMergeGateContexts(7, "head", requirements, statuses)
	require.Len(t, facts, 4)
	for _, fact := range facts {
		switch fact.Context {
		case "security/gitleaks", "security/*":
			require.Equal(t, "failure", fact.State)
		case "ci/*":
			require.Equal(t, "missing", fact.State)
		case "ci/build":
			require.Equal(t, "passed", fact.State)
		}
	}
}

func TestMergeGateErrorIdentityAndContextDeduplication(t *testing.T) {
	result := EvaluateMergeGate(MergeGateInput{Mode: "enforce", Phase: "admission", Facts: []MergeGateFact{{Code: "policy_read_failed", Source: "policy", State: "error"}}})
	require.Equal(t, "error", result.AdmissionDecision)
	require.Equal(t, "policy_read_failed", result.BlockingReasons[0].Code)
	require.Len(t, EvaluateMergeGateContexts(1, "head", []MergeGateContext{{Context: "ci", Source: "native"}, {Context: "ci", Source: "native"}, {Context: "ci", Source: "feature"}}, nil), 2)
	invalid := ProtectedPathConfig{Enabled: true, PathPattern: "[", RequiredRoleID: 1}
	match, _ := invalid.Match("main", []string{"a"}, true)
	require.Equal(t, Unresolved, match)
}

func TestMergeGatePatternErrorsCannotBeBypassed(t *testing.T) {
	for _, first := range []string{"failure", "pending", "unexpected"} {
		facts := EvaluateMergeGateContexts(1, "head", []MergeGateContext{{Context: "security/*", Source: "native", Pattern: true}}, []MergeGateStatus{
			{ID: 1, RepoID: 1, SHA: "head", Context: "security/a", State: first},
			{ID: 2, RepoID: 1, SHA: "head", Context: "security/z", State: "error"},
		})
		result := EvaluateMergeGate(MergeGateInput{Mode: "enforce", Phase: "admission", Facts: facts, Bypass: MergeGateBypass{Requested: true, Authorized: true, NativeAllowed: true, Reason: "rollback", Categories: []string{"required_check"}}})
		require.Equal(t, "error", result.AdmissionDecision, first)
		require.False(t, result.BypassUsed)
	}
}

func TestMergeGatePreviewNeverUsesBypass(t *testing.T) {
	result := EvaluateMergeGate(MergeGateInput{Mode: "enforce", Phase: "preview", Facts: []MergeGateFact{{Code: "required_check", State: "missing"}}, Bypass: MergeGateBypass{Requested: true, Authorized: true, NativeAllowed: true, Reason: "rollback", Categories: []string{"required_check"}}})
	require.Equal(t, "bypass", result.CandidateDecision)
	require.Equal(t, "not_admitted", result.AdmissionDecision)
	require.False(t, result.BypassUsed)
}

func TestMergeGateSameNameWorkflowIdentities(t *testing.T) {
	for _, pattern := range []bool{false, true} {
		statuses := []MergeGateStatus{
			{ID: 1, RepoID: 1, SHA: "head", Context: "shared", ContextHash: "workflow-a", State: "success"},
			{ID: 2, RepoID: 1, SHA: "head", Context: "shared", ContextHash: "workflow-a", State: "failure"},
			{ID: 3, RepoID: 1, SHA: "head", Context: "shared", ContextHash: "workflow-b", State: "success"},
		}
		source := "feature"
		if pattern {
			source = "native"
		}
		requirements := []MergeGateContext{{Context: "shared", Source: source, Pattern: pattern}}
		facts := EvaluateMergeGateContexts(1, "head", requirements, statuses)
		require.Equal(t, "failure", facts[0].State)
		statuses[1].State = "error"
		facts = EvaluateMergeGateContexts(1, "head", requirements, statuses)
		require.Equal(t, "error", facts[0].State)
		statuses = append(statuses, MergeGateStatus{ID: 4, RepoID: 1, SHA: "head", Context: "shared", ContextHash: "workflow-a", State: "success"})
		facts = EvaluateMergeGateContexts(1, "head", requirements, statuses)
		require.Equal(t, "passed", facts[0].State)
		statuses[3].State, statuses[2].State = "pending", "failure"
		facts = EvaluateMergeGateContexts(1, "head", requirements, statuses)
		require.Equal(t, "failure", facts[0].State, "a pending identity cannot hide another identity's failure")
	}
}

func TestMergeGateKnownWarningIsFailure(t *testing.T) {
	facts := EvaluateMergeGateContexts(1, "head", []MergeGateContext{{Context: "check", Source: "native", Pattern: true}}, []MergeGateStatus{{ID: 1, RepoID: 1, SHA: "head", Context: "check", State: "warning"}})
	require.Equal(t, "failure", facts[0].State)
	result := EvaluateMergeGate(MergeGateInput{Mode: "enforce", Phase: "admission", Facts: facts})
	require.Equal(t, "deny", result.CandidateDecision)
}

func TestMergeGateSkippedIsSourceSpecific(t *testing.T) {
	requirements := []MergeGateContext{
		{Context: "ci/*", Source: "native", Pattern: true},
		{Context: "ci/build", Source: "feature"},
		{Context: "ci/build", Source: "path", ReferenceID: 4},
	}
	statuses := []MergeGateStatus{{ID: 1, RepoID: 7, SHA: "head", Context: "ci/build", State: "skipped"}}
	facts := EvaluateMergeGateContexts(7, "head", requirements, statuses)
	require.Equal(t, "passed", facts[0].State)
	for _, fact := range facts[1:] {
		require.Equal(t, "failure", fact.State)
	}
	statuses = append(statuses, MergeGateStatus{ID: 2, RepoID: 7, SHA: "head", Context: "ci/build", State: "success"})
	for _, fact := range EvaluateMergeGateContexts(7, "head", requirements, statuses) {
		require.Equal(t, "passed", fact.State)
	}
}

func TestMergeGateReasonCatalogHasEnglishLocale(t *testing.T) {
	raw, err := os.ReadFile("../../options/locale/locale_en-US.json")
	require.NoError(t, err)
	var labels map[string]string
	require.NoError(t, json.Unmarshal(raw, &labels))
	for _, entry := range MergeGateReasonCatalog() {
		require.NotEmpty(t, labels[entry.MessageKey], entry.Code)
	}
}

func TestMergeGateCheckingCannotPassNativeQueueEligibility(t *testing.T) {
	result := EvaluateMergeGate(MergeGateInput{Mode: "enforce", Phase: "schedule", Facts: []MergeGateFact{{Code: "checking", Source: "native", State: "failed"}}})
	require.Equal(t, "deny", result.CandidateDecision)
	require.False(t, result.Waiting)
	require.Equal(t, "not_admitted", result.AdmissionDecision)
}
