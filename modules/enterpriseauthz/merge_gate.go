// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"cmp"
	"errors"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"gitea.dev/modules/glob"
	"gitea.dev/modules/json"
)

const (
	MergeGateSnapshotVersion = 1
	MaxMergeGateFacts        = 1024
	MaxProtectedPathRules    = 256
)

type MergeGateReasonDescriptor struct {
	Code           string `json:"code"`
	MessageKey     string `json:"message_key"`
	Tone           string `json:"tone"`
	BypassCategory string `json:"bypass_category,omitempty"`
	Waitable       bool   `json:"waitable"`
}

func MergeGateReasonCatalog() []MergeGateReasonDescriptor {
	var result []MergeGateReasonDescriptor
	for _, code := range []string{
		"actor_invalid", "credential_denied", "missing_action", "feature_disabled", "native_permission_denied",
		"closed", "merged", "draft", "conflict", "checking", "dependency", "unresolved_conversation",
		"protected_files", "outdated_branch", "signing_required", "merge_style_denied",
		"required_approvals", "rejected_review", "official_review_request", "codeowners_review",
		"required_check", "sensitive_path_approval", "sensitive_path_check",
		"required_contexts_empty", "feature_native_pending", "paths_incomplete", "policy_unresolved", "policy_read_failed", "facts_read_failed",
		"snapshot_too_large", "rules_limit_exceeded", "state_changed", "audit_unavailable", "bypass_invalid", "auto_bypass_denied",
	} {
		category := ""
		if slices.Contains(mergeGateBypassCategories, code) {
			category = code
		}
		result = append(result, MergeGateReasonDescriptor{
			Code: code, MessageKey: "repo.merge_gate.reason." + code, Tone: "warning", BypassCategory: category,
			Waitable: category != "" || code == "unresolved_conversation",
		})
	}
	return result
}

var mergeGateBypassCategories = []string{"required_approvals", "rejected_review", "official_review_request", "codeowners_review", "required_check", "sensitive_path_approval", "sensitive_path_check"}

type MergeGateFact struct {
	Code        string `json:"code"`
	Source      string `json:"source"`
	Context     string `json:"context,omitempty"`
	ReferenceID int64  `json:"reference_id,omitempty"`
	State       string `json:"state"`
}

type MergeGateBypass struct {
	Requested     bool     `json:"requested"`
	Authorized    bool     `json:"authorized"`
	NativeAllowed bool     `json:"native_allowed"`
	Reason        string   `json:"reason,omitempty"`
	Categories    []string `json:"categories,omitempty"`
}

func NormalizeMergeGateBypass(input MergeGateBypass) (MergeGateBypass, error) {
	if !input.Requested {
		return MergeGateBypass{}, nil
	}
	reason := strings.TrimSpace(input.Reason)
	if !utf8.ValidString(input.Reason) || strings.ContainsFunc(input.Reason, unicode.IsControl) || len(reason) > 1024 || reason == "" || len(input.Categories) == 0 || len(input.Categories) > 7 {
		return MergeGateBypass{}, errors.New("invalid_merge_gate_bypass")
	}
	for _, category := range input.Categories {
		if !slices.Contains(mergeGateBypassCategories, category) {
			return MergeGateBypass{}, errors.New("invalid_merge_gate_bypass")
		}
	}
	input.Reason = reason
	input.Categories = slices.Clone(input.Categories)
	slices.Sort(input.Categories)
	input.Categories = slices.Compact(input.Categories)
	return input, nil
}

type MergeGateInput struct {
	Mode   string          `json:"mode"`
	Phase  string          `json:"phase"`
	Facts  []MergeGateFact `json:"facts"`
	Bypass MergeGateBypass `json:"bypass"`
}

type MergeGateResult struct {
	CandidateDecision string          `json:"candidate_decision"`
	AdmissionDecision string          `json:"admission_decision"`
	ExecutionState    string          `json:"execution_state"`
	BlockingReasons   []MergeGateFact `json:"blocking_reasons"`
	BypassedReasons   []MergeGateFact `json:"bypassed_reasons"`
	BypassRequested   bool            `json:"bypass_requested"`
	BypassUsed        bool            `json:"bypass_used"`
	PreviewOnly       bool            `json:"preview_only"`
	Waiting           bool            `json:"waiting"`
}

func EvaluateMergeGate(input MergeGateInput) MergeGateResult {
	result := MergeGateResult{CandidateDecision: "allow", AdmissionDecision: "allow", ExecutionState: "not_started", PreviewOnly: input.Phase == "preview", BypassRequested: input.Bypass.Requested}
	if input.Mode == "disabled" {
		result.CandidateDecision, result.AdmissionDecision = "not_evaluated", "not_enforced"
		return result
	}
	descriptors := map[string]MergeGateReasonDescriptor{}
	for _, entry := range MergeGateReasonCatalog() {
		descriptors[entry.Code] = entry
	}
	hasError := false
	if !slices.Contains([]string{"shadow", "enforce"}, input.Mode) || !slices.Contains([]string{"preview", "schedule", "admission", "auto_admission", "manual_recognition"}, input.Phase) || len(input.Facts) > MaxMergeGateFacts {
		input.Facts = []MergeGateFact{{Code: "facts_read_failed", Source: "gate", State: "error"}}
	}
	bypass, err := NormalizeMergeGateBypass(input.Bypass)
	if err != nil {
		input.Facts = append(slices.Clone(input.Facts), MergeGateFact{Code: "bypass_invalid", Source: "gate", State: "failed"})
	}
	if input.Bypass.Requested && (input.Phase == "schedule" || input.Phase == "auto_admission") {
		input.Facts = append(slices.Clone(input.Facts), MergeGateFact{Code: "auto_bypass_denied", Source: "gate", State: "failed"})
	}
	canBypass := err == nil && bypass.Requested && bypass.Authorized && bypass.NativeAllowed && input.Phase != "schedule" && input.Phase != "auto_admission"
	if bypass.Requested && (!bypass.Authorized || !bypass.NativeAllowed) {
		input.Facts = append(slices.Clone(input.Facts), MergeGateFact{Code: "bypass_invalid", Source: "gate", State: "failed"})
	}
	for _, fact := range input.Facts {
		descriptor, known := descriptors[fact.Code]
		if !known || fact.ReferenceID < 0 || len(fact.Context) > 128 || !utf8.ValidString(fact.Context) || strings.ContainsFunc(fact.Context, unicode.IsControl) || len(fact.Source) > 32 || !utf8.ValidString(fact.Source) || strings.ContainsFunc(fact.Source, unicode.IsControl) || !slices.Contains([]string{"passed", "failed", "missing", "pending", "failure", "error", "unknown"}, fact.State) {
			hasError = true
			result.BlockingReasons = append(result.BlockingReasons, MergeGateFact{Code: "facts_read_failed", Source: "gate", State: "error"})
			continue
		}
		if fact.State == "error" || fact.State == "unknown" {
			hasError = true
			result.BlockingReasons = append(result.BlockingReasons, fact)
			continue
		}
		if fact.State == "passed" {
			continue
		}
		if canBypass && descriptor.BypassCategory != "" && slices.Contains(bypass.Categories, descriptor.BypassCategory) {
			result.BypassedReasons = append(result.BypassedReasons, fact)
		} else {
			result.BlockingReasons = append(result.BlockingReasons, fact)
		}
	}
	compare := func(a, b MergeGateFact) int {
		if n := cmp.Compare(a.Code, b.Code); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Source, b.Source); n != 0 {
			return n
		}
		if n := cmp.Compare(a.ReferenceID, b.ReferenceID); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Context, b.Context); n != 0 {
			return n
		}
		return cmp.Compare(a.State, b.State)
	}
	slices.SortFunc(result.BlockingReasons, compare)
	slices.SortFunc(result.BypassedReasons, compare)
	result.BlockingReasons = slices.Compact(result.BlockingReasons)
	result.BypassedReasons = slices.Compact(result.BypassedReasons)
	switch {
	case hasError:
		result.CandidateDecision = "error"
	case len(result.BlockingReasons) != 0:
		result.CandidateDecision = "deny"
	case len(result.BypassedReasons) != 0:
		result.CandidateDecision, result.BypassUsed = "bypass", true
	}
	result.AdmissionDecision = result.CandidateDecision
	if input.Phase == "schedule" && result.CandidateDecision == "deny" {
		result.Waiting = true
		for _, fact := range result.BlockingReasons {
			result.Waiting = result.Waiting && descriptors[fact.Code].Waitable
		}
	}
	if input.Phase == "schedule" || result.PreviewOnly {
		result.AdmissionDecision = "not_admitted"
		result.BypassUsed = false
	}
	if input.Mode == "shadow" {
		result.AdmissionDecision = "not_enforced"
		result.BypassUsed = false
	}
	return result
}

func MarshalMergeGateSnapshot(input any) (string, error) {
	raw, err := json.Marshal(input)
	if err != nil {
		return "", err
	}
	if len(raw) > MaxSnapshotBytes {
		return "", errors.New("merge_gate_snapshot_too_large")
	}
	return string(raw), nil
}

type MergeGateContext struct {
	Context     string `json:"context"`
	Source      string `json:"source"`
	ReferenceID int64  `json:"reference_id,omitempty"`
	Pattern     bool   `json:"pattern"`
	AllStatuses bool   `json:"all_statuses,omitempty"`
}

type MergeGateStatus struct {
	ID          int64  `json:"id"`
	RepoID      int64  `json:"repo_id"`
	SHA         string `json:"sha"`
	Context     string `json:"context"`
	ContextHash string `json:"context_hash,omitempty"`
	State       string `json:"state"`
	CreatorID   int64  `json:"creator_id"`
}

func EvaluateMergeGateContexts(repoID int64, sha string, requirements []MergeGateContext, statuses []MergeGateStatus) []MergeGateFact {
	type statusIdentity struct{ hash, context string }
	latest := map[statusIdentity]MergeGateStatus{}
	for _, status := range statuses {
		key := statusIdentity{hash: status.ContextHash}
		if key.hash == "" {
			key.context = status.Context
		}
		if status.RepoID == repoID && status.SHA == sha && status.ID > latest[key].ID {
			latest[key] = status
		}
	}
	var facts []MergeGateFact
	seen := map[MergeGateContext]bool{}
	for _, requirement := range requirements {
		if seen[requirement] {
			continue
		}
		seen[requirement] = true
		code := "required_check"
		if requirement.Source == "path" {
			code = "sensitive_path_check"
		}
		fact := MergeGateFact{Code: code, Source: requirement.Source, ReferenceID: requirement.ReferenceID, Context: requirement.Context, State: "missing"}
		var matches []MergeGateStatus
		if requirement.AllStatuses && requirement.Source == "native" {
			for _, status := range latest {
				matches = append(matches, status)
			}
		} else if requirement.Pattern {
			pattern, err := glob.Compile(requirement.Context)
			if err != nil {
				fact.State = "error"
			} else {
				for _, status := range latest {
					if pattern.Match(status.Context) {
						matches = append(matches, status)
					}
				}
			}
		} else {
			for _, status := range latest {
				if status.Context == requirement.Context {
					matches = append(matches, status)
				}
			}
		}
		if len(matches) != 0 {
			fact.State = "passed"
			slices.SortFunc(matches, func(a, b MergeGateStatus) int {
				return cmp.Or(cmp.Compare(a.Context, b.Context), cmp.Compare(a.ContextHash, b.ContextHash), cmp.Compare(a.ID, b.ID))
			})
			for _, status := range matches {
				state := status.State
				if state == "success" || state == "skipped" && requirement.Source == "native" {
					continue
				}
				if state == "warning" || state == "skipped" {
					state = "failure"
				}
				if !slices.Contains([]string{"pending", "failure", "error"}, state) {
					state = "unknown"
				}
				if state == "error" || fact.State != "error" && (state == "unknown" || fact.State == "passed" || state == "failure" && fact.State == "pending") {
					fact.State = state
				}
			}
		}
		facts = append(facts, fact)
	}
	return facts
}
