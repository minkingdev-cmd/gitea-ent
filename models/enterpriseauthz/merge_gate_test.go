// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestProtectedPathRuleCAS(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	_, config, err := authz.ParseProtectedPathConfig([]byte(`{"path_pattern":"k8s/**","required_role_id":1}`))
	require.NoError(t, err)
	rule := &ProtectedPathRule{ScopeType: ScopeRepo, ScopeID: 1, OwnerID: 2, ConfigJSON: config, RequiredRoleID: 1, Enabled: true, CreatedBy: 2, UpdatedBy: 2}
	require.Error(t, SaveProtectedPathRule(t.Context(), rule, 0))
	save := func(expected int64) error {
		return db.WithTx(t.Context(), func(ctx context.Context) error { return SaveProtectedPathRule(ctx, rule, expected) })
	}
	require.NoError(t, save(0))
	require.EqualValues(t, 1, rule.Revision)
	require.Error(t, save(0))
	require.NoError(t, save(1))
	require.EqualValues(t, 1, rule.Revision)
	rule.Deleted, rule.Enabled = true, false
	require.NoError(t, save(1))
	require.EqualValues(t, 2, rule.Revision)
	rule.Deleted = false
	require.Error(t, save(1))
	require.Error(t, save(2))
	stored := unittest.AssertExistsAndLoadBean(t, &ProtectedPathRule{ID: rule.ID})
	require.True(t, stored.Deleted)
	require.EqualValues(t, 2, stored.Revision)
}

func TestMergeGateReadiness(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseMergeGate)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	setting.EnterpriseAuthz.Enabled = true
	seedBuiltinRoles(t)
	setting.EnterpriseMergeGate.Enabled = true
	require.NoError(t, CheckMergeGateReady(t.Context()))
	x := db.GetXORMEngineForTesting()
	_, auditErr := x.Exec("DROP INDEX IDX_audit_event_timestamp_unix")
	require.NoError(t, auditErr)
	require.EqualError(t, CheckMergeGateReady(t.Context()), "merge_gate_schema_missing")
	require.NoError(t, x.Sync(new(audit_model.Event)))
	_, err := x.Exec("DROP INDEX UQE_enterprise_merge_gate_evaluation_operation_attempt_phase")
	require.NoError(t, err)
	defer func() { require.NoError(t, x.Sync(new(MergeGateEvaluation))) }()
	require.EqualError(t, CheckMergeGateReady(t.Context()), "merge_gate_schema_missing")
	require.NoError(t, x.Sync(new(MergeGateEvaluation)))
	_, err = db.GetEngine(t.Context()).Where("action=?", authz.ManageSensitivePaths).Delete(new(RolePermission))
	require.NoError(t, err)
	require.ErrorIs(t, CheckMergeGateReady(t.Context()), errSeedIncomplete)
	setting.EnterpriseMergeGate.Enabled = false
	require.NoError(t, CheckMergeGateReady(t.Context()))
}

func TestMergeGateEvaluationImmutableAndTerminalCAS(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	snapshot := `{"snapshot_version":1}`
	record := &MergeGateEvaluation{OperationID: "operation", Attempt: 1, Phase: "admission", RepoID: 1, PullID: 1, IssueID: 1, ActorID: 2, HeadSHA: strings.Repeat("a", 40), BaseSHA: strings.Repeat("b", 40), Source: "web", Mode: "enforce", CandidateDecision: "allow", AdmissionDecision: "allow", ExecutionState: "not_started", SnapshotVersion: 1, SnapshotJSON: snapshot, SnapshotHash: fmt.Sprintf("%x", sha256.Sum256([]byte(snapshot))), ReasonsJSON: "[]"}
	inserted, err := InsertMergeGateEvaluation(t.Context(), record)
	require.NoError(t, err)
	require.True(t, inserted)
	require.Positive(t, record.ID)
	inserted, err = InsertMergeGateEvaluation(t.Context(), record)
	require.NoError(t, err)
	require.False(t, inserted)
	changed := *record
	changed.ActorID = 4
	_, err = InsertMergeGateEvaluation(t.Context(), &changed)
	require.Error(t, err)
	require.Error(t, TransitionMergeGateExecution(t.Context(), record.ID, "not_started", "succeeded", ""))
	require.NoError(t, TransitionMergeGateExecution(t.Context(), record.ID, "not_started", "started", ""))
	require.Error(t, TransitionMergeGateExecution(t.Context(), record.ID, "not_started", "started", ""))
	require.NoError(t, TransitionMergeGateExecution(t.Context(), record.ID, "started", "unknown", ""))
	require.NoError(t, TransitionMergeGateExecution(t.Context(), record.ID, "unknown", "succeeded", strings.Repeat("c", 40)))
	require.Error(t, TransitionMergeGateExecution(t.Context(), record.ID, "succeeded", "failed", ""))
	stored := unittest.AssertExistsAndLoadBean(t, &MergeGateEvaluation{ID: record.ID})
	require.Equal(t, snapshot, stored.SnapshotJSON)
	require.Equal(t, "succeeded", stored.ExecutionState)
	require.Equal(t, strings.Repeat("c", 40), stored.MergedSHA)
}

func TestMergeGateEvaluationRejectsInconsistentEvidence(t *testing.T) {
	snapshot := `{"snapshot_version":1}`
	valid := MergeGateEvaluation{OperationID: "operation", Attempt: 1, Phase: "admission", RepoID: 1, PullID: 1, IssueID: 1, ActorID: 2, Source: "web", Mode: "enforce", HeadSHA: strings.Repeat("a", 40), BaseSHA: strings.Repeat("b", 40), CandidateDecision: "allow", AdmissionDecision: "allow", ExecutionState: "not_started", SnapshotVersion: 1, SnapshotJSON: snapshot, SnapshotHash: fmt.Sprintf("%x", sha256.Sum256([]byte(snapshot))), ReasonsJSON: "[]"}
	require.NoError(t, valid.Validate())
	for _, change := range []func(*MergeGateEvaluation){
		func(e *MergeGateEvaluation) { e.IssueID = 0 },
		func(e *MergeGateEvaluation) { e.HeadSHA = "not-a-sha" },
		func(e *MergeGateEvaluation) { e.HeadSHA = "" },
		func(e *MergeGateEvaluation) { e.Mode = "shadow" },
		func(e *MergeGateEvaluation) { e.Phase = "schedule" },
		func(e *MergeGateEvaluation) { e.CandidateDecision = "deny" },
		func(e *MergeGateEvaluation) { e.BypassUsed = true },
		func(e *MergeGateEvaluation) { e.BypassReason = strings.Repeat("x", 1025) },
	} {
		invalid := valid
		change(&invalid)
		require.Error(t, invalid.Validate())
	}
}

func TestMergeGateSnapshotBodyVersionMustMatch(t *testing.T) {
	record := MergeGateEvaluation{OperationID: "body-version", Attempt: 1, Phase: "admission", RepoID: 1, PullID: 1, IssueID: 1, ActorID: 2, Source: "web", Mode: "enforce", HeadSHA: strings.Repeat("a", 40), BaseSHA: strings.Repeat("b", 40), CandidateDecision: "allow", AdmissionDecision: "allow", ExecutionState: "not_started", SnapshotVersion: 1, ReasonsJSON: "[]"}
	for _, raw := range []string{`{"snapshot_version":999}`, `{}`, `[]`, `{"snapshot_version":null}`} {
		record.SnapshotJSON = raw
		record.SnapshotHash = fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))
		require.Error(t, record.Validate(), raw)
	}
}

func TestMergeGateUnknownActorCannotAdmitOrStart(t *testing.T) {
	raw := `{"snapshot_version":1,"git_already_present":true}`
	record := MergeGateEvaluation{OperationID: "unknown", Attempt: 1, Phase: "manual_recognition", RepoID: 1, PullID: 1, IssueID: 1, Source: "auto_merge", Mode: "enforce", CandidateDecision: "error", AdmissionDecision: "error", ExecutionState: "not_started", SnapshotVersion: 1, SnapshotJSON: raw, SnapshotHash: fmt.Sprintf("%x", sha256.Sum256([]byte(raw))), ReasonsJSON: "[]"}
	require.NoError(t, record.Validate())
	for _, field := range []string{"decision", "phase", "source", "state", "bypass"} {
		changed := record
		switch field {
		case "decision":
			changed.CandidateDecision = "allow"
			changed.AdmissionDecision = "allow"
			changed.HeadSHA = strings.Repeat("a", 40)
			changed.BaseSHA = strings.Repeat("b", 40)
		case "phase":
			changed.Phase = "admission"
		case "source":
			changed.Source = "web"
		case "state":
			changed.ExecutionState = "started"
		case "bypass":
			changed.BypassRequested = true
		}
		require.Error(t, changed.Validate(), field)
	}
}
