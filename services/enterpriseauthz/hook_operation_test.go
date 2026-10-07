// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
	"time"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/audit"

	"github.com/stretchr/testify/require"
)

func TestHookOperationTicketTrustAndIdentity(t *testing.T) {
	enableObservation(t)
	defer test.MockVariableValue(&setting.InternalToken, "test-only-server-internal-token")()
	input := observationInput(t)
	input.Action = authz.PushBranch
	input.ConditionContext = authz.ConditionContext{Source: "git_http", Branch: "private/branch", BranchKnown: true}
	ctx := audit.WithImpersonator(audit.WithOrigin(t.Context(), audit_model.OriginAPI), input.Actor)
	ticket := NewHookOperationTicket(ctx, input, nil)
	require.NotEmpty(t, string(ticket))
	require.NotContains(t, fmt.Sprintf("%+v", ticket), string(ticket))
	require.NotContains(t, string(ticket), "private/branch")
	restored, operation := RestoreHookOperation(t.Context(), ticket, 1, 2, "")
	require.NotNil(t, operation)
	require.Equal(t, "git_http", operation.Source())
	require.Equal(t, input.Credential, operation.Credential())
	require.Equal(t, audit_model.OriginAPI, audit.OriginFromContext(restored))
	require.EqualValues(t, 2, audit.ImpersonatorFromContext(restored).ID)
	for _, tc := range []struct {
		ticket          authz.HookOperationTicket
		repoID, actorID int64
		ext             string
	}{
		{authz.HookOperationTicket(string(ticket) + "tampered"), 1, 2, ""},
		{ticket, 2, 2, ""},
		{ticket, 1, 4, ""},
		{ticket, 1, 2, "deploy-key:1"},
		{"", 1, 2, ""},
		{authz.HookOperationTicket(strings.Repeat("x", 4097)), 1, 2, ""},
	} {
		_, invalid := RestoreHookOperation(t.Context(), tc.ticket, tc.repoID, tc.actorID, tc.ext)
		require.Nil(t, invalid)
	}
	now := time.Now()
	defer test.MockVariableValue(&hookOperationNow, func() time.Time { return now.Add(25 * time.Hour) })()
	_, expired := RestoreHookOperation(t.Context(), ticket, 1, 2, "")
	require.Nil(t, expired)
}

func TestHookObservationTerminalPreservesSnapshotAndAtomicEvidence(t *testing.T) {
	enableObservation(t)
	defer test.MockVariableValue(&setting.InternalToken, "test-only-server-internal-token")()
	input := observationInput(t)
	input.Action = authz.PushBranch
	input.ConditionContext = authz.ConditionContext{Source: "ssh", Branch: "private/branch", BranchKnown: true}
	ticket := NewHookOperationTicket(t.Context(), input, nil)
	ctx, operation := RestoreHookOperation(t.Context(), ticket, 1, 2, "")
	require.NotNil(t, operation)
	ctx, observation := BeginObservation(ctx, input)
	require.NotNil(t, observation)
	observation.Finish(ctx, NativeUnknown, StagePreReceive)
	original := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{NativeOutcome: "unknown"})
	// 新进程重试不重写 candidate，也不新增第二条审计。
	retry, again := RestoreHookOperation(t.Context(), ticket, 1, 2, "")
	require.NotNil(t, again)
	retry, repeated := BeginObservation(retry, input)
	repeated.Finish(retry, NativeUnknown, StagePreReceive)
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 1)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, 1)
	CompleteHookObservation(t.Context(), operation, authz.PushBranch, "private/branch", NativeSuccess, StageTransport)
	terminal := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ID: original.ID})
	require.Equal(t, "success", terminal.NativeOutcome)
	require.Equal(t, "transport", terminal.NativeStage)
	require.Equal(t, original.SnapshotJSON, terminal.SnapshotJSON)
	require.Equal(t, original.CandidateDecision, terminal.CandidateDecision)
	require.Equal(t, original.CreatedUnix, terminal.CreatedUnix)
	event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
	require.Equal(t, "success", audit_model.DecodeMetadata(event.Metadata)["native_outcome"])
	require.Equal(t, false, audit_model.DecodeMetadata(event.Metadata)["mismatch"])
	CompleteHookObservation(t.Context(), operation, authz.PushBranch, "private/branch", NativeDenied, StagePreReceive)
	require.Equal(t, "success", unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ID: original.ID}).NativeOutcome)
	CompleteHookObservation(t.Context(), operation, authz.PushBranch, "another/branch", NativeSuccess, StageTransport)
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 1)
	// 已有 unknown 若关联审计丢失，终态更新必须回滚。
	ticket = NewHookOperationTicket(t.Context(), input, nil)
	second, secondOperation := RestoreHookOperation(t.Context(), ticket, 1, 2, "")
	second, observation = BeginObservation(second, input)
	observation.Finish(second, NativeUnknown, StagePreReceive)
	pending := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{NativeOutcome: "unknown"})
	_, err := db.GetEngine(t.Context()).Where("metadata LIKE ?", "%"+pending.ObservationID+"%").Delete(&audit_model.Event{})
	require.NoError(t, err)
	CompleteHookObservation(context.Background(), secondOperation, authz.PushBranch, "private/branch", NativeSuccess, StageTransport)
	require.Equal(t, "unknown", unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ID: pending.ID}).NativeOutcome)
}

func TestHookTicketOwnershipIsRefAndActionScoped(t *testing.T) {
	enableObservation(t)
	defer test.MockVariableValue(&setting.InternalToken, "test-only-server-internal-token")()
	input := observationInput(t)
	input.ConditionContext.Source = "file_editor"
	ticket := NewHookOperationTicket(t.Context(), input, []HookOwnedObservation{{Action: authz.PushBranch, Branch: "main"}})
	_, operation := RestoreHookOperation(t.Context(), ticket, 1, 2, "")
	require.NotNil(t, operation)
	require.True(t, operation.Owns(authz.PushBranch, "main"))
	require.False(t, operation.Owns(authz.PushBranch, "other"))
	require.False(t, operation.Owns(authz.ManageCodeowners, "main"))
	require.False(t, operation.Owns(authz.CreateBranch, "main"))
}

func TestHookRetryDoesNotReevaluateHistoricalPolicy(t *testing.T) {
	enableObservation(t)
	defer test.MockVariableValue(&setting.InternalToken, "test-only-server-internal-token")()
	input := observationInput(t)
	input.Action = authz.PushBranch
	input.ConditionContext = authz.ConditionContext{Source: "git_http", Branch: "main", BranchKnown: true}
	ticket := NewHookOperationTicket(t.Context(), input, nil)
	ctx, _ := RestoreHookOperation(t.Context(), ticket, 1, 2, "")
	ctx, original := BeginObservation(ctx, input)
	original.Finish(ctx, NativeUnknown, StagePreReceive)
	_, err := db.Exec(t.Context(), "ALTER TABLE enterprise_subject_role_binding RENAME TO authz_hook_hidden_bindings")
	require.NoError(t, err)
	defer func() {
		_, err := db.Exec(context.Background(), "ALTER TABLE authz_hook_hidden_bindings RENAME TO enterprise_subject_role_binding")
		require.NoError(t, err)
	}()
	retry, _ := RestoreHookOperation(t.Context(), ticket, 1, 2, "")
	_, repeated := BeginObservation(retry, input)
	require.NotNil(t, repeated)
	require.Equal(t, original.record.CandidateDecision, repeated.record.CandidateDecision)
	require.Equal(t, original.record.SnapshotJSON, repeated.record.SnapshotJSON)
	require.False(t, repeated.evaluationFailed)
}

func TestManagedHookTicketKeepsDetachedCredentialAndExactRef(t *testing.T) {
	enableObservation(t)
	defer test.MockVariableValue(&setting.InternalToken, "test-only-server-internal-token")()
	input := observationInput(t)
	input.Action = authz.MergePullRequest
	input.ConditionContext.Source = "api"
	input.Credential.Write = false
	source, observation := WithObservationContext(t.Context(), input)
	require.NotNil(t, observation)
	detached := DetachedObservationContext(context.Background(), source)
	ticket := ManagedHookOperationTicket(detached, input.Actor, input.Repo, "main", authz.MergePullRequest)
	_, operation := RestoreHookOperation(t.Context(), ticket, 1, 2, "")
	require.NotNil(t, operation)
	require.Equal(t, input.Credential, operation.Credential())
	require.True(t, operation.Owns(authz.MergePullRequest, "main"))
	require.False(t, operation.Owns(authz.MergePullRequest, "other"))
	require.False(t, operation.Owns(authz.PushBranch, "main"))
}

func TestManagedHookCaptureGapStillOwnsOnlyExactParentIntent(t *testing.T) {
	enableObservation(t)
	defer test.MockVariableValue(&setting.InternalToken, "test-only-server-internal-token")()
	input := observationInput(t)
	input.Action = authz.MergePullRequest
	input.ConditionContext.Source = "api"
	input.Credential.Write = false
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	source, observation := WithObservationContext(canceled, input)
	require.Nil(t, observation)
	detached := DetachedObservationContext(context.Background(), source)
	ticket := ManagedHookOperationTicket(detached, input.Actor, input.Repo, "main", authz.MergePullRequest)
	_, operation := RestoreHookOperation(t.Context(), ticket, 1, 2, "")
	require.NotNil(t, operation)
	require.Equal(t, "api", operation.Source())
	require.Equal(t, input.Credential, operation.Credential())
	require.True(t, operation.Owns(authz.MergePullRequest, "main"))
	require.False(t, operation.Owns(authz.MergePullRequest, "other"))
}

func TestRepoPushObservationDoesNotMergeDifferentRefs(t *testing.T) {
	enableObservation(t)
	input := observationInput(t)
	input.Action = authz.PushBranch
	input.ConditionContext = authz.ConditionContext{Source: "api", Branch: "master", BranchKnown: true}
	input.Credential.Write = false
	ctx, first := WithObservationContext(t.Context(), input)
	require.NotNil(t, first)
	ctx = DetachedObservationContext(context.Background(), ctx)
	_, same := WithRepoPushObservation(ctx, input.Actor, input.Repo.ID, "master")
	require.Same(t, first, same)
	otherCtx, other := WithRepoPushObservation(ctx, input.Actor, input.Repo.ID, "branch2")
	require.NotNil(t, other)
	require.NotSame(t, first, other)
	first.Finish(ctx, NativeSuccess, StageOperation)
	other.Finish(otherCtx, NativeDenied, StageOperation)
	var records []*authz_model.DecisionRecord
	require.NoError(t, db.GetEngine(t.Context()).Where("action = ?", "repo.push_branch").OrderBy("id").Find(&records))
	require.Len(t, records, 2)
	require.Equal(t, records[0].OperationID, records[1].OperationID)
	require.NotEqual(t, records[0].ObservationID, records[1].ObservationID)
	for _, record := range records {
		require.Equal(t, "api", record.RequestSource)
		require.Equal(t, "deny", record.CandidateDecision)
	}
}

func TestMergeGateHookRejectsUnadmittedMerge(t *testing.T) {
	enableMergeGate(t)
	defer test.MockVariableValue(&setting.InternalToken, "test-only-server-internal-token")()
	defer test.MockVariableValue(&setting.EnterpriseMergeGate.Enforce, true)()
	input := observationInput(t)
	input.Action = authz.MergePullRequest
	input.ConditionContext = authz.ConditionContext{Source: "api", Branch: "main", BranchKnown: true}
	ticket := NewHookOperationTicket(WithOperation(t.Context()), input, []HookOwnedObservation{{Action: authz.MergePullRequest, Branch: "main"}})
	require.Empty(t, string(ticket))
}

func TestMergeGateHookBindsStartedEvidenceAndExactRefs(t *testing.T) {
	enableMergeGate(t)
	defer test.MockVariableValue(&setting.InternalToken, "test-only-server-internal-token")()
	defer test.MockVariableValue(&setting.EnterpriseMergeGate.Enforce, true)()
	input := observationInput(t)
	input.Action = authz.MergePullRequest
	input.ConditionContext = authz.ConditionContext{Source: "api", Branch: "main", BranchKnown: true}
	ctx := WithOperation(t.Context())
	oldSHA, newSHA := strings.Repeat("a", 40), strings.Repeat("b", 40)
	snapshot := `{"snapshot_version":1,"result_sha":"` + newSHA + `"}`
	record := &authz_model.MergeGateEvaluation{OperationID: MergeGateOperationID(ctx), Attempt: 1, Phase: "admission", RepoID: input.Repo.ID, PullID: 1, IssueID: 1, ActorID: input.Actor.ID, Source: "api", Mode: "enforce", HeadSHA: strings.Repeat("c", 40), BaseSHA: oldSHA, CandidateDecision: "allow", AdmissionDecision: "allow", ReasonsJSON: "[]", SnapshotJSON: snapshot, SnapshotHash: fmt.Sprintf("%x", sha256.Sum256([]byte(snapshot))), SnapshotVersion: 1, ExecutionState: "not_started"}
	require.NoError(t, db.WithIndependentTx(ctx, func(tx context.Context) error { return PersistMergeGateEvaluationTx(tx, record, true) }))
	bound := WithMergeGateHookAdmission(ctx, record, "main", newSHA)
	ticket := NewHookOperationTicket(bound, input, []HookOwnedObservation{{Action: authz.MergePullRequest, Branch: "main"}})
	require.NotEmpty(t, string(ticket))
	restored, operation := RestoreHookOperation(t.Context(), ticket, input.Repo.ID, input.Actor.ID, "")
	require.NotNil(t, operation)
	require.NoError(t, ValidateMergeGateHook(restored, operation, git.RefNameFromBranch("main"), oldSHA, newSHA))
	otherRequest := WithOperation(t.Context())
	_, crossed := RestoreHookOperation(otherRequest, ticket, input.Repo.ID, input.Actor.ID, "")
	require.Nil(t, crossed)
	unbound := WithMergeGateHookAdmission(otherRequest, record, "main", newSHA)
	require.Empty(t, string(NewHookOperationTicket(unbound, input, []HookOwnedObservation{{Action: authz.MergePullRequest, Branch: "main"}})))
	for _, tc := range []struct{ branch, old, next string }{
		{"other", oldSHA, newSHA}, {"main", newSHA, newSHA}, {"main", oldSHA, oldSHA},
	} {
		require.Error(t, ValidateMergeGateHook(restored, operation, git.RefNameFromBranch(tc.branch), tc.old, tc.next))
	}
	require.NoError(t, FinishMergeGateEvaluation(ctx, record, "succeeded", newSHA))
	require.Error(t, ValidateMergeGateHook(restored, operation, git.RefNameFromBranch("main"), oldSHA, newSHA))
	now := time.Now()
	t.Cleanup(test.MockVariableValue(&hookOperationNow, func() time.Time { return now.Add(25 * time.Hour) }))
	_, expired := RestoreHookOperation(t.Context(), ticket, input.Repo.ID, input.Actor.ID, "")
	require.Nil(t, expired)
}
