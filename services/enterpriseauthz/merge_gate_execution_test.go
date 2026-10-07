// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	asymkey_model "gitea.dev/models/asymkey"
	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/setting"

	"github.com/stretchr/testify/require"
)

func TestMergeGateEvidenceAtomicAndTerminalFailure(t *testing.T) {
	enableMergeGate(t)
	snapshot := `{"snapshot_version":1}`
	newRecord := func(operation string) *authz_model.MergeGateEvaluation {
		return &authz_model.MergeGateEvaluation{OperationID: operation, Attempt: 1, Phase: "admission", RepoID: 1, PullID: 1, IssueID: 1, ActorID: 2, HeadSHA: strings.Repeat("a", 40), BaseSHA: strings.Repeat("b", 40), Source: "api", Mode: "enforce", CandidateDecision: "allow", AdmissionDecision: "allow", ExecutionState: "not_started", SnapshotVersion: 1, SnapshotJSON: snapshot, SnapshotHash: fmt.Sprintf("%x", sha256.Sum256([]byte(snapshot))), ReasonsJSON: "[]"}
	}
	persist := func(record *authz_model.MergeGateEvaluation, start bool) error {
		return db.WithIndependentTx(t.Context(), func(tx context.Context) error { return PersistMergeGateEvaluationTx(tx, record, start) })
	}
	hook := &featureAuditFailure{enabled: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	t.Cleanup(func() { hook.enabled = false })
	record := newRecord("audit-insert-failed")
	require.ErrorContains(t, persist(record, true), "injected_audit_failure")
	require.True(t, hook.fired)
	unittest.AssertCount(t, &authz_model.MergeGateEvaluation{}, 0)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateEvaluation}, 0)
	hook.enabled = false
	record = newRecord("atomic-start")
	require.NoError(t, persist(record, true))
	require.Equal(t, "started", record.ExecutionState)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateEvaluation}, 1)
	duplicate := newRecord("atomic-start")
	require.Error(t, persist(duplicate, true))
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateEvaluation}, 1)
	hook.enabled, hook.fired = true, false
	require.ErrorContains(t, FinishMergeGateEvaluation(t.Context(), record, "succeeded", strings.Repeat("c", 40)), "injected_audit_failure")
	require.True(t, hook.fired)
	stored := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{ID: record.ID})
	require.Equal(t, "started", stored.ExecutionState)
	require.Empty(t, stored.MergedSHA)
	require.Zero(t, stored.TerminalUnix)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateExecution}, 0)
	hook.enabled = false
	require.NoError(t, FinishMergeGateEvaluation(t.Context(), record, "succeeded", strings.Repeat("c", 40)))
	require.Error(t, FinishMergeGateEvaluation(t.Context(), record, "failed", ""))
	stored = unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{ID: record.ID})
	require.Equal(t, "succeeded", stored.ExecutionState)
	require.Equal(t, snapshot, stored.SnapshotJSON)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateExecution}, 1)
	setting.Audit.RecordOutput = setting.AuditRecordOutputDisabled
	require.Error(t, persist(newRecord("audit-disabled"), true))
}

func TestMergeGateCredentialRefreshUsesCurrentIntersection(t *testing.T) {
	enableMergeGate(t)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	token := &auth_model.AccessToken{UID: 2, Name: "merge-gate-current", Scope: auth_model.AccessTokenScopeWriteRepository}
	require.NoError(t, auth_model.NewAccessToken(t.Context(), token))
	original := CredentialCeiling{Read: true, Write: true, Reference: fmt.Sprintf("access-token:%d", token.ID)}
	refresh := func(actorID int64, ceiling CredentialCeiling, read, write bool) {
		t.Helper()
		current, err := RefreshMergeGateCredential(t.Context(), actorID, repo, ceiling)
		require.NoError(t, err)
		require.Equal(t, read, current.Read)
		require.Equal(t, write, current.Write)
	}
	refresh(2, original, true, true)
	refresh(4, original, false, false)
	narrowed := original
	narrowed.Write = false
	refresh(2, narrowed, true, false)
	narrowed.NativeOnly = true
	refresh(2, narrowed, false, false)
	_, err := db.GetEngine(t.Context()).ID(token.ID).Cols("scope").Update(&auth_model.AccessToken{Scope: auth_model.AccessTokenScopeReadRepository})
	require.NoError(t, err)
	refresh(2, original, true, false)
	_, err = db.GetEngine(t.Context()).ID(token.ID).Cols("scope").Update(&auth_model.AccessToken{Scope: auth_model.AccessTokenScope("public-only,write:repository")})
	require.NoError(t, err)
	publicRepo := *repo
	publicRepo.IsPrivate = false
	captured, err := RefreshMergeGateCredential(t.Context(), 2, &publicRepo, original)
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).ID(token.ID).Cols("scope").Update(&auth_model.AccessToken{Scope: auth_model.AccessTokenScopeWriteRepository})
	require.NoError(t, err)
	privateRepo := *repo
	privateRepo.IsPrivate = true
	widened, err := RefreshMergeGateCredential(t.Context(), 2, &privateRepo, captured)
	require.NoError(t, err)
	require.False(t, widened.Read, "排队后扩大 token scope 不得扩大原 public-only ceiling")
	_, err = db.GetEngine(t.Context()).ID(token.ID).Cols("scope").Update(&auth_model.AccessToken{Scope: auth_model.AccessTokenScope("public-only,write:repository")})
	require.NoError(t, err)
	current, err := RefreshMergeGateCredential(t.Context(), 2, &privateRepo, original)
	require.NoError(t, err)
	require.False(t, current.Read)
	require.False(t, current.Write)
	_, err = db.GetEngine(t.Context()).ID(token.ID).Delete(new(auth_model.AccessToken))
	require.NoError(t, err)
	refresh(2, original, false, false)
	grant := &auth_model.OAuth2Grant{ApplicationID: 1, UserID: 2, Scope: string(auth_model.AccessTokenScopeWriteRepository)}
	require.NoError(t, db.Insert(t.Context(), grant))
	original.Reference = fmt.Sprintf("oauth2-grant:%d", grant.ID)
	refresh(2, original, true, true)
	refresh(4, original, false, false)
	_, err = db.GetEngine(t.Context()).ID(grant.ID).Delete(new(auth_model.OAuth2Grant))
	require.NoError(t, err)
	refresh(2, original, false, false)
	original.Reference = "untrusted:secret"
	refresh(2, original, false, false)
}

func TestMergeGateReconcileUnknownIsAtomicAndSealed(t *testing.T) {
	enableMergeGate(t)
	snapshot := `{"snapshot_version":1}`
	record := &authz_model.MergeGateEvaluation{OperationID: "unknown-reconcile", Attempt: 1, Phase: "admission", RepoID: 1, PullID: 1, IssueID: 1, ActorID: 2, HeadSHA: strings.Repeat("a", 40), BaseSHA: strings.Repeat("b", 40), Source: "api", Mode: "enforce", CandidateDecision: "allow", AdmissionDecision: "allow", ExecutionState: "not_started", SnapshotVersion: 1, SnapshotJSON: snapshot, SnapshotHash: fmt.Sprintf("%x", sha256.Sum256([]byte(snapshot))), ReasonsJSON: "[]"}
	require.NoError(t, db.WithIndependentTx(t.Context(), func(tx context.Context) error { return PersistMergeGateEvaluationTx(tx, record, true) }))
	require.NoError(t, FinishMergeGateEvaluation(t.Context(), record, "unknown", ""))
	record = unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{ID: record.ID})
	require.NoError(t, FinishMergeGateEvaluation(t.Context(), record, "succeeded", strings.Repeat("c", 40)))
	stored := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{ID: record.ID})
	require.Equal(t, "succeeded", stored.ExecutionState)
	require.Equal(t, snapshot, stored.SnapshotJSON)
	require.Error(t, FinishMergeGateEvaluation(t.Context(), stored, "failed", ""))
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateExecution}, 2)
}

func TestMergeGateShadowCancellationAuditFailureDoesNotBlockNative(t *testing.T) {
	enableMergeGate(t)
	setting.EnterpriseMergeGate.Enforce = false
	snapshot := `{"snapshot_version":1}`
	record := &authz_model.MergeGateEvaluation{OperationID: "shadow-cancel", Attempt: 1, Phase: "schedule", RepoID: 1, PullID: 1, IssueID: 1, ActorID: 2, HeadSHA: strings.Repeat("a", 40), BaseSHA: strings.Repeat("b", 40), Source: "api", Mode: "shadow", CandidateDecision: "allow", AdmissionDecision: "not_enforced", ExecutionState: "not_started", SnapshotVersion: 1, SnapshotJSON: snapshot, SnapshotHash: fmt.Sprintf("%x", sha256.Sum256([]byte(snapshot))), ReasonsJSON: "[]"}
	require.NoError(t, db.WithIndependentTx(t.Context(), func(tx context.Context) error { return PersistMergeGateEvaluationTx(tx, record, false) }))
	hook := &featureAuditFailure{enabled: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	t.Cleanup(func() { hook.enabled = false })
	require.NoError(t, db.WithIndependentTx(t.Context(), func(tx context.Context) error { return CancelMergeGateSchedulesTx(tx, 1) }))
	require.True(t, hook.fired)
	require.Equal(t, "not_started", unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{ID: record.ID}).ExecutionState)
}

func TestMergeGateRefreshReceiveSSHCredential(t *testing.T) {
	enableMergeGate(t)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	ceiling := CredentialCeiling{Read: true, Write: true, Reference: "ssh-key:1"}
	current, err := RefreshMergeGateCredential(t.Context(), 2, repo, ceiling)
	require.NoError(t, err)
	require.True(t, current.Write)
	_, err = db.GetEngine(t.Context()).ID(1).Delete(new(asymkey_model.PublicKey))
	require.NoError(t, err)
	current, err = RefreshMergeGateCredential(t.Context(), 2, repo, ceiling)
	require.NoError(t, err)
	require.False(t, current.Read)
	require.False(t, current.Write)
}
