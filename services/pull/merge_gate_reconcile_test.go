// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	issues_model "gitea.dev/models/issues"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/git"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/audit"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func TestMergeGateReconcileRequiresGitAndPRProof(t *testing.T) {
	for _, merged := range []bool{false, true} {
		t.Run(strconv.FormatBool(merged), func(t *testing.T) {
			require.NoError(t, unittest.PrepareTestDatabase())
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true}))
			t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
			require.NoError(t, pr.LoadBaseRepo(t.Context()))
			baseSHA, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
			require.NoError(t, err)
			raw, err := json.Marshal(mergeGateSnapshot{Version: 1, RepoID: pr.BaseRepoID, PullID: pr.ID, Branch: pr.BaseBranch, ResultSHA: baseSHA})
			require.NoError(t, err)
			record := &authz_model.MergeGateEvaluation{OperationID: "reconcile-real-git", Attempt: 1, Phase: "admission", RepoID: pr.BaseRepoID, PullID: pr.ID, IssueID: pr.IssueID, ActorID: 2, Source: "api", Mode: "enforce", HeadSHA: strings.Repeat("a", 40), BaseSHA: baseSHA, CandidateDecision: "allow", AdmissionDecision: "allow", ExecutionState: "not_started", SnapshotVersion: 1, SnapshotJSON: string(raw), SnapshotHash: fmt.Sprintf("%x", sha256.Sum256(raw)), ReasonsJSON: "[]"}
			require.NoError(t, db.WithIndependentTx(t.Context(), func(tx context.Context) error { return authz_service.PersistMergeGateEvaluationTx(tx, record, true) }))
			if merged {
				_, err = db.GetEngine(t.Context()).ID(pr.ID).Cols("has_merged", "merged_commit_id").Update(&issues_model.PullRequest{HasMerged: true, MergedCommitID: baseSHA})
				require.NoError(t, err)
			}
			var successor *authz_model.MergeGateEvaluation
			if merged {
				ctx := authz_service.WithOperation(t.Context())
				copied := *record
				copied.ID, copied.OperationID, copied.ExecutionState = 0, authz_service.MergeGateOperationID(ctx), "not_started"
				copied.StartedUnix, copied.TerminalUnix = 0, 0
				successor = &copied
				require.NoError(t, db.WithIndependentTx(ctx, func(tx context.Context) error { return authz_service.PersistMergeGateEvaluationTx(tx, successor, true) }))
				require.NoError(t, db.WithIndependentTx(ctx, func(tx context.Context) error {
					return authz_service.RecordMergeGateMarkerTx(tx, pr.BaseRepoID, pr.ID, 2, pr.BaseBranch, baseSHA)
				}))
			}
			require.NoError(t, reconcileMergeGateEvaluation(t.Context(), record))
			stored := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{ID: record.ID})
			require.Equal(t, "unknown", stored.ExecutionState)
			require.Empty(t, stored.MergedSHA)
			require.Equal(t, record.SnapshotJSON, stored.SnapshotJSON)
			require.NoError(t, reconcileMergeGateEvaluation(t.Context(), stored))
			unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateExecution}, 1)
			if successor != nil {
				require.NoError(t, reconcileMergeGateEvaluation(t.Context(), successor))
				require.Equal(t, "succeeded", unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{ID: successor.ID}).ExecutionState)
				unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateExecution}, 2)
			}
			current := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
			require.Equal(t, merged, current.HasMerged)
			after, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
			require.NoError(t, err)
			require.Equal(t, baseSHA, after)
		})
	}
}

func TestMergeGateReconcileDoesNotStarveBehindUnknown(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(t.Context()))
	baseSHA, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).ID(pr.ID).Cols("has_merged", "merged_commit_id").Update(&issues_model.PullRequest{HasMerged: true, MergedCommitID: baseSHA})
	require.NoError(t, err)
	var last *authz_model.MergeGateEvaluation
	for i := range 101 {
		resultSHA := strings.Repeat("a", 40)
		if i == 100 {
			resultSHA = baseSHA
		}
		raw, err := json.Marshal(mergeGateSnapshot{Version: 1, RepoID: pr.BaseRepoID, PullID: pr.ID, Branch: pr.BaseBranch, ResultSHA: resultSHA})
		require.NoError(t, err)
		last = &authz_model.MergeGateEvaluation{OperationID: fmt.Sprintf("reconcile-queue-%d", i), Attempt: 1, Phase: "admission", RepoID: pr.BaseRepoID, PullID: pr.ID, IssueID: pr.IssueID, ActorID: 2, Source: "api", Mode: "enforce", HeadSHA: baseSHA, BaseSHA: baseSHA, CandidateDecision: "allow", AdmissionDecision: "allow", ExecutionState: "not_started", SnapshotVersion: 1, SnapshotJSON: string(raw), SnapshotHash: fmt.Sprintf("%x", sha256.Sum256(raw)), ReasonsJSON: "[]"}
		require.NoError(t, db.WithIndependentTx(t.Context(), func(tx context.Context) error { return authz_service.PersistMergeGateEvaluationTx(tx, last, true) }))
		if i < 100 {
			require.NoError(t, authz_service.FinishMergeGateEvaluation(t.Context(), last, "unknown", ""))
		}
	}
	require.NoError(t, audit.RecordEvent(t.Context(), audit.RecordParams{Action: audit_model.EnterpriseMergeGateMarker, Actor: audit_model.EntityRef{Type: audit_model.ScopeUser, ID: last.ActorID}, Scope: audit_model.EntityRef{Type: audit_model.ScopeRepository, ID: last.RepoID}, Metadata: map[string]any{"evaluation_id": last.ID, "operation_id": last.OperationID, "pull_id": last.PullID, "snapshot_hash": last.SnapshotHash, "result_sha": baseSHA}}))
	_, err = db.GetEngine(t.Context()).Table(new(authz_model.MergeGateEvaluation)).Where("pull_id=?", pr.ID).Cols("started_unix").Update(&authz_model.MergeGateEvaluation{StartedUnix: 1})
	require.NoError(t, err)
	require.NoError(t, ReconcileMergeGateEvaluations(t.Context()))
	require.Equal(t, "succeeded", unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{ID: last.ID}).ExecutionState)
}

func TestMergeGateTerminalCannotClaimAnotherOperationsMarker(t *testing.T) {
	ctx := mergeExecutionContext(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(ctx))
	sha, err := git.GetFullCommitID(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
	require.NoError(t, err)
	raw, err := json.Marshal(mergeGateSnapshot{Version: 1, RepoID: pr.BaseRepoID, PullID: pr.ID, Branch: pr.BaseBranch, ResultSHA: sha})
	require.NoError(t, err)
	record := &authz_model.MergeGateEvaluation{OperationID: "terminal-other-operation", Attempt: 1, Phase: "admission", RepoID: pr.BaseRepoID, PullID: pr.ID, IssueID: pr.IssueID, ActorID: 2, Source: "api", Mode: "enforce", HeadSHA: sha, BaseSHA: sha, CandidateDecision: "allow", AdmissionDecision: "allow", ExecutionState: "not_started", SnapshotVersion: 1, SnapshotJSON: string(raw), SnapshotHash: fmt.Sprintf("%x", sha256.Sum256(raw)), ReasonsJSON: "[]"}
	require.NoError(t, db.WithIndependentTx(ctx, func(tx context.Context) error { return authz_service.PersistMergeGateEvaluationTx(tx, record, true) }))
	_, err = db.GetEngine(ctx).ID(pr.ID).Cols("has_merged", "merged_commit_id").Update(&issues_model.PullRequest{HasMerged: true, MergedCommitID: sha})
	require.NoError(t, err)
	execution := &mergeExecution{ctx: ctx, gate: record, gateResultSHA: sha, gatePushAttempted: true, gatePushSucceeded: true}
	require.Error(t, execution.finishMergeGate(nil))
	require.Equal(t, "unknown", unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{ID: record.ID}).ExecutionState)
}
