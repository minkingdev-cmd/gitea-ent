// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/log"
	"gitea.dev/modules/metrics"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/audit"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
)

type simultaneousOperationContext struct {
	reqctx.RequestContext
	reads  atomic.Int32
	writes atomic.Int32
	ready  chan struct{}
}

func (c *simultaneousOperationContext) Value(key any) any {
	if _, ok := key.(operationKey); ok {
		n := c.reads.Add(1)
		if n <= 16 {
			if n == 16 {
				close(c.ready)
			}
			<-c.ready
			return nil
		}
	}
	return c.RequestContext.Value(key)
}

func (c *simultaneousOperationContext) SetContextValue(key, value any) {
	c.writes.Add(1)
	c.RequestContext.SetContextValue(key, value)
}

func TestObservationConcurrentRequestCreatesOneOperation(t *testing.T) {
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true))
	ctx := &simultaneousOperationContext{RequestContext: reqctx.NewRequestContextForTest(t), ready: make(chan struct{})}
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() { WithOperation(ctx) })
	}
	wg.Wait()
	require.Equal(t, int32(1), ctx.writes.Load())
}

func TestObservationPreservesTrustedImpersonatorWithoutPrivateNames(t *testing.T) {
	enableObservation(t)
	ctx := reqctx.NewRequestContextForTest(t)
	audit.SetRequestInfo(ctx, audit_model.OriginAPI, "127.0.0.1")
	impersonator := &user_model.User{ID: 1, Name: "private-admin@example.com"}
	operationCtx, observation := BeginObservation(audit.WithImpersonator(ctx, impersonator), observationInput(t))
	observation.Finish(operationCtx, NativeSuccess, StageOperation)
	event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
	require.Equal(t, impersonator.ID, event.ImpersonatorID)
	require.NotContains(t, event.ImpersonatorName, "private-admin")
	require.Equal(t, audit_model.OriginAPI, event.Origin)
	require.Equal(t, "127.0.0.1", event.IPAddress)
}

func observationInput(t *testing.T) EvaluateInput {
	t.Helper()
	permission := &access_model.Permission{AccessMode: perm.AccessModeAdmin}
	permission.SetUnitsWithDefaultAccessMode([]*repo_model.RepoUnit{{Type: unit.TypeCode}}, perm.AccessModeAdmin)
	return EvaluateInput{Actor: unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}), Repo: unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}), Permission: permission, Credential: CredentialCeiling{Read: true, Write: true, Reference: "access-token:42"}, Action: authz.Delete, ConditionContext: authz.ConditionContext{Source: "api"}}
}

func enableObservation(t *testing.T) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled = true
	require.NoError(t, unittest.PrepareTestDatabase())
}

func TestObservationUsesResolvedSnapshotOwner(t *testing.T) {
	enableObservation(t)
	input := observationInput(t)
	_, err := db.GetEngine(t.Context()).ID(input.Repo.ID).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 4})
	require.NoError(t, err)
	ctx, observation := BeginObservation(t.Context(), input)
	require.NotNil(t, observation)
	observation.Finish(ctx, NativeSuccess, StageOperation)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: input.Repo.ID})
	var snapshot roleSnapshot
	require.NoError(t, json.Unmarshal([]byte(record.SnapshotJSON), &snapshot))
	require.EqualValues(t, 4, snapshot.OwnerID)
	require.Equal(t, snapshot.OwnerID, record.OwnerID)
	event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
	require.Contains(t, event.Metadata, `"owner_id":4`)
}

func TestObservationPreservesPreMutationEvidenceAndDeduplicates(t *testing.T) {
	enableObservation(t)
	input := observationInput(t)
	ctx, observation := BeginObservation(t.Context(), input)
	_, duplicate := BeginObservation(ctx, input)
	require.Same(t, observation, duplicate)
	originalOwner := input.Repo.OwnerID
	nativeErr := errors.New("native operation failed")
	require.ErrorIs(t, db.WithTx(ctx, func(tx context.Context) error {
		_, err := db.GetEngine(tx).ID(input.Repo.ID).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 3})
		require.NoError(t, err)
		return nativeErr
	}), nativeErr)
	input.Repo.OwnerID = 999
	observation.Finish(ctx, NativeFailed, StageOperation)
	duplicate.Finish(ctx, NativeSuccess, StageOperation)
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 1)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1})
	require.Equal(t, originalOwner, record.OwnerID)
	require.Equal(t, "deny", record.CandidateDecision)
	require.Equal(t, "failed", record.NativeOutcome)
	require.Contains(t, record.SnapshotJSON, `"owner_id":2`)
	event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
	metadata := audit_model.DecodeMetadata(event.Metadata)
	require.Equal(t, record.ObservationID, metadata["observation_id"])
	require.EqualValues(t, record.ID, metadata["decision_id"])
	require.NotContains(t, metadata, "mismatch")
	require.Equal(t, "access-token:42", event.ActorCredential)
	require.Equal(t, record.CreatedUnix, event.TimestampUnix)
	_, independent := BeginObservation(t.Context(), observationInput(t))
	independent.Finish(t.Context(), NativeSuccess, StageOperation)
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 2)
	event = unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision, ID: event.ID + 1})
	require.Equal(t, true, audit_model.DecodeMetadata(event.Metadata)["mismatch"])
}

func TestObservationAuditFailureIsAtomicAndSafe(t *testing.T) {
	enableObservation(t)
	_, err := db.GetEngine(t.Context()).Exec(`CREATE TRIGGER authz_audit_failure BEFORE INSERT ON audit_event BEGIN SELECT RAISE(ABORT, 'secret=TOPSECRET token=TOPTOKEN code=OAUTH https://callback.invalid/?code=OAUTH'); END`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.GetEngine(context.WithoutCancel(t.Context())).Exec("DROP TRIGGER authz_audit_failure")
		require.NoError(t, err)
	})
	before := observationFailureCount("evidence_persist_failed")
	ctx, observation := BeginObservation(t.Context(), observationInput(t))
	observation.Finish(ctx, NativeSuccess, StageOperation)
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 0)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, 0)
	require.Equal(t, before+1, observationFailureCount("evidence_persist_failed"))
}

func TestObservationSkipsDisabledInvisibleAndActiveTransactions(t *testing.T) {
	enableObservation(t)
	input := observationInput(t)
	setting.EnterpriseAuthz.Enabled = false
	_, err := db.GetEngine(t.Context()).Exec("ALTER TABLE enterprise_role_definition RENAME TO authz_hidden_roles")
	require.NoError(t, err)
	ctx, observation := BeginObservation(t.Context(), input)
	require.Nil(t, observation)
	observation.Finish(ctx, NativeSuccess, StageOperation)
	_, err = db.GetEngine(t.Context()).Exec("ALTER TABLE authz_hidden_roles RENAME TO enterprise_role_definition")
	require.NoError(t, err)
	setting.EnterpriseAuthz.Enabled = true
	input.Permission = &access_model.Permission{}
	_, observation = BeginObservation(t.Context(), input)
	require.Nil(t, observation)
	input = observationInput(t)
	before := observationFailureCount("business_transaction_active")
	require.NoError(t, db.WithTx(t.Context(), func(tx context.Context) error {
		_, observation := BeginObservation(tx, input)
		require.Nil(t, observation)
		return nil
	}))
	require.Equal(t, before+1, observationFailureCount("business_transaction_active"))
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 0)
}

func TestObservationCancellationBudgetAndGuardStage(t *testing.T) {
	enableObservation(t)
	input := observationInput(t)
	ctx, observation := BeginObservation(t.Context(), input)
	observation.remaining = 0
	before := observationFailureCount("observation_timeout")
	observation.Finish(ctx, NativeSuccess, StageOperation)
	require.Equal(t, before+1, observationFailureCount("observation_timeout"))
	ctx, observation = BeginObservation(t.Context(), input)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	before = observationFailureCount("observation_canceled")
	observation.Finish(canceled, NativeSuccess, StageOperation)
	require.Equal(t, before+1, observationFailureCount("observation_canceled"))
	input.Action = authz.Clone
	ctx, observation = BeginObservation(t.Context(), input)
	observation.Finish(ctx, NativeSuccess, StageAuthorization)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1})
	require.Equal(t, "unknown", record.NativeOutcome)
	require.Equal(t, "authorization", record.NativeStage)
	event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
	require.NotContains(t, audit_model.DecodeMetadata(event.Metadata), "mismatch")
	var snapshot map[string]any
	require.NoError(t, json.Unmarshal([]byte(record.SnapshotJSON), &snapshot))
	require.EqualValues(t, 2, snapshot["actor_id"])
}

func observationFailureCount(reason string) uint64 {
	value := new(dto.Metric)
	_ = metrics.EnterpriseAuthzObservationFailed.WithLabelValues(reason).Write(value)
	return uint64(value.GetCounter().GetValue())
}

type capturedLogWriter struct {
	*log.EventWriterBaseImpl
	bytes.Buffer
}

func (w *capturedLogWriter) Close() error { return nil }

func TestObservationFaultLogsAreBoundedAndNeverExposePayloads(t *testing.T) {
	enableObservation(t)
	writer := &capturedLogWriter{EventWriterBaseImpl: log.NewEventWriterBase("authz-fault-capture", "test", log.WriterMode{Level: log.WARN, Flags: log.FlagsFromBits(0)})}
	writer.Base().OutputWriteCloser = writer
	logger := log.GetManager().GetLogger(log.DEFAULT)
	logger.AddWriters(writer)
	t.Cleanup(func() { _ = logger.RemoveWriter(writer.GetWriterName()) })
	_, err := db.GetEngine(t.Context()).Exec(`CREATE TRIGGER authz_sensitive_audit_failure BEFORE INSERT ON audit_event BEGIN SELECT RAISE(ABORT, 'secret=TOPSECRET token=TOPTOKEN code=OAUTH https://callback.invalid/ phone=13800000000 mail=private@example.invalid path=private/secret'); END`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.GetEngine(context.WithoutCancel(t.Context())).Exec("DROP TRIGGER authz_sensitive_audit_failure")
		require.NoError(t, err)
	})
	observationWarnings.Lock()
	observationWarnings.last["evidence_persist_failed"] = time.Time{}
	observationWarnings.Unlock()
	for range 3 {
		ctx, observation := BeginObservation(t.Context(), observationInput(t))
		observation.Finish(ctx, NativeSuccess, StageOperation)
	}
	require.NoError(t, logger.RemoveWriter(writer.GetWriterName()))
	require.Equal(t, 1, strings.Count(writer.String(), "evidence_persist_failed"))
	for _, private := range []string{"TOPSECRET", "TOPTOKEN", "OAUTH", "callback.invalid", "13800000000", "private@example.invalid", "private/secret"} {
		require.NotContains(t, writer.String(), private)
	}
}

func TestObservationSnapshotsAndAuditExportRejectPrivateContextAndCredential(t *testing.T) {
	enableObservation(t)
	input := observationInput(t)
	private := "TOPSECRET-TOPTOKEN-OAUTH-13800000000-private@example.invalid-private/secret"
	input.Actor.Name, input.Repo.Name, input.Credential.Reference = private, private, "access-token:"+private
	input.ConditionContext.Branch, input.ConditionContext.BranchKnown = private, true
	input.ConditionContext.Paths, input.ConditionContext.PathsComplete = []string{private}, true
	ctx, observation := BeginObservation(t.Context(), input)
	observation.Finish(ctx, NativeSuccess, StageOperation)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1})
	data, err := json.Marshal(record)
	require.NoError(t, err)
	require.NotContains(t, string(data), private)
	event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
	require.Empty(t, event.ActorCredential)
	var exported bytes.Buffer
	require.NoError(t, audit.WriteEventsAsJSON(&exported, []*audit_model.Event{event}))
	require.NotContains(t, exported.String(), private)
}

func TestObservationRetryUsesOnlyObservationID(t *testing.T) {
	enableObservation(t)
	ctx, observation := BeginObservation(t.Context(), observationInput(t))
	observation.Finish(ctx, NativeSuccess, StageOperation)
	original := observation.record
	retry := original
	retry.NativeOutcome = "denied"
	require.NoError(t, persistObservation(t.Context(), &retry, "access-token:42"))
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 1)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, 1)
	stored := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ID: original.ID})
	require.Equal(t, "success", stored.NativeOutcome)
	retry.ObservationID = "trusted-different-observation"
	require.NoError(t, persistObservation(t.Context(), &retry, "access-token:42"))
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 2)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, 2)
	second := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ObservationID: "trusted-different-observation"})
	event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, unittest.Cond("metadata LIKE ?", "%trusted-different-observation%"))
	require.EqualValues(t, second.ID, audit_model.DecodeMetadata(event.Metadata)["decision_id"])
}

func TestObservationCanceledBeforeEvaluationHasNoPolicyRead(t *testing.T) {
	enableObservation(t)
	input := observationInput(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	before := observationFailureCount("observation_canceled")
	_, observation := BeginObservation(ctx, input)
	require.Nil(t, observation)
	require.Equal(t, before+1, observationFailureCount("observation_canceled"))
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 0)
}

func TestObservationSnapshotOverflowRecordsSafeErrorInsteadOfTruncation(t *testing.T) {
	enableObservation(t)
	input := observationInput(t)
	_, normalized, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	roles := make([]*authz_model.RoleDefinition, 0, 200)
	bindings := make([]*authz_model.SubjectRoleBinding, 0, 200)
	permissions := make([]*authz_model.RolePermission, 0, 200)
	for i := range int64(200) {
		id := 1000 + i
		name := fmt.Sprintf("role-%d", i)
		roles = append(roles, &authz_model.RoleDefinition{ID: id, ScopeType: authz_model.ScopeRepo, ScopeID: 1, Revision: 1, Name: name, LowerName: name})
		bindings = append(bindings, &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: 2, ScopeType: authz_model.ScopeRepo, ScopeID: 1, ScopeOwnerID: 2, RoleID: id})
		permissions = append(permissions, &authz_model.RolePermission{RoleID: id, Action: authz.Delete, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash})
	}
	require.NoError(t, db.Insert(t.Context(), roles))
	require.NoError(t, db.Insert(t.Context(), bindings))
	require.NoError(t, db.Insert(t.Context(), permissions))
	before := observationFailureCount("snapshot_limit_exceeded")
	ctx, observation := BeginObservation(t.Context(), input)
	observation.Finish(ctx, NativeSuccess, StageOperation)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1})
	require.Equal(t, "error", record.CandidateDecision)
	require.Equal(t, "snapshot_limit_exceeded", record.Reason)
	require.Less(t, len(record.SnapshotJSON), 64*1024)
	require.Equal(t, before+1, observationFailureCount("snapshot_limit_exceeded"))
	event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
	require.NotContains(t, audit_model.DecodeMetadata(event.Metadata), "mismatch")
}

func TestObservationGuardDenialValidatesTargetsWithinOneBudget(t *testing.T) {
	for _, scenario := range []string{"valid", "validation", "unrelated", "error", "timeout", "disabled", "read-only"} {
		t.Run(scenario, func(t *testing.T) {
			enableObservation(t)
			input := observationInput(t)
			setting.EnterpriseAuthz.Enabled = scenario != "disabled"
			input.Credential.Write = scenario != "read-only"
			called := false
			observe := ObserveGuardDenial
			if scenario == "validation" {
				observe = ObserveValidationFailure
			}
			observe(t.Context(), input, func(ctx context.Context) (bool, error) {
				called = true
				deadline, ok := ctx.Deadline()
				require.True(t, ok)
				require.LessOrEqual(t, time.Until(deadline), observationBudget)
				switch scenario {
				case "unrelated":
					return false, nil
				case "error":
					return false, errors.New("secret-token-OAuth-code-private@example.com/private/path")
				case "timeout":
					<-ctx.Done()
					return false, ctx.Err()
				default:
					return true, nil
				}
			})
			require.Equal(t, scenario != "disabled" && scenario != "read-only", called)
			count := 0
			if scenario == "valid" || scenario == "validation" {
				count = 1
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{})
				if scenario == "validation" {
					require.Equal(t, "failed", record.NativeOutcome)
					require.Equal(t, "operation", record.NativeStage)
					event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
					require.NotContains(t, audit_model.DecodeMetadata(event.Metadata), "mismatch")
				} else {
					require.Equal(t, "denied", record.NativeOutcome)
					require.Equal(t, "authorization", record.NativeStage)
				}
			}
			unittest.AssertCount(t, &authz_model.DecisionRecord{}, count)
			unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, count)
		})
	}
}

func TestObservationDetachedMergePreservesCredentialAndDeduplication(t *testing.T) {
	enableObservation(t)
	input := observationInput(t)
	input.Action = authz.MergePullRequest
	input.Credential = CredentialCeiling{Read: true, Write: false, Reference: "access-token:42"}
	requestInfo := reqctx.NewRequestContextForTest(t)
	audit.SetRequestInfo(requestInfo, audit_model.OriginAPI, "127.0.0.1")
	request, cancel := context.WithCancel(audit.WithImpersonator(requestInfo, &user_model.User{ID: 1, Name: "secret-admin"}))
	request, observation := WithObservationContext(request, input)
	type requestPermissionKey struct{}
	limited, cancelDeadline := context.WithTimeout(context.WithValue(request, requestPermissionKey{}, true), time.Second)
	defer cancelDeadline()
	require.NoError(t, db.WithTx(limited, func(tx context.Context) error {
		detached := DetachedObservationContext(t.Context(), tx)
		require.False(t, db.InTransaction(detached))
		require.Nil(t, detached.Value(requestPermissionKey{}))
		_, hasDeadline := detached.Deadline()
		require.False(t, hasDeadline)
		return nil
	}))
	cancel()
	background := DetachedObservationContext(t.Context(), request)
	require.NoError(t, background.Err())
	FinishOperationObservation(background, input.Actor.ID+1, input.Repo.ID, authz.MergePullRequest, NativeSuccess, StageOperation)
	require.Zero(t, unittest.GetCount(t, &authz_model.DecisionRecord{}))
	FinishOperationObservation(background, input.Actor.ID, input.Repo.ID, authz.MergePullRequest, NativeSuccess, StageOperation)
	observation.Finish(background, NativeFailed, StageOperation)
	require.Equal(t, 1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{})
	require.Equal(t, "deny", record.CandidateDecision)
	require.Equal(t, "success", record.NativeOutcome)
	require.Equal(t, "api", record.RequestSource)
	require.Contains(t, record.SnapshotJSON, `"write":false`)
	event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
	require.Equal(t, "access-token:42", event.ActorCredential)
	require.Equal(t, int64(1), event.ImpersonatorID)
	require.Equal(t, audit_model.OriginAPI, event.Origin)
	require.Equal(t, "127.0.0.1", event.IPAddress)
	require.NotContains(t, event.ImpersonatorName, "secret-admin")
	require.Contains(t, event.Metadata, `"mismatch":true`)
}

func TestObservationPermissionResolutionSharesBudgetAndDoesNotLeakErrors(t *testing.T) {
	enableObservation(t)
	writer := &capturedLogWriter{EventWriterBaseImpl: log.NewEventWriterBase("authz-resolve-capture", "test", log.WriterMode{Level: log.WARN, Flags: log.FlagsFromBits(0)})}
	writer.Base().OutputWriteCloser = writer
	logger := log.GetManager().GetLogger(log.DEFAULT)
	logger.AddWriters(writer)
	t.Cleanup(func() { _ = logger.RemoveWriter(writer.GetWriterName()) })
	observationWarnings.Lock()
	observationWarnings.last["observation_failed"] = time.Time{}
	observationWarnings.Unlock()
	input := observationInput(t)
	input.Permission = nil
	for _, result := range []string{"visible", "error", "timeout"} {
		t.Run(result, func(t *testing.T) {
			started := time.Now()
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			ctx, observation := BeginResolvedObservation(t.Context(), input, func(ctx context.Context) (*access_model.Permission, error) {
				switch result {
				case "error":
					return nil, errors.New("secret-token-OAuth-code-private@example.com/private/path")
				case "timeout":
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return observationInput(t).Permission, nil
			})
			require.NoError(t, ctx.Err())
			observation.Finish(ctx, NativeSuccess, StageOperation)
			if result == "visible" {
				require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			} else {
				require.Nil(t, observation)
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			}
			require.Less(t, time.Since(started), 400*time.Millisecond)
		})
	}
	require.NoError(t, logger.RemoveWriter(writer.GetWriterName()))
	require.Contains(t, writer.String(), "observation_failed")
	require.NotContains(t, writer.String(), "secret-token-OAuth-code-private@example.com/private/path")
	setting.EnterpriseAuthz.Enabled = false
	_, observation := BeginResolvedObservation(t.Context(), input, func(context.Context) (*access_model.Permission, error) {
		t.Fatal("disabled 不能解析或查询仓库权限")
		return &access_model.Permission{}, nil
	})
	require.Nil(t, observation)
}

func TestObservationVisibleNativeFallbackKeepsCredentialCeiling(t *testing.T) {
	enableObservation(t)
	input := observationInput(t)
	input.Credential = CredentialCeiling{Reference: "access-token:123"}
	_, err := db.Exec(t.Context(), "ALTER TABLE enterprise_subject_role_binding RENAME TO authz_fallback_binding")
	require.NoError(t, err)
	defer func() {
		_, err := db.Exec(t.Context(), "ALTER TABLE authz_fallback_binding RENAME TO enterprise_subject_role_binding")
		require.NoError(t, err)
	}()
	ctx, observation := BeginObservation(t.Context(), input)
	require.NotNil(t, observation)
	observation.Finish(ctx, NativeSuccess, StageTransport)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: input.Repo.ID, CandidateDecision: "deny", NativeOutcome: "success"})
	var snapshot roleSnapshot
	require.NoError(t, json.Unmarshal([]byte(record.SnapshotJSON), &snapshot))
	require.False(t, snapshot.Credential.Read)
	require.False(t, snapshot.Credential.Write)
	require.Empty(t, snapshot.NativeActions)
	require.Empty(t, snapshot.Definitions)
}
