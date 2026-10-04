// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/git"
	"gitea.dev/modules/json"
	"gitea.dev/modules/log"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/timeutil"
	"gitea.dev/modules/util"
	"gitea.dev/services/audit"

	"github.com/stretchr/testify/require"
)

func TestMigrationFailureAuditScopesDeduplicationAndRetention(t *testing.T) {
	enableObservation(t)
	actor := &user_model.User{ID: 2, Name: "secret-token-private@example.com", Email: "private@example.com"}
	ctx := WithMigrationSource(reqctx.NewRequestContextForTest(t), "api")
	ctx = audit.WithImpersonator(ctx, &user_model.User{ID: 1, Name: "private-admin@example.com"})
	for range 2 {
		RecordMigrationFailure(ctx, actor, 3, "validate_source", "source_policy_denied")
	}
	RecordMigrationFailure(WithMigrationSource(t.Context(), "web"), actor, 0, "site_policy", "migration_disabled")
	RecordMigrationFailure(WithMigrationSource(t.Context(), "system"), nil, 0, "prepare_task", "task_creation_failed")
	var records []audit_model.Event
	require.NoError(t, db.GetEngine(t.Context()).Where("action = ?", audit_model.EnterpriseAuthzMigrationFailure).Asc("id").Find(&records))
	require.Len(t, records, 3)
	require.Equal(t, audit_model.ScopeUser, records[0].ScopeType)
	require.EqualValues(t, 2, records[0].ScopeID)
	require.EqualValues(t, 1, records[0].ImpersonatorID)
	require.Equal(t, audit_model.ScopeSystem, records[2].ScopeType)
	require.Zero(t, records[2].ScopeID)
	require.Zero(t, records[2].ActorID)
	ids := map[string]bool{}
	for _, record := range records {
		metadata := audit_model.DecodeMetadata(record.Metadata)
		id, ok := metadata["operation_id"].(string)
		require.True(t, ok)
		require.Len(t, id, 26)
		require.False(t, ids[id])
		ids[id] = true
		for _, key := range []string{"repo_id", "candidate_decision", "mismatch", "snapshot", "credential"} {
			require.NotContains(t, metadata, key)
		}
		exported, err := json.Marshal(record)
		require.NoError(t, err)
		require.NotContains(t, string(exported), "secret-token")
		require.NotContains(t, string(exported), "private@example.com")
		require.NotContains(t, string(exported), "private-admin")
	}
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 0)
	old := timeutil.TimeStamp(time.Now().Add(-48 * time.Hour).Unix())
	_, err := db.GetEngine(t.Context()).Where("action = ?", audit_model.EnterpriseAuthzMigrationFailure).Cols("timestamp_unix").Update(&audit_model.Event{TimestampUnix: old})
	require.NoError(t, err)
	require.NoError(t, audit.DeleteOldEvents(t.Context(), 0))
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzMigrationFailure}, 3)
	require.NoError(t, audit.DeleteOldEvents(t.Context(), 24*time.Hour))
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzMigrationFailure}, 0)
}

func TestMigrationFailureAuditRejectsUntrustedContext(t *testing.T) {
	enableObservation(t)
	actor := &user_model.User{ID: 2}
	before := observationFailureCount("invalid_observation_context")
	for _, tc := range []struct {
		source, stage, reason string
		actor                 *user_model.User
		owner                 int64
	}{
		{"private-token", "validate_source", "source_invalid", actor, 0},
		{"api", "private-path", "source_invalid", actor, 0},
		{"api", "validate_source", "private-token", actor, 0},
		{"api", "validate_source", "source_invalid", nil, 0},
		{"", "validate_source", "source_invalid", nil, 0},
		{"system", "validate_source", "source_invalid", &user_model.User{ID: -1}, 0},
		{"api", "validate_source", "source_invalid", actor, -1},
	} {
		RecordMigrationFailure(WithMigrationSource(t.Context(), tc.source), tc.actor, tc.owner, tc.stage, tc.reason)
	}
	require.Equal(t, before+7, observationFailureCount("invalid_observation_context"))
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzMigrationFailure}, 0)
}

func TestMigrationFailureAuditFaultsAreBoundedAndSafe(t *testing.T) {
	enableObservation(t)
	writer := &capturedLogWriter{EventWriterBaseImpl: log.NewEventWriterBase("authz-migration-fault-capture", "test", log.WriterMode{Level: log.WARN, Flags: log.FlagsFromBits(0)})}
	writer.Base().OutputWriteCloser = writer
	logger := log.GetManager().GetLogger(log.DEFAULT)
	logger.AddWriters(writer)
	t.Cleanup(func() { _ = logger.RemoveWriter(writer.GetWriterName()) })
	_, err := db.Exec(t.Context(), `CREATE TRIGGER migration_sensitive_audit_failure BEFORE INSERT ON audit_event BEGIN SELECT RAISE(ABORT, 'secret=TOPSECRET token=TOPTOKEN code=OAUTH https://callback.invalid/ phone=13800000000 mail=private@example.invalid path=private/secret'); END`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.Exec(context.WithoutCancel(t.Context()), "DROP TRIGGER migration_sensitive_audit_failure")
		require.NoError(t, err)
	})
	observationWarnings.Lock()
	observationWarnings.last["evidence_persist_failed"] = time.Time{}
	observationWarnings.Unlock()
	before := observationFailureCount("evidence_persist_failed")
	for range 3 {
		RecordMigrationFailure(WithMigrationSource(t.Context(), "system"), &user_model.User{ID: 2}, 0, "create_target", "target_creation_failed")
	}
	require.Equal(t, before+3, observationFailureCount("evidence_persist_failed"))
	require.NoError(t, logger.RemoveWriter(writer.GetWriterName()))
	require.Equal(t, 1, strings.Count(writer.String(), "evidence_persist_failed"))
	for _, private := range []string{"TOPSECRET", "TOPTOKEN", "OAUTH", "callback.invalid", "13800000000", "private@example.invalid", "private/secret"} {
		require.NotContains(t, writer.String(), private)
	}
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzMigrationFailure}, 0)
	for _, tc := range []struct {
		name, reason string
		ctx          context.Context
	}{
		{"canceled", "observation_canceled", func() context.Context { ctx, cancel := context.WithCancel(t.Context()); cancel(); return ctx }()},
		{"timeout", "observation_timeout", func() context.Context {
			ctx, cancel := context.WithDeadline(t.Context(), time.Time{})
			cancel()
			return ctx
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := observationFailureCount(tc.reason)
			RecordMigrationFailure(WithMigrationSource(tc.ctx, "system"), &user_model.User{ID: 2}, 0, "create_target", "target_creation_failed")
			require.Equal(t, before+1, observationFailureCount(tc.reason))
		})
	}
	before = observationFailureCount("business_transaction_active")
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		RecordMigrationFailure(WithMigrationSource(ctx, "system"), &user_model.User{ID: 2}, 0, "create_target", "target_creation_failed")
		return nil
	}))
	require.Equal(t, before+1, observationFailureCount("business_transaction_active"))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, false))
	before = observationFailureCount("evidence_persist_failed")
	RecordMigrationFailure(WithMigrationSource(t.Context(), "system"), &user_model.User{ID: 2}, 0, "create_target", "target_creation_failed")
	require.Equal(t, before, observationFailureCount("evidence_persist_failed"))
}

func TestMigrationFailureReasonsDoNotExposeErrors(t *testing.T) {
	for _, tc := range []struct {
		err    error
		reason string
	}{
		{fmt.Errorf("wrapped: %w", &git.ErrInvalidCloneAddr{Host: "secret-token", IsPermissionDenied: true}), "source_policy_denied"},
		{&git.ErrInvalidCloneAddr{Host: "private-path", IsURLError: true}, "source_invalid"},
		{errors.New("TOPSECRET"), "source_check_failed"},
	} {
		require.Equal(t, tc.reason, MigrationSourceFailureReason(tc.err))
	}
	for _, tc := range []struct {
		err    error
		reason string
	}{
		{repo_model.ErrRepoAlreadyExist{Uname: "private@example.com", Name: "secret-token"}, "repository_name_conflict"},
		{repo_model.ErrReachLimitOfRepo{Limit: 0}, "quota_exceeded"},
		{util.NewPermissionDeniedErrorf("TOPSECRET"), "target_permission_denied"},
		{db.ErrNameReserved{Name: "TOPSECRET"}, "repository_name_invalid"},
		{errors.New("secret-token https://callback/private"), "target_creation_failed"},
	} {
		require.Equal(t, tc.reason, MigrationTargetFailureReason(tc.err))
	}
}

func TestMigrationFailureTargetMarkerFollowsOutermostCommit(t *testing.T) {
	enableObservation(t)
	for _, rollback := range []bool{false, true} {
		ctx := WithMigrationSource(t.Context(), "system")
		before := unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzMigrationFailure})
		err := db.WithTx(ctx, func(tx context.Context) error {
			MarkMigrationTargetCreated(tx, 42)
			if rollback {
				return errors.New("native_rollback")
			}
			return nil
		})
		if rollback {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
		RecordMigrationFailure(ctx, &user_model.User{ID: 2}, 0, "create_target", "target_creation_failed")
		want := before
		if rollback {
			want++
		}
		require.Equal(t, want, unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzMigrationFailure}))
	}
}
