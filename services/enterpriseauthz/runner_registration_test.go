// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"testing"

	actions_model "gitea.dev/models/actions"
	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"

	"github.com/stretchr/testify/require"
)

func TestRunnerRegistrationExecutionMachineScope(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	token := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunnerToken{ID: 4})
	ctx, admission, err := BeginRunnerRegistrationExecution(t.Context(), token)
	require.NoError(t, err)
	require.NotNil(t, admission)
	require.NoError(t, admission.Start(ctx))
	require.NoError(t, RequireExecution(ctx, 1, authz.ManageCI, "runner-registration:1:4"))
	require.Error(t, RequireExecution(ctx, 1, authz.ManageSecret, "runner-registration:1:4"))
	admission.Finish(ctx, NativeSuccess, StageOperation)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 0, RepoID: 1, Action: authz.ManageCI, DecisionMode: "enforce"})
	require.Equal(t, "native_action", record.Reason)
	require.NotContains(t, record.SnapshotJSON, token.Token)
	decoded, err := DecisionDTO(record)
	require.NoError(t, err)
	require.True(t, decoded.Snapshot.CredentialCeiling.NativeOnly)
	require.False(t, decoded.Snapshot.RoleEligible)
	require.Equal(t, []string{string(authz.ManageCI)}, decoded.Snapshot.NativeActions)
	require.Empty(t, decoded.Snapshot.Roles)
}

func TestRunnerRegistrationExecutionRevalidatesToken(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*actions_model.ActionRunnerToken) string
	}{
		{"revoked", func(token *actions_model.ActionRunnerToken) string { token.IsActive = false; return "is_active" }},
		{"changed-token", func(token *actions_model.ActionRunnerToken) string {
			token.Token = "SENSITIVE-replaced"
			return "token"
		}},
		{"changed-scope", func(token *actions_model.ActionRunnerToken) string { token.RepoID = 2; return "repo_id" }},
		{"mixed-scope", func(token *actions_model.ActionRunnerToken) string { token.OwnerID = 2; return "owner_id" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enableObservation(t)
			setting.EnterpriseAuthz.Enforce = true
			setting.EnterpriseAuthz.FailClosedOnError = false
			stale := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunnerToken{ID: 4})
			current := *stale
			col := tc.mutate(&current)
			require.NoError(t, actions_model.UpdateRunnerToken(t.Context(), &current, col))
			before, err := db.GetEngine(t.Context()).Where("execution_started = ?", true).Count(new(authz_model.DecisionRecord))
			require.NoError(t, err)
			_, admission, err := BeginRunnerRegistrationExecution(t.Context(), stale)
			var rejection *ExecutionError
			require.ErrorAs(t, err, &rejection)
			require.Equal(t, 403, rejection.Status)
			require.Equal(t, "invalid_execution_context", rejection.Reason)
			require.Nil(t, admission)
			after, err := db.GetEngine(t.Context()).Where("execution_started = ?", true).Count(new(authz_model.DecisionRecord))
			require.NoError(t, err)
			require.Equal(t, before, after)
			record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.ManageCI, DecisionMode: "enforce"})
			require.False(t, record.ExecutionStarted)
			require.Equal(t, "error", record.AuthorizationDecision)
			require.Equal(t, "unknown", record.NativeOutcome)
			var event audit_model.Event
			found, err := db.GetEngine(t.Context()).Where("action = ? AND metadata LIKE ?", audit_model.EnterpriseAuthzDecision, "%"+record.ObservationID+"%").Get(&event)
			require.NoError(t, err)
			require.True(t, found)
			require.EqualValues(t, 0, event.ActorID)
			require.Equal(t, "runner-registration-token:4", event.ActorCredential)
			require.Equal(t, false, audit_model.DecodeMetadata(event.Metadata)["execution_started"])
		})
	}
}

func TestRunnerRegistrationExecutionDoesNotBorrowHumanIdentity(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	token := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunnerToken{ID: 4})
	_, err := db.Exec(t.Context(), "ALTER TABLE enterprise_subject_role_binding RENAME TO runner_binding_unavailable")
	require.NoError(t, err)
	defer func() {
		_, err := db.Exec(t.Context(), "ALTER TABLE runner_binding_unavailable RENAME TO enterprise_subject_role_binding")
		require.NoError(t, err)
	}()
	_, admission, err := BeginRunnerRegistrationExecution(t.Context(), token)
	require.NoError(t, err)
	require.NotNil(t, admission)
	for _, id := range []int64{1, 3} {
		nonRepo := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunnerToken{ID: id})
		_, admission, err := BeginRunnerRegistrationExecution(t.Context(), nonRepo)
		require.NoError(t, err)
		require.Nil(t, admission)
	}
	_, admission, err = BeginRunnerRegistrationExecution(t.Context(), nil)
	require.Error(t, err)
	require.Nil(t, admission)
}
