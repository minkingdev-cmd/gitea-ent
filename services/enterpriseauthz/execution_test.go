// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"
	"strconv"
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
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func executionInput(t *testing.T) ExecutionInput {
	t.Helper()
	return ExecutionInput{EvaluateInput: observationInput(t), Intent: "delete:repo:1"}
}

func TestExecutionDenialPrecedesMutation(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	setting.EnterpriseAuthz.FailClosedOnError = true
	input := executionInput(t)
	input.Actor = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	_, admission, err := BeginExecution(t.Context(), []ExecutionInput{input})
	var denied *ExecutionError
	require.ErrorAs(t, err, &denied)
	require.Equal(t, 403, denied.Status)
	require.Nil(t, admission)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.Delete})
	require.Equal(t, "enforce", record.DecisionMode)
	require.Equal(t, "deny", record.AuthorizationDecision)
	require.False(t, record.ExecutionStarted)
	require.Equal(t, "unknown", record.NativeOutcome)
}

func TestExecutionOwnerEvidenceAndOutcome(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	setting.EnterpriseAuthz.FailClosedOnError = true
	input := executionInput(t)
	input.Permission = nil
	ctx, admission, err := BeginExecution(t.Context(), []ExecutionInput{input, input})
	require.NoError(t, err)
	require.NotNil(t, admission)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.Delete})
	require.Equal(t, "allow", record.AuthorizationDecision)
	require.False(t, record.ExecutionStarted)
	require.Equal(t, "unknown", record.NativeOutcome)
	require.NoError(t, admission.Start(ctx))
	require.NoError(t, RequireExecution(ctx, input.Repo.ID, input.Action, input.Intent))
	require.Error(t, RequireExecution(ctx, input.Repo.ID, input.Action, "different-intent"))
	require.Error(t, RequireExecution(t.Context(), input.Repo.ID, input.Action, input.Intent))
	record = unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.Delete})
	require.True(t, record.ExecutionStarted)
	admission.Finish(ctx, NativeFailed, StageOperation)
	admission.Finish(ctx, NativeSuccess, StageOperation)
	record = unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.Delete})
	require.Equal(t, "failed", record.NativeOutcome)
	require.Error(t, RequireExecution(ctx, input.Repo.ID, input.Action, input.Intent))
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 1)
}

func TestExecutionRejectsStaleManagementAuthority(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	setting.EnterpriseAuthz.FailClosedOnError = true
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom.Enabled, true))
	input := executionInput(t)
	input.Actor = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	_, admission, err := BeginExecution(t.Context(), []ExecutionInput{input})
	require.Error(t, err)
	require.Nil(t, admission)
}

func TestExecutionIncompleteCodeownersNeverFallsOpen(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	setting.EnterpriseAuthz.FailClosedOnError = false
	input := executionInput(t)
	input.Action = authz.ManageCodeowners
	_, admission, err := BeginExecution(t.Context(), []ExecutionInput{input})
	require.Error(t, err)
	require.Nil(t, admission)
}

func TestExecutionDisabledAndShadowSkipPreparation(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			enableObservation(t)
			setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce = enabled, false
			_, admission, err := BeginPreparedExecution(t.Context(), func(context.Context) ([]ExecutionInput, error) {
				t.Fatal("unexpected policy preparation")
				return nil, nil
			})
			require.NoError(t, err)
			require.Nil(t, admission)
			unittest.AssertCount(t, &authz_model.DecisionRecord{}, 0)
		})
	}
}

func TestExecutionCancellationLimitsAndTransactionCannotFallback(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	setting.EnterpriseAuthz.FailClosedOnError = false
	input := executionInput(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, admission, err := BeginExecution(ctx, []ExecutionInput{input})
	require.Error(t, err)
	require.Nil(t, admission)
	input.ConditionContext.Paths = make([]string, authz.MaxContextPaths+1)
	_, admission, err = BeginExecution(t.Context(), []ExecutionInput{input})
	require.Error(t, err)
	require.Nil(t, admission)
	input = executionInput(t)
	require.NoError(t, db.WithTx(t.Context(), func(tx context.Context) error {
		_, admission, err := BeginExecution(tx, []ExecutionInput{input})
		require.Error(t, err)
		require.Nil(t, admission)
		return nil
	}))
}

func TestExecutionEvidenceFailureHasNoPartialAudit(t *testing.T) {
	for _, failClosed := range []bool{true, false} {
		t.Run(strconv.FormatBool(failClosed), func(t *testing.T) {
			enableObservation(t)
			setting.EnterpriseAuthz.Enforce = true
			setting.EnterpriseAuthz.FailClosedOnError = failClosed
			_, dropErr := db.GetEngine(t.Context()).Exec("DROP TABLE audit_event")
			require.NoError(t, dropErr)
			input := executionInput(t)
			ctx, admission, err := BeginExecution(t.Context(), []ExecutionInput{input})
			if failClosed {
				require.Error(t, err)
				require.Nil(t, admission)
			} else {
				require.NoError(t, err)
				require.NotNil(t, admission)
				require.NoError(t, admission.Start(ctx))
			}
			unittest.AssertCount(t, &authz_model.DecisionRecord{}, 0)
			require.NoError(t, db.GetEngine(t.Context()).Sync(new(audit_model.Event)))
		})
	}
}

func TestExecutionRoleRevocationBeforeAdmissionAndNewRetries(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	setting.EnterpriseAuthz.FailClosedOnError = true
	input := executionInput(t)
	input.Actor = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: input.Repo.ID, Name: "delete-grant", LowerName: "delete-grant", Revision: 1}
	require.NoError(t, db.Insert(t.Context(), role))
	_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: input.Action, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
	binding := &authz_model.SubjectRoleBinding{RoleID: role.ID, SubjectType: authz_model.SubjectUser, SubjectID: input.Actor.ID, ScopeType: authz_model.ScopeRepo, ScopeID: input.Repo.ID, ScopeOwnerID: input.Repo.OwnerID}
	require.NoError(t, db.Insert(t.Context(), binding))
	ctx, admitted, err := BeginExecution(t.Context(), []ExecutionInput{input})
	require.NoError(t, err)
	require.NoError(t, admitted.Start(ctx))
	_, err = db.GetEngine(t.Context()).ID(binding.ID).Delete(new(authz_model.SubjectRoleBinding))
	require.NoError(t, err)
	require.NoError(t, RequireExecution(ctx, input.Repo.ID, input.Action, input.Intent))
	admitted.Finish(ctx, NativeFailed, StageOperation)
	_, retry, err := BeginExecution(ctx, []ExecutionInput{input})
	require.Error(t, err)
	require.Nil(t, retry)
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 2)
}

func TestExecutionCredentialCeilingDoesNotExpandWithRole(t *testing.T) {
	for _, variant := range []string{"readonly", "action-ceiling", "native-only"} {
		t.Run(variant, func(t *testing.T) {
			enableObservation(t)
			setting.EnterpriseAuthz.Enforce = true
			setting.EnterpriseAuthz.FailClosedOnError = true
			input := executionInput(t)
			switch variant {
			case "readonly":
				input.Credential.Write = false
			case "action-ceiling":
				input.Credential.Actions = []authz.Action{authz.ManageAccess}
			case "native-only":
				input.Actor = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
				input.Credential.NativeOnly = true
			}
			_, admitted, err := BeginExecution(t.Context(), []ExecutionInput{input})
			require.Error(t, err)
			require.Nil(t, admitted)
		})
	}
}

func TestExecutionCompoundExplicitDenialPrecedesInfrastructureFallback(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	setting.EnterpriseAuthz.FailClosedOnError = false
	input := executionInput(t)
	input.Credential.Write = false
	bad := executionInput(t)
	bad.Repo = &repo_model.Repository{ID: 987654, OwnerID: input.Repo.OwnerID}
	_, admitted, err := BeginExecution(t.Context(), []ExecutionInput{input, bad})
	var denied *ExecutionError
	require.ErrorAs(t, err, &denied)
	require.Equal(t, 403, denied.Status)
	require.Equal(t, "native_visibility_denied", denied.Reason)
	require.Nil(t, admitted)
	unittest.AssertCount(t, &authz_model.DecisionRecord{AuthorizationDecision: "deny", ExecutionStarted: false}, 2)
}

func TestExecutionBudgetAndSafePreparationFailure(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	setting.EnterpriseAuthz.FailClosedOnError = true
	started := time.Now()
	_, admitted, err := BeginPreparedExecution(t.Context(), func(ctx context.Context) ([]ExecutionInput, error) { <-ctx.Done(); return nil, ctx.Err() })
	var failure *ExecutionError
	require.ErrorAs(t, err, &failure)
	require.Equal(t, 503, failure.Status)
	require.Equal(t, "execution_timeout", failure.Reason)
	require.Nil(t, admitted)
	require.Less(t, time.Since(started), 2*time.Second)
	setting.EnterpriseAuthz.FailClosedOnError = false
	_, _, err = BeginPreparedExecution(t.Context(), func(context.Context) ([]ExecutionInput, error) {
		return nil, &ExecutionError{Reason: "invalid_execution_context", Status: 403}
	})
	require.ErrorAs(t, err, &failure)
	require.Equal(t, 403, failure.Status)
}

func TestExecutionNonRecoverableContextOverridesInfrastructureFallback(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	setting.EnterpriseAuthz.FailClosedOnError = false
	missing := executionInput(t)
	missing.Repo = &repo_model.Repository{ID: 987654, OwnerID: 2}
	changed := executionInput(t)
	changed.Repo = &repo_model.Repository{ID: 1, OwnerID: 999}
	_, admitted, err := BeginExecution(t.Context(), []ExecutionInput{missing, changed})
	require.Error(t, err)
	require.Nil(t, admitted)
}

func TestExecutionPostEvidenceFailurePreservesRealSuccess(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	setting.EnterpriseAuthz.FailClosedOnError = true
	input := executionInput(t)
	ctx, admitted, err := BeginExecution(t.Context(), []ExecutionInput{input})
	require.NoError(t, err)
	require.NoError(t, admitted.Start(ctx))
	_, err = db.GetEngine(t.Context()).Exec("DROP TABLE audit_event")
	require.NoError(t, err)
	admitted.Finish(ctx, NativeSuccess, StageOperation)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: input.Action})
	require.Equal(t, "unknown", record.NativeOutcome)
	require.True(t, record.ExecutionStarted)
	require.NoError(t, db.GetEngine(t.Context()).Sync(new(audit_model.Event)))
}

func TestExecutionHandleFreezesActorOwnerAndCredential(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	setting.EnterpriseAuthz.FailClosedOnError = true
	input := executionInput(t)
	ctx, admitted, err := BeginExecution(t.Context(), []ExecutionInput{input})
	require.NoError(t, err)
	require.NoError(t, admitted.Start(ctx))
	originalOwner := input.Repo.OwnerID
	input.Repo.OwnerID = originalOwner + 10
	require.Error(t, RequireExecutionTarget(ctx, input.Repo, input.Action, input.Intent))
	input.Repo.OwnerID = originalOwner
	input.Credential.Write = false
	require.Error(t, RequireExecutionInput(ctx, input))
	input.Credential.Write = true
	input.Actor.ID++
	require.Error(t, RequireExecutionInput(ctx, input))
}

func TestExecutionNativePreparationErrorCannotFallbackOrLeak(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	setting.EnterpriseAuthz.FailClosedOnError = false
	_, admitted, err := BeginPreparedExecution(t.Context(), func(context.Context) ([]ExecutionInput, error) {
		return nil, errors.New("native signature check failed: private branch and body")
	})
	var failure *ExecutionError
	require.ErrorAs(t, err, &failure)
	require.Equal(t, 403, failure.Status)
	require.Equal(t, "invalid_execution_context", failure.Reason)
	require.Nil(t, admitted)
	require.NotContains(t, err.Error(), "private")
	_, admitted, err = BeginPreparedExecution(t.Context(), func(context.Context) ([]ExecutionInput, error) {
		return nil, &ExecutionError{Reason: "policy_read_failed", Status: 503}
	})
	require.ErrorAs(t, err, &failure)
	require.Equal(t, 503, failure.Status)
	require.Nil(t, admitted)
}

func TestExecutionSettingsRoleDoesNotReplaceCurrentNativeAdmin(t *testing.T) {
	for _, action := range []authz.Action{authz.ManageBranchProtection, authz.ManageWebhook, authz.ManageCI, authz.ManageSecret} {
		t.Run(string(action), func(t *testing.T) {
			enableObservation(t)
			setting.EnterpriseAuthz.Enforce = true
			setting.EnterpriseAuthz.FailClosedOnError = false
			input := executionInput(t)
			input.Actor = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
			input.Action, input.Intent = action, SettingsIntent(action, "native-revoked")
			input.ConditionContext.Source = "web"
			require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: input.Repo.ID, UserID: 4, Mode: perm.AccessModeRead}))
			require.NoError(t, db.Insert(t.Context(), &access_model.Access{RepoID: input.Repo.ID, UserID: 4, Mode: perm.AccessModeRead}))
			if action == authz.ManageSecret {
				require.NoError(t, db.Insert(t.Context(), &repo_model.RepoUnit{RepoID: input.Repo.ID, Type: unit.TypeActions}))
			}
			role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: input.Repo.ID, Name: "settings-grant", LowerName: "settings-grant", Revision: 1}
			require.NoError(t, db.Insert(t.Context(), role))
			_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
			require.NoError(t, err)
			require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: action, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
			require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{RoleID: role.ID, SubjectType: authz_model.SubjectUser, SubjectID: 4, ScopeType: authz_model.ScopeRepo, ScopeID: input.Repo.ID, ScopeOwnerID: input.Repo.OwnerID}))
			permission, err := access_model.GetDoerRepoPermission(t.Context(), input.Repo, input.Actor)
			require.NoError(t, err)
			input.Permission = &permission
			candidate, err := Evaluate(t.Context(), input.EvaluateInput)
			require.NoError(t, err)
			require.Equal(t, "allow", candidate.CandidateDecision)
			_, admission, err := BeginExecution(t.Context(), []ExecutionInput{input})
			var rejection *ExecutionError
			require.ErrorAs(t, err, &rejection)
			require.Equal(t, 403, rejection.Status)
			require.Nil(t, admission)
			row := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, Action: action})
			require.False(t, row.ExecutionStarted)
		})
	}
}

func TestExecutionNativeIdentityReadFailureCannotFallback(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	setting.EnterpriseAuthz.FailClosedOnError = false
	input := executionInput(t)
	_, err := db.GetEngine(t.Context()).Exec("ALTER TABLE `user` RENAME TO authz_user_unavailable")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.GetEngine(context.WithoutCancel(t.Context())).Exec("ALTER TABLE authz_user_unavailable RENAME TO `user`")
		require.NoError(t, err)
	})
	_, admission, err := BeginExecution(t.Context(), []ExecutionInput{input})
	var rejection *ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, 503, rejection.Status)
	require.Equal(t, "policy_read_failed", rejection.Reason)
	require.Nil(t, admission)
}

func TestExecutionStartEvidenceFallbackRecoversActualTerminal(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	setting.EnterpriseAuthz.FailClosedOnError = false
	input := executionInput(t)
	ctx, admitted, err := BeginExecution(t.Context(), []ExecutionInput{input})
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Exec("CREATE TRIGGER authz_start_fault BEFORE UPDATE OF execution_started ON enterprise_authz_decision BEGIN SELECT RAISE(ABORT, 'start evidence fault'); END")
	require.NoError(t, err)
	require.NoError(t, admitted.Start(ctx))
	_, err = db.GetEngine(t.Context()).Exec("DROP TRIGGER authz_start_fault")
	require.NoError(t, err)
	admitted.Finish(ctx, NativeSuccess, StageOperation)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: input.Action})
	require.True(t, record.ExecutionStarted)
	require.Equal(t, "fallback", record.AuthorizationDecision)
	require.Equal(t, "evidence_persist_failed", record.AuthorizationReason)
	require.Equal(t, "success", record.NativeOutcome)
	event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
	require.Contains(t, event.Metadata, `"execution_started":true`)
	require.Contains(t, event.Metadata, `"authorization_decision":"fallback"`)
	require.NotContains(t, event.Metadata, `"mismatch"`)
}
