// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"testing"

	actions_model "gitea.dev/models/actions"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"

	"github.com/stretchr/testify/require"
)

func TestActionsExecutionCurrentNativeOnlyAdmission(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 4})
	input := ExecutionInput{EvaluateInput: EvaluateInput{Actor: user_model.NewActionsUserWithTaskID(47), Repo: repo, Action: authz.MergePullRequest, Credential: CredentialCeiling{Read: true, Write: true, NativeOnly: true, Reference: "gitea-actions:47"}, ConditionContext: authz.ConditionContext{Source: "api"}}, Intent: "actions:merge:4"}
	ctx, admission, err := BeginExecution(t.Context(), []ExecutionInput{input})
	require.NoError(t, err)
	require.NotNil(t, admission)
	require.NoError(t, admission.Start(ctx))
	admission.Finish(ctx, NativeSuccess, StageOperation)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: user_model.ActionsUserID, Action: authz.MergePullRequest, DecisionMode: "enforce"})
	decoded, err := DecisionDTO(record)
	require.NoError(t, err)
	require.True(t, decoded.Snapshot.CredentialCeiling.NativeOnly)
	require.False(t, decoded.Snapshot.RoleEligible)
	require.Empty(t, decoded.Snapshot.Roles)
	_, err = db.Exec(t.Context(), "ALTER TABLE enterprise_subject_role_binding RENAME TO actions_roles_unavailable")
	require.NoError(t, err)
	defer func() {
		_, err := db.Exec(t.Context(), "ALTER TABLE actions_roles_unavailable RENAME TO enterprise_subject_role_binding")
		require.NoError(t, err)
	}()
	_, _, err = BeginExecution(t.Context(), []ExecutionInput{input})
	require.NoError(t, err)
	input.Action = authz.ManageSecret
	_, _, err = BeginExecution(t.Context(), []ExecutionInput{input})
	var rejection *ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, 403, rejection.Status)
	task := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionTask{ID: 47})
	task.Status = actions_model.StatusSuccess
	require.NoError(t, actions_model.UpdateTask(t.Context(), task, "status"))
	input.Action = authz.MergePullRequest
	_, _, err = BeginExecution(t.Context(), []ExecutionInput{input})
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, 403, rejection.Status)
}

func TestActionsExecutionRejectsForgedIdentityAndReadonly(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ExecutionInput)
	}{
		{"wrong-reference", func(in *ExecutionInput) { in.Credential.Reference = "gitea-actions:48" }},
		{"human-issuer", func(in *ExecutionInput) { in.Actor.ID = 5 }},
		{"foreign-ext-type", func(in *ExecutionInput) { in.Actor.ExtDoerData = user_model.NewDeployKeyUserWithKeyID(1).ExtDoerData }},
		{"not-native-only", func(in *ExecutionInput) { in.Credential.NativeOnly = false }},
		{"read-only", func(in *ExecutionInput) { in.Credential.Write = false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enableObservation(t)
			setting.EnterpriseAuthz.Enforce = true
			setting.EnterpriseAuthz.FailClosedOnError = false
			input := ExecutionInput{EvaluateInput: EvaluateInput{Actor: user_model.NewActionsUserWithTaskID(47), Repo: unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 4}), Action: authz.MergePullRequest, Credential: CredentialCeiling{Read: true, Write: true, NativeOnly: true, Reference: "gitea-actions:47"}, ConditionContext: authz.ConditionContext{Source: "api"}}, Intent: "actions:merge:4"}
			tc.mutate(&input)
			_, _, err := BeginExecution(t.Context(), []ExecutionInput{input})
			var rejection *ExecutionError
			require.ErrorAs(t, err, &rejection)
			require.Equal(t, 403, rejection.Status)
		})
	}
}
