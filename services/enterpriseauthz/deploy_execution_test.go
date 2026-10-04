// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"strconv"
	"testing"

	"gitea.dev/models/asymkey"
	"gitea.dev/models/db"
	deploykey_model "gitea.dev/models/deploykey"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/perm"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"

	"github.com/stretchr/testify/require"
)

func TestDeployExecutionHighRiskDoesNotBorrowOwner(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	key, err := deploykey_model.AddDeployKeyToken(t.Context(), 1, "machine-native", perm.AccessModeWrite)
	require.NoError(t, err)
	input := ExecutionInput{EvaluateInput: EvaluateInput{Actor: user_model.NewDeployKeyUserWithKeyID(key.ID), Repo: unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}), Action: authz.PushProtectedBranch, Credential: CredentialCeiling{Read: true, Write: true, NativeOnly: true, Reference: "deploy-key:" + strconv.FormatInt(key.ID, 10)}, ConditionContext: authz.ConditionContext{Source: "git_http", Branch: "master", BranchKnown: true}}, Intent: "deploy:push:1"}
	_, admission, err := BeginExecution(t.Context(), []ExecutionInput{input})
	var rejection *ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, "missing_action", rejection.Reason)
	require.Nil(t, admission)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: user_model.DeployKeyUserID, Action: authz.PushProtectedBranch, DecisionMode: "enforce"})
	decoded, err := DecisionDTO(record)
	require.NoError(t, err)
	require.True(t, decoded.Snapshot.CredentialCeiling.NativeOnly)
	require.False(t, decoded.Snapshot.RoleEligible)
	require.Empty(t, decoded.Snapshot.Roles)
	require.False(t, record.ExecutionStarted)
	require.NotContains(t, record.SnapshotJSON, key.Token)
}

func TestDeployExecutionCurrentScopeModeAndRevocation(t *testing.T) {
	enableObservation(t)
	key, err := deploykey_model.AddDeployKeyToken(t.Context(), 1, "machine-current", perm.AccessModeWrite)
	require.NoError(t, err)
	input := ExecutionInput{EvaluateInput: EvaluateInput{Actor: user_model.NewDeployKeyUserWithKeyID(key.ID), Repo: unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}), Action: authz.PushBranch, Credential: CredentialCeiling{Read: true, Write: true, NativeOnly: true, Reference: "deploy-key:" + strconv.FormatInt(key.ID, 10)}, ConditionContext: authz.ConditionContext{Source: "git_http"}}}
	_, err = db.Exec(t.Context(), "ALTER TABLE enterprise_subject_role_binding RENAME TO deploy_roles_unavailable")
	require.NoError(t, err)
	defer func() {
		_, err := db.Exec(t.Context(), "ALTER TABLE deploy_roles_unavailable RENAME TO enterprise_subject_role_binding")
		require.NoError(t, err)
	}()
	decision, err := authenticatedDeployExecutionActor(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, "allow", decision.CandidateDecision)
	_, err = db.GetEngine(t.Context()).ID(key.ID).Cols("mode").Update(&deploykey_model.DeployKey{Mode: perm.AccessModeRead})
	require.NoError(t, err)
	decision, err = authenticatedDeployExecutionActor(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, "deny", decision.CandidateDecision)
	input.Repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
	_, err = authenticatedDeployExecutionActor(t.Context(), input)
	var rejection *ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, 403, rejection.Status)
	input.Repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	_, err = db.DeleteByID[deploykey_model.DeployKey](t.Context(), key.ID)
	require.NoError(t, err)
	_, err = authenticatedDeployExecutionActor(t.Context(), input)
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, 403, rejection.Status)
}

func TestDeployExecutionRejectsForgedIdentityAndDeletedSSHKey(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	setting.EnterpriseAuthz.FailClosedOnError = false
	pkey := &asymkey.PublicKey{Type: asymkey.KeyTypeDeploy, Name: "machine-ssh", Content: "ssh-ed25519 machine-test"}
	require.NoError(t, db.Insert(t.Context(), pkey))
	key := &deploykey_model.DeployKey{RepoID: 1, KeyType: deploykey_model.KeyTypeSSH, KeyID: pkey.ID, Mode: perm.AccessModeWrite, Name: "machine-ssh"}
	require.NoError(t, db.Insert(t.Context(), key))
	input := ExecutionInput{EvaluateInput: EvaluateInput{Actor: user_model.NewDeployKeyUserWithKeyID(key.ID), Repo: unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}), Action: authz.PushBranch, Credential: CredentialCeiling{Read: true, Write: true, NativeOnly: true, Reference: "deploy-key:" + strconv.FormatInt(key.ID, 10)}, ConditionContext: authz.ConditionContext{Source: "ssh"}}, Intent: "deploy:ssh:1"}
	decision, err := authenticatedDeployExecutionActor(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, "allow", decision.CandidateDecision)
	for _, mutate := range []func(*ExecutionInput){
		func(in *ExecutionInput) { in.Actor = user_model.NewDeployKeyUserWithKeyID(key.ID); in.Actor.ID = 2 },
		func(in *ExecutionInput) { in.Credential.Reference = "deploy-key:999999" },
		func(in *ExecutionInput) { in.Credential.NativeOnly = false },
		func(in *ExecutionInput) { in.Actor = user_model.NewActionsUserWithTaskID(47) },
	} {
		forged := input
		forged.Action = authz.PushProtectedBranch
		mutate(&forged)
		_, _, err := BeginExecution(t.Context(), []ExecutionInput{forged})
		var rejection *ExecutionError
		require.ErrorAs(t, err, &rejection)
		require.Equal(t, 403, rejection.Status)
		require.Equal(t, "invalid_execution_context", rejection.Reason)
	}
	_, err = db.DeleteByID[asymkey.PublicKey](t.Context(), pkey.ID)
	require.NoError(t, err)
	_, err = authenticatedDeployExecutionActor(t.Context(), input)
	var rejection *ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, 403, rejection.Status)
}
