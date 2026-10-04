// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"slices"

	actions_model "gitea.dev/models/actions"
	"gitea.dev/models/db"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
)

func BeginRunnerRegistrationExecution(ctx context.Context, verifiedToken *actions_model.ActionRunnerToken) (context.Context, *Admission, error) {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return ctx, nil, nil
	}
	if verifiedToken == nil || verifiedToken.ID <= 0 || verifiedToken.RepoID < 0 || verifiedToken.OwnerID < 0 {
		return ctx, nil, &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	}
	if verifiedToken.RepoID == 0 {
		return ctx, nil, nil
	}
	if verifiedToken.OwnerID != 0 || !verifiedToken.IsActive || verifiedToken.Deleted != 0 || verifiedToken.Token == "" {
		return ctx, nil, &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	}
	return BeginPreparedExecution(ctx, func(ctx context.Context) ([]ExecutionInput, error) {
		repo, err := repo_model.GetRepositoryByID(ctx, verifiedToken.RepoID)
		if err != nil {
			if repo_model.IsErrRepoNotExist(err) {
				return nil, &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
			}
			return nil, errors.New("policy_read_failed")
		}
		input := ExecutionInput{EvaluateInput: EvaluateInput{Repo: repo, Action: authz.ManageCI, Credential: CredentialCeiling{Read: true, Write: true, NativeOnly: true, Actions: []authz.Action{authz.ManageCI}, Reference: fmt.Sprintf("runner-registration-token:%d", verifiedToken.ID)}, ConditionContext: authz.ConditionContext{Source: "system"}}, Intent: fmt.Sprintf("runner-registration:%d:%d", repo.ID, verifiedToken.ID), registrationTokenID: verifiedToken.ID, registrationTokenHash: sha256.Sum256([]byte(verifiedToken.Token)), registrationCheck: evaluateRunnerRegistration}
		return []ExecutionInput{input}, nil
	})
}

func evaluateRunnerRegistration(ctx context.Context, input ExecutionInput) (Decision, error) {
	ownerID := int64(0)
	if input.Repo != nil {
		ownerID = input.Repo.OwnerID
	}
	failure := Decision{Action: input.Action, CandidateDecision: "error", Reason: "invalid_evaluation_context", CandidateOnly: true, ownerID: ownerID}
	invalid := func() (Decision, error) {
		return failure, &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	}
	if input.Repo == nil || input.Repo.ID <= 0 || input.Actor != nil || input.registrationTokenID <= 0 || input.Action != authz.ManageCI || input.ConditionContext.Source != "system" || !input.Credential.NativeOnly || !input.Credential.Read || !input.Credential.Write || !slices.Equal(input.Credential.Actions, []authz.Action{authz.ManageCI}) || input.Credential.Reference != fmt.Sprintf("runner-registration-token:%d", input.registrationTokenID) || input.Intent != fmt.Sprintf("runner-registration:%d:%d", input.Repo.ID, input.registrationTokenID) {
		return invalid()
	}
	token, exists, err := db.GetByID[actions_model.ActionRunnerToken](ctx, input.registrationTokenID)
	if err != nil {
		failure.Reason = "policy_read_failed"
		return failure, errors.New("policy_read_failed")
	}
	if !exists || !token.IsActive || token.Deleted != 0 || token.OwnerID != 0 || token.RepoID != input.Repo.ID {
		return invalid()
	}
	tokenHash := sha256.Sum256([]byte(token.Token))
	if subtle.ConstantTimeCompare(tokenHash[:], input.registrationTokenHash[:]) != 1 {
		return invalid()
	}
	repo, err := repo_model.GetRepositoryByID(ctx, token.RepoID)
	if err != nil {
		if repo_model.IsErrRepoNotExist(err) {
			return invalid()
		}
		failure.Reason = "policy_read_failed"
		return failure, errors.New("policy_read_failed")
	}
	if repo.OwnerID != input.Repo.OwnerID || unit.TypeActions.UnitGlobalDisabled() {
		return invalid()
	}
	actionsUnit, err := repo.GetUnit(ctx, unit.TypeActions)
	if err != nil {
		if repo_model.IsErrUnitTypeNotExist(err) {
			return invalid()
		}
		failure.Reason = "policy_read_failed"
		return failure, errors.New("policy_read_failed")
	}
	permission := &access_model.Permission{AccessMode: perm.AccessModeOwner}
	permission.SetUnitsWithDefaultAccessMode([]*repo_model.RepoUnit{actionsUnit}, perm.AccessModeOwner)
	input.Repo, input.Permission = repo, permission
	snapshot, err := json.Marshal(baseSnapshot(input.EvaluateInput, []authz.Action{authz.ManageCI}))
	if err != nil {
		failure.Reason = "policy_read_failed"
		return failure, errors.New("policy_read_failed")
	}
	return Decision{Action: authz.ManageCI, CandidateDecision: "allow", Reason: "native_action", NativeActions: []authz.Action{authz.ManageCI}, CandidateOnly: true, Snapshot: string(snapshot), ownerID: repo.OwnerID}, nil
}
