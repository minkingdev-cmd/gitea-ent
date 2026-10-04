// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"
	"reflect"
	"strconv"

	"gitea.dev/models/asymkey"
	"gitea.dev/models/db"
	deploykey_model "gitea.dev/models/deploykey"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
)

func isDeployExecutionActor(input ExecutionInput) bool {
	actor := input.Actor
	if actor == nil || actor.ID != user_model.DeployKeyUserID || actor.ExtDoerData == nil || !input.Credential.NativeOnly || reflect.TypeOf(actor.ExtDoerData) != reflect.TypeOf(user_model.NewDeployKeyUserWithKeyID(1).ExtDoerData) {
		return false
	}
	keyID, ok := user_model.GetDeployKeyUserDeployKeyID(actor)
	return ok && keyID > 0 && input.Credential.Reference == "deploy-key:"+strconv.FormatInt(keyID, 10)
}

func authenticatedDeployExecutionActor(ctx context.Context, input ExecutionInput) (Decision, error) {
	failure := Decision{Action: input.Action, CandidateDecision: "error", Reason: "invalid_evaluation_context", CandidateOnly: true}
	invalid := func() (Decision, error) {
		return failure, &ExecutionError{Reason: "invalid_execution_context", Status: 403}
	}
	infra := func() (Decision, error) {
		failure.Reason = "policy_read_failed"
		return failure, errors.New("policy_read_failed")
	}
	if !isDeployExecutionActor(input) || input.Repo == nil {
		return invalid()
	}
	failure.ownerID = input.Repo.OwnerID
	keyID, _ := user_model.GetDeployKeyUserDeployKeyID(input.Actor)
	key, exists, err := db.GetByID[deploykey_model.DeployKey](ctx, keyID)
	if err != nil {
		return infra()
	}
	if !exists || key.RepoID != input.Repo.ID || key.Mode != perm.AccessModeRead && key.Mode != perm.AccessModeWrite {
		return invalid()
	}
	switch key.KeyType {
	case deploykey_model.KeyTypeToken:
		if key.TokenHash == "" {
			return invalid()
		}
	case deploykey_model.KeyTypeSSH:
		pkey, exists, err := db.GetByID[asymkey.PublicKey](ctx, key.KeyID)
		if err != nil {
			return infra()
		}
		if !exists || pkey.Type != asymkey.KeyTypeDeploy {
			return invalid()
		}
	default:
		return invalid()
	}
	repo, exists, err := db.GetByID[repo_model.Repository](ctx, input.Repo.ID)
	if err != nil {
		return infra()
	}
	if !exists || repo.OwnerID != input.Repo.OwnerID {
		return invalid()
	}
	actor := user_model.NewDeployKeyUserWithKeyID(keyID)
	permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
	if err != nil {
		return infra()
	}
	input.Actor, input.Repo, input.Permission = actor, repo, &permission
	return evaluate(ctx, input.EvaluateInput, true)
}
