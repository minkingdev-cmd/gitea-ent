// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"
	"reflect"
	"strconv"

	actions_model "gitea.dev/models/actions"
	"gitea.dev/models/db"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
)

func isActionsExecutionActor(input ExecutionInput) bool {
	actor := input.Actor
	if actor == nil || actor.ID != user_model.ActionsUserID || actor.ExtDoerData == nil || !input.Credential.NativeOnly || reflect.TypeOf(actor.ExtDoerData) != reflect.TypeOf(user_model.NewActionsUserWithTaskID(1).ExtDoerData) {
		return false
	}
	taskID, ok := user_model.GetActionsUserTaskID(actor)
	return ok && taskID > 0 && input.Credential.Reference == "gitea-actions:"+strconv.FormatInt(taskID, 10)
}

func authenticatedActionsExecutionActor(ctx context.Context, input ExecutionInput) (Decision, error) {
	failure := Decision{Action: input.Action, CandidateDecision: "error", Reason: "invalid_evaluation_context", CandidateOnly: true}
	invalid := func() (Decision, error) {
		return failure, &ExecutionError{Reason: "invalid_execution_context", Status: 403}
	}
	infra := func() (Decision, error) {
		failure.Reason = "policy_read_failed"
		return failure, errors.New("policy_read_failed")
	}
	if !isActionsExecutionActor(input) || input.Repo == nil {
		return invalid()
	}
	failure.ownerID = input.Repo.OwnerID
	taskID, _ := user_model.GetActionsUserTaskID(input.Actor)
	task, exists, err := db.GetByID[actions_model.ActionTask](ctx, taskID)
	if err != nil {
		return infra()
	}
	if !exists || task.TokenHash == "" || task.Status != actions_model.StatusRunning && task.Status != actions_model.StatusCancelling {
		return invalid()
	}
	repo, exists, err := db.GetByID[repo_model.Repository](ctx, input.Repo.ID)
	if err != nil {
		return infra()
	}
	if !exists || repo.OwnerID != input.Repo.OwnerID {
		return invalid()
	}
	if err := task.LoadJob(ctx); err != nil {
		return infra()
	}
	if task.Job.RepoID != task.RepoID {
		return invalid()
	}
	for _, repoID := range []int64{task.RepoID, repo.ID} {
		source, exists, err := db.GetByID[repo_model.Repository](ctx, repoID)
		if err != nil {
			return infra()
		}
		if !exists {
			return invalid()
		}
		if _, err := source.GetUnit(ctx, unit.TypeActions); err != nil {
			if repo_model.IsErrUnitTypeNotExist(err) {
				return invalid()
			}
			return infra()
		}
	}
	permission, err := access_model.GetActionsUserRepoPermission(ctx, repo, input.Actor, taskID)
	if err != nil {
		return infra()
	}
	input.Actor, input.Repo, input.Permission = user_model.NewActionsUserWithTaskID(taskID), repo, &permission
	return evaluate(ctx, input.EvaluateInput, true)
}
