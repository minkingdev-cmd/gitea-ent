// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package common

import (
	stdcontext "context"
	"net/http"

	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func RepoCollectionObserver(base *context.Base, actor *user_model.User, action authz.Action, source string) (func(*repo_model.Repository, *access_model.Permission), func()) {
	if !setting.EnterpriseAuthz.Enabled {
		return func(*repo_model.Repository, *access_model.Permission) {}, func() {}
	}
	ceiling := RepoCredentialCeiling(base, actor)
	if action == authz.ViewMetadata && !ceiling.Read {
		ceiling.Read, ceiling.Write = true, false
		ceiling.Actions = []authz.Action{authz.ViewMetadata}
	}
	var observations []*authz_service.Observation
	observe := func(repo *repo_model.Repository, permission *access_model.Permission) {
		input := authz_service.EvaluateInput{Actor: actor, Repo: repo, Permission: permission, Credential: ceiling, Action: action, ConditionContext: authz.ConditionContext{Source: source}}
		var observation *authz_service.Observation
		if permission == nil {
			_, observation = authz_service.BeginResolvedObservation(base, input, func(ctx stdcontext.Context) (*access_model.Permission, error) {
				permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
				return &permission, err
			})
		} else {
			_, observation = authz_service.BeginObservation(base, input)
		}
		if observation != nil {
			observations = append(observations, observation)
		}
	}
	return observe, func() {
		outcome := authz_service.NativeUnknown
		switch status := base.WrittenStatus(); {
		case status >= 200 && status < 300:
			outcome = authz_service.NativeSuccess
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			outcome = authz_service.NativeDenied
		case status >= 400:
			outcome = authz_service.NativeFailed
		}
		for _, observation := range observations {
			observation.Finish(base, outcome, authz_service.StageOperation)
		}
	}
}

func RepoReadResultCollector(base *context.Base, actor *user_model.User, source string) (func(*repo_model.Repository) func(authz_service.NativeOutcome), func()) {
	if !setting.EnterpriseAuthz.Enabled {
		return func(*repo_model.Repository) func(authz_service.NativeOutcome) {
			return func(authz_service.NativeOutcome) {}
		}, func() {}
	}
	type readResult struct {
		observation *authz_service.Observation
		outcome     authz_service.NativeOutcome
	}
	var results []*readResult
	capture := func(repo *repo_model.Repository) func(authz_service.NativeOutcome) {
		_, observation := authz_service.BeginResolvedObservation(base, authz_service.EvaluateInput{Actor: actor, Repo: repo, Credential: RepoCredentialCeiling(base, actor), Action: authz.ReadCode, ConditionContext: authz.ConditionContext{Source: source}}, func(ctx stdcontext.Context) (*access_model.Permission, error) {
			permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
			return &permission, err
		})
		result := &readResult{observation: observation, outcome: authz_service.NativeFailed}
		results = append(results, result)
		return func(outcome authz_service.NativeOutcome) { result.outcome = outcome }
	}
	return capture, func() {
		for _, result := range results {
			outcome := result.outcome
			if outcome == authz_service.NativeSuccess && base.WrittenStatus() >= http.StatusBadRequest {
				outcome = authz_service.NativeFailed
			}
			result.observation.Finish(base, outcome, authz_service.StageOperation)
		}
	}
}
