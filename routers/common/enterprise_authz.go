// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package common

import (
	"net/http"

	auth_model "gitea.dev/models/auth"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/web/middleware"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func ObserveRepoRequest(base *context.Base, actor *user_model.User, repo *repo_model.Repository, permission *access_model.Permission, action authz.Action, source string) func() {
	if !setting.EnterpriseAuthz.Enabled {
		return func() {}
	}
	ceiling := RepoCredentialCeiling(base, actor)
	observationCtx, observation := authz_service.BeginObservation(base, authz_service.EvaluateInput{
		Actor: actor, Repo: repo, Permission: permission, Credential: ceiling,
		Action: action, ConditionContext: authz.ConditionContext{Source: source},
	})
	return func() {
		outcome := authz_service.NativeUnknown
		switch status := base.WrittenStatus(); {
		case status >= 200 && status < 300:
			outcome = authz_service.NativeSuccess
		case status == http.StatusUnauthorized || status == http.StatusForbidden:
			outcome = authz_service.NativeDenied
		case status >= 400:
			outcome = authz_service.NativeFailed
		}
		if _, denied := base.Value(nativeMutationDeniedKey{}).(struct{}); denied && outcome == authz_service.NativeFailed {
			outcome = authz_service.NativeDenied
		}
		observation.Finish(observationCtx, outcome, authz_service.StageOperation)
	}
}

type nativeMutationDeniedKey struct{}

func MarkNativeMutationDenied(base *context.Base) {
	if setting.EnterpriseAuthz.Enabled {
		base.SetContextValue(nativeMutationDeniedKey{}, struct{}{})
	}
}

func ObserveRepoMutation(base *context.Base, actor *user_model.User, repo *repo_model.Repository, permission *access_model.Permission, action authz.Action, source string) func(authz_service.NativeOutcome) {
	if !setting.EnterpriseAuthz.Enabled {
		return func(authz_service.NativeOutcome) {}
	}
	return observeRepoMutation(base, actor, repo, permission, action, source, RepoCredentialCeiling(base, actor))
}

func ObserveRepoBranchMutation(base *context.Base, actor *user_model.User, repo *repo_model.Repository, permission *access_model.Permission, action authz.Action, source, branch string) func(authz_service.NativeOutcome) {
	if !setting.EnterpriseAuthz.Enabled {
		return func(authz_service.NativeOutcome) {}
	}
	return observeRepoMutation(base, actor, repo, permission, action, source, RepoCredentialCeiling(base, actor), authz.ConditionContext{Branch: branch, BranchKnown: true})
}

func observeRepoMutation(base *context.Base, actor *user_model.User, repo *repo_model.Repository, permission *access_model.Permission, action authz.Action, source string, ceiling authz_service.CredentialCeiling, conditions ...authz.ConditionContext) func(authz_service.NativeOutcome) {
	condition := authz.ConditionContext{Source: source}
	if len(conditions) > 0 {
		condition = conditions[0]
		condition.Source = source
	}
	observationCtx, observation := authz_service.WithObservationContext(base, authz_service.EvaluateInput{
		Actor: actor, Repo: repo, Permission: permission, Credential: ceiling,
		Action: action, ConditionContext: condition,
	})
	return func(outcome authz_service.NativeOutcome) {
		if _, persisted := base.Value(nativeSettingSuccessKey{action}).(struct{}); persisted && outcome == authz_service.NativeSuccess {
			observation.Finish(observationCtx, outcome, authz_service.StageOperation)
			return
		}
		if outcome == authz_service.NativeSuccess && base.WrittenStatus() >= http.StatusBadRequest {
			outcome = authz_service.NativeFailed
		}
		_, denied := base.Value(nativeMutationDeniedKey{}).(struct{})
		if outcome == authz_service.NativeFailed && (denied || base.WrittenStatus() == http.StatusForbidden || base.WrittenStatus() == http.StatusUnauthorized) {
			outcome = authz_service.NativeDenied
		}
		observation.Finish(observationCtx, outcome, authz_service.StageOperation)
	}
}

func RepoCredentialCeiling(base *context.Base, actor *user_model.User) authz_service.CredentialCeiling {
	ceiling := authz_service.CredentialCeiling{Read: true, Write: actor != nil}
	if scope, exists := base.Data["ApiTokenScope"].(auth_model.AccessTokenScope); exists {
		var err error
		ceiling.Read, err = scope.HasScope(auth_model.AccessTokenScopeReadRepository)
		if err != nil {
			ceiling.Read = false
		}
		ceiling.Write, err = scope.HasScope(auth_model.AccessTokenScopeWriteRepository)
		if err != nil {
			ceiling.Write = false
		}
	}
	ceiling.Reference, _ = base.Data[middleware.ContextDataKeyAuthCredential].(string)
	if actor != nil && actor.ExtDoerData != nil {
		ceiling.NativeOnly = true
		ceiling.Reference = actor.ExtDoerData.EncodeToString()
	}
	return ceiling
}
