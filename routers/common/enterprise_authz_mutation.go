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
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/web/types"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
)

type (
	repoMutationKey         struct{}
	nativeSettingSuccessKey struct{ action authz.Action }
)

func MarkRepoSettingSuccess(base *context.Base, action authz.Action) {
	if setting.EnterpriseAuthz.Enabled {
		base.SetContextValue(nativeSettingSuccessKey{action}, struct{}{})
	}
}

func ObserveRepoSettingMutation(base *context.Base, actor *user_model.User, repo *repo_model.Repository, permission *access_model.Permission, action authz.Action) func() {
	return observeRepoSettingMutation(base, actor, repo, permission, action, "web")
}

func ObserveAPIRepoSettingMutation(base *context.Base, actor *user_model.User, repo *repo_model.Repository, permission *access_model.Permission, action authz.Action) func() {
	return observeRepoSettingMutation(base, actor, repo, permission, action, "api")
}

func observeRepoSettingMutation(base *context.Base, actor *user_model.User, repo *repo_model.Repository, permission *access_model.Permission, action authz.Action, source string) func() {
	if !setting.EnterpriseAuthz.Enabled || repo == nil {
		return func() {}
	}
	finish := ObserveRepoMutation(base, actor, repo, permission, action, source)
	return func() {
		outcome := authz_service.NativeFailed
		if _, ok := base.Value(nativeSettingSuccessKey{action}).(struct{}); ok {
			outcome = authz_service.NativeSuccess
		}
		finish(outcome)
	}
}

func RepoMutationRoute(action authz.Action) types.PreMiddlewareProvider {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if setting.EnterpriseAuthz.Enabled && req.Method != http.MethodGet && req.Method != http.MethodHead {
				reqctx.GetRequestDataStore(req.Context()).SetContextValue(repoMutationKey{}, action)
			}
			next.ServeHTTP(w, req)
		})
	}
}

func ObserveMarkedRepoDenial(base *context.Base, actor *user_model.User, repo *context.Repository, source string) {
	observeMarkedRepoRejection(base, actor, repo, source, false)
}

func ObserveMarkedRepoValidationFailure(base *context.Base, actor *user_model.User, repo *context.Repository) {
	observeMarkedRepoRejection(base, actor, repo, "api", true)
}

func observeMarkedRepoRejection(base *context.Base, actor *user_model.User, repo *context.Repository, source string, validationFailed bool) {
	if !setting.EnterpriseAuthz.Enabled || actor == nil || repo == nil || repo.Repository == nil || !repo.Permission.HasAnyUnitAccessOrPublicAccess() {
		return
	}
	action, ok := base.Value(repoMutationKey{}).(authz.Action)
	if !ok {
		if !validationFailed {
			observeMarkedLifecycleDenial(base, actor, repo, source)
		}
		return
	}
	observe := authz_service.ObserveGuardDenial
	if validationFailed {
		observe = authz_service.ObserveValidationFailure
	}
	observe(base, authz_service.EvaluateInput{Actor: actor, Repo: repo.Repository, Permission: &repo.Permission, Credential: RepoCredentialCeiling(base, actor), Action: action, ConditionContext: authz.ConditionContext{Source: source}}, func(stdcontext.Context) (bool, error) { return true, nil })
}
