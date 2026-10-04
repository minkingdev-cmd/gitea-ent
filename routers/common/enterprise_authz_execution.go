// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package common

import (
	"errors"
	"net/http"

	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func BeginRepoExecution(base *context.Base, actor *user_model.User, repo *repo_model.Repository, source, intent string, actions ...authz.Action) (func(), bool) {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce || repo == nil || len(actions) == 0 {
		return func() {}, true
	}
	required := make([]RepoExecutionAction, len(actions))
	for i, action := range actions {
		required[i] = RepoExecutionAction{Action: action, Intent: intent}
	}
	return BeginRepoActionExecution(base, actor, repo, source, required)
}

type RepoExecutionAction struct {
	Action authz.Action
	Intent string
}

func BeginRepoActionExecution(base *context.Base, actor *user_model.User, repo *repo_model.Repository, source string, required []RepoExecutionAction) (func(), bool) {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce || len(required) == 0 {
		return func() {}, true
	}
	inputs := make([]authz_service.ExecutionInput, len(required))
	for i, item := range required {
		inputs[i] = authz_service.ExecutionInput{EvaluateInput: authz_service.EvaluateInput{Actor: actor, Repo: repo, Credential: RepoCredentialCeiling(base, actor), Action: item.Action, ConditionContext: authz.ConditionContext{Source: source}}, Intent: item.Intent}
	}
	executionCtx, admission, err := authz_service.BeginExecution(base.RequestContext, inputs)
	if err == nil {
		err = admission.Start(executionCtx)
	}
	if err != nil {
		if !WriteExecutionError(base, err) {
			base.JSON(http.StatusServiceUnavailable, map[string]string{"message": "authorization_unavailable"})
		}
		return func() {}, false
	}
	base.RequestContext = reqctx.FromContext(executionCtx)
	return func() {
		outcome := authz_service.NativeFailed
		status := base.WrittenStatus()
		if status >= 200 && status < 300 {
			outcome = authz_service.NativeSuccess
		}
		for _, item := range required {
			if _, ok := base.Value(nativeSettingSuccessKey{item.Action}).(struct{}); ok {
				outcome = authz_service.NativeSuccess
			}
		}
		if status == http.StatusUnauthorized || status == http.StatusForbidden {
			outcome = authz_service.NativeDenied
		}
		admission.Finish(executionCtx, outcome, authz_service.StageOperation)
	}, true
}

func WriteExecutionError(base *context.Base, err error) bool {
	var rejection *authz_service.ExecutionError
	if !errors.As(err, &rejection) {
		return false
	}
	status := rejection.Status
	if status != http.StatusForbidden && status != http.StatusServiceUnavailable {
		status = http.StatusServiceUnavailable
	}
	base.JSON(status, map[string]string{"message": rejection.Reason})
	return true
}

func BeginRepoSettingExecution(base *context.Base, actor *user_model.User, repo *repo_model.Repository, source string, action authz.Action, target string, additional ...authz.Action) (func(), bool) {
	return BeginRepoExecution(base, actor, repo, source, authz_service.SettingsIntent(action, target), append([]authz.Action{action}, additional...)...)
}
