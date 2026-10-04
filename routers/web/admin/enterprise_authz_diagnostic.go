// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	authz_model "gitea.dev/models/enterpriseauthz"
	authz "gitea.dev/modules/enterpriseauthz"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/util"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func authzDiagnosticPage(ctx *context.Context) authz_model.ScopeType {
	scope, ok := ctx.Data["AuthzScope"].(authz_model.Scope)
	if !ok {
		authzError(ctx, authz_service.ErrPolicyStorage)
		return ""
	}
	ctx.Data["AuthzTab"] = "diagnostic"
	ctx.Data["AuthzNeedsRepo"] = scope.Type != authz_model.ScopeRepo
	return scope.Type
}

func authzDiagnosticRoleNames(ctx *context.Context, ui *authz_service.ManagementUI, roles []authz_service.DiagnosticRole) bool {
	names, ok := ctx.Data["AuthzDiagnosticRoleNames"].(map[int64]string)
	if !ok {
		names = make(map[int64]string)
	}
	for _, ref := range roles {
		if _, exists := names[ref.ID]; exists {
			continue
		}
		role, err := ui.Role(ref.ID)
		if errors.Is(err, util.ErrNotExist) {
			names[ref.ID] = ctx.Locale.TrString("admin.enterprise_authz.deleted_role")
			continue
		}
		if err != nil {
			authzError(ctx, err)
			return false
		}
		names[ref.ID] = role.Definition.Name
	}
	ctx.Data["AuthzDiagnosticRoleNames"] = names
	return true
}

func authzDiagnosticPickers(ctx *context.Context, ui *authz_service.ManagementUI, userID int64) bool {
	if userID == 0 {
		userID = ctx.Doer.ID
	}
	value := strconv.FormatInt(userID, 10)
	return authzPicker(ctx, ui, "AuthzEffectiveUserPicker", "authz-effective-user", "user_id", "user", "search_user", value, true) && authzPicker(ctx, ui, "AuthzEvaluateUserPicker", "authz-evaluate-user", "user_id", "user", "search_user", value, true)
}

func EnterpriseAuthzDiagnostic(ctx *context.Context) {
	ui := authzUI(ctx)
	if ui == nil {
		return
	}
	scopeType := authzDiagnosticPage(ctx)
	if ctx.Written() {
		return
	}
	if scopeType != authz_model.ScopeRepo {
		authzRender(ctx, http.StatusOK, "admin/enterpriseauthz/diagnostic")
		return
	}
	if len(ctx.Req.URL.Query()["user_id"]) > 1 {
		authzError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	userID, err := authzDiagnosticUser(ctx.FormString("user_id"))
	if err != nil {
		authzError(ctx, err)
		return
	}
	result, err := ui.EffectivePermissions(authz_service.DiagnosticInput{TargetUserID: userID})
	if err != nil {
		authzError(ctx, err)
		return
	}
	ctx.Data["AuthzDiagnosticUserID"] = userID
	if !authzDiagnosticPickers(ctx, ui, userID) {
		return
	}
	if !authzDiagnosticRoleNames(ctx, ui, result.Roles) {
		return
	}
	ctx.Data["AuthzEffective"] = api.EnterpriseAuthzEffectivePermissions{EnterpriseAuthzExplanation: authz_service.ExplanationDTO(result.NativeActions, result.RoleActions, result.Reason, result.Roles, result.Bindings, result.Conditions), UnresolvedActions: authz_service.ActionsDTO(result.UnresolvedActions)}
	authzRender(ctx, http.StatusOK, "admin/enterpriseauthz/diagnostic")
}

func authzDiagnosticUser(value string) (int64, error) {
	if value == "" {
		return 0, nil
	}
	id, err := strconv.ParseInt(value, 10, 64)
	if err != nil || id < 0 {
		return 0, authz_service.ErrInvalidPolicy
	}
	return id, nil
}

func EnterpriseAuthzEvaluate(ctx *context.Context) {
	ui := authzUI(ctx)
	if ui == nil {
		return
	}
	authzDiagnosticPage(ctx)
	if ctx.Written() {
		return
	}
	ctx.Req.Body = http.MaxBytesReader(ctx.Resp, ctx.Req.Body, authz.MaxBodyBytes)
	if err := ctx.Req.ParseForm(); err != nil {
		authzError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	size := 0
	for key, values := range ctx.Req.Form {
		if len(values) != 1 || key != "authz_csrf" && key != "user_id" && key != "action" && key != "branch" && key != "paths" {
			authzError(ctx, authz_service.ErrInvalidPolicy)
			return
		}
		size += len(key) + len(values[0])
	}
	if size > authz.MaxBodyBytes {
		authzError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	userID, err := authzDiagnosticUser(ctx.FormString("user_id"))
	if err != nil {
		authzError(ctx, err)
		return
	}
	branch, paths := ctx.FormString("branch"), ctx.FormString("paths")
	input := authz_service.DiagnosticInput{TargetUserID: userID, Action: authz.Action(ctx.FormString("action")), ConditionContext: authz.ConditionContext{Source: "diagnostic", Branch: branch, BranchKnown: branch != ""}}
	if paths != "" {
		input.ConditionContext.Paths = strings.Split(strings.ReplaceAll(paths, "\r\n", "\n"), "\n")
		input.ConditionContext.PathsComplete = true
	}
	ctx.Data["AuthzDiagnosticUserID"], ctx.Data["AuthzDiagnosticAction"], ctx.Data["AuthzDiagnosticBranch"] = userID, string(input.Action), branch
	if !authzDiagnosticPickers(ctx, ui, userID) {
		return
	}
	result, err := ui.Evaluate(input)
	if err != nil {
		status, reason := authzFailure(err)
		if status == http.StatusUnprocessableEntity || status == http.StatusInternalServerError {
			ctx.Data["AuthzError"] = ctx.Locale.TrString("admin.enterprise_authz.error." + reason)
			authzRender(ctx, status, "admin/enterpriseauthz/diagnostic")
		} else {
			authzError(ctx, err)
		}
		return
	}
	if !authzDiagnosticRoleNames(ctx, ui, result.Roles) {
		return
	}
	ctx.Data["AuthzDiagnostic"] = api.EnterpriseAuthzDiagnostic{EnterpriseAuthzExplanation: authz_service.ExplanationDTO(result.NativeActions, result.RoleActions, result.Reason, result.Roles, result.Bindings, result.Conditions), Action: string(result.Action), CandidateDecision: result.CandidateDecision, MatchedRoleIDs: result.MatchedRoleIDs, MatchedBindingIDs: result.MatchedBindingIDs, MissingActions: authz_service.ActionsDTO(result.MissingActions)}
	authzRender(ctx, http.StatusOK, "admin/enterpriseauthz/diagnostic")
}
