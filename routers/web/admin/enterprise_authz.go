// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package admin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"

	authz_model "gitea.dev/models/enterpriseauthz"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/session"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/templates"
	"gitea.dev/modules/util"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
)

const authzRoot = "/-/admin/enterprise/authz"

func EnterpriseAuthzRequired(ctx *context.Context) {
	if ctx.Session == nil || ctx.Doer == nil || ctx.Data["AuthedMethod"] != "session" || ctx.Session.Get(session.KeyUID) != ctx.Doer.ID {
		ctx.HTTPError(http.StatusForbidden)
		return
	}
	if err := authz_service.CheckUIAuthority(ctx, ctx.Doer); err != nil {
		authzError(ctx, err)
		return
	}

	csrfKey := fmt.Sprintf("enterprise_authz_csrf_%d", ctx.Doer.ID)
	token, _ := ctx.Session.Get(csrfKey).(string)
	if len(token) != 64 {
		random := make([]byte, 32)
		if _, err := rand.Read(random); err != nil {
			authzError(ctx, authz_service.ErrPolicyStorage)
			return
		}
		token = hex.EncodeToString(random)
		if err := ctx.Session.Set(csrfKey, token); err != nil {
			authzError(ctx, authz_service.ErrPolicyStorage)
			return
		}
	}
	ctx.Data["AuthzCSRF"] = token
	if ctx.Req.Method == http.MethodPost {
		mediaType, _, err := mime.ParseMediaType(ctx.Req.Header.Get("Content-Type"))
		if err != nil || mediaType != "application/x-www-form-urlencoded" {
			authzError(ctx, authz_service.ErrInvalidPolicy)
			return
		}

		ctx.Req.Body = http.MaxBytesReader(ctx.Resp, ctx.Req.Body, authz.MaxBodyBytes)
		if err := ctx.Req.ParseForm(); err != nil {
			authzError(ctx, authz_service.ErrInvalidPolicy)
			return
		}
		values := ctx.Req.PostForm["authz_csrf"]
		if len(values) != 1 || subtle.ConstantTimeCompare([]byte(values[0]), []byte(token)) != 1 {
			ctx.HTTPError(http.StatusForbidden, ctx.Locale.TrString("admin.enterprise_authz.error.csrf"))
			return
		}
		size := 0
		for key, values := range ctx.Req.Form {
			for _, value := range values {
				size += len(key) + len(value)
			}
		}
		if size > authz.MaxBodyBytes {
			authzError(ctx, authz_service.ErrInvalidPolicy)
			return
		}
	}
	ctx.Data["PageIsAdmin"] = true
	ctx.Data["PageIsAdminEnterpriseAuthz"] = true
	ctx.Data["ShowEnterpriseAuthz"] = true
	ctx.Data["Title"] = ctx.Tr("admin.enterprise_authz.title")
	ctx.Resp.Header().Set("Cache-Control", "no-store")
}

func authzScope(ctx *context.Context) (authz_model.Scope, error) {
	scope := authz_model.Scope{Type: authz_model.ScopeType(ctx.PathParam("scope"))}
	if scope.Type != authz_model.ScopeSystem {
		id, err := strconv.ParseInt(ctx.PathParam("scopeid"), 10, 64)
		if err != nil {
			return scope, authz_service.ErrInvalidPolicy
		}
		scope.ID = id
	}
	if !scope.Valid() {
		return scope, authz_service.ErrInvalidPolicy
	}
	return scope, nil
}

func authzUI(ctx *context.Context) *authz_service.ManagementUI {
	EnterpriseAuthzRequired(ctx)
	if ctx.Written() {
		return nil
	}
	scope, err := authzScope(ctx)
	if err != nil {
		authzError(ctx, err)
		return nil
	}
	ui, err := authz_service.NewManagementUI(ctx, ctx.Doer, scope)
	if err != nil {
		authzError(ctx, err)
		return nil
	}
	base := setting.AppSubURL + authzRoot + "/scopes/" + string(scope.Type)
	if scope.ID != 0 {
		base += "/" + strconv.FormatInt(scope.ID, 10)
	}
	label, err := authzScopeName(ctx, scope)
	if err != nil {
		authzError(ctx, err)
		return nil
	}
	pickerUI, err := authz_service.NewManagementUI(ctx, ctx.Doer, authz_model.Scope{Type: authz_model.ScopeSystem})
	if err != nil {
		authzError(ctx, err)
		return nil
	}
	value := ""
	if scope.ID != 0 {
		value = strconv.FormatInt(scope.ID, 10)
	}
	if !authzPicker(ctx, pickerUI, "AuthzScopePicker", "authz-scope-id", "scope_id", string(scope.Type), "search_scope", value, scope.Type != authz_model.ScopeSystem) {
		return nil
	}
	picker, ok := ctx.Data["AuthzScopePicker"].(authzPickerView)
	if !ok {
		authzError(ctx, authz_service.ErrPolicyStorage)
		return nil
	}
	picker.Kind = "scope"
	ctx.Data["AuthzScopePicker"] = picker

	ctx.Data["AuthzScope"] = scope
	ctx.Data["AuthzBase"] = base
	ctx.Data["AuthzRoot"] = setting.AppSubURL + authzRoot
	ctx.Data["AuthzScopeLabel"] = label
	actions := make([]api.EnterpriseAuthzAction, 0, len(authz.Catalog()))
	for _, a := range authz.Catalog() {
		actions = append(actions, api.EnterpriseAuthzAction{Key: string(a.Key), Description: ctx.Locale.TrString("admin.enterprise_authz.action." + string(a.Key)), Units: a.Units, Risk: a.Risk, Observed: a.Observed, Mutating: a.Mutating, UnitsAny: a.UnitsAny})
	}
	ctx.Data["AuthzActions"] = actions
	ctx.Data["AuthzSources"] = authz.RequestSources()
	ctx.Data["AuthzLabel"] = func(code string) string {
		key := "admin.enterprise_authz.label." + code
		label := ctx.Locale.TrString(key)
		if label == key {
			return ctx.Locale.TrString("admin.enterprise_authz.label.unknown")
		}
		return label
	}
	return ui
}

func authzFailure(err error) (int, string) {
	switch {
	case errors.Is(err, util.ErrPermissionDenied):
		return http.StatusForbidden, "forbidden"
	case errors.Is(err, util.ErrNotExist):
		return http.StatusNotFound, "not_found"
	case errors.Is(err, authz_service.ErrRevisionConflict):
		return http.StatusConflict, "revision_conflict"
	case errors.Is(err, authz_service.ErrBuiltinImmutable):
		return http.StatusConflict, "builtin_role_immutable"
	case errors.Is(err, authz_service.ErrRoleNameConflict):
		return http.StatusConflict, "role_name_conflict"
	case errors.Is(err, authz_service.ErrRoleReferenced):
		return http.StatusConflict, "role_referenced"
	case errors.Is(err, authz_service.ErrInvalidPolicy):
		return http.StatusUnprocessableEntity, "invalid_policy"
	default:
		return http.StatusInternalServerError, "policy_storage_failed"
	}
}

func authzError(ctx *context.Context, err error) {
	status, reason := authzFailure(err)
	ctx.HTTPError(status, ctx.Locale.TrString("admin.enterprise_authz.error."+reason))
}

func authzRender(ctx *context.Context, status int, tpl templates.TplName) { ctx.HTML(status, tpl) }

func authzPaging(ctx *context.Context) (authz_service.PolicyListOptions, error) {
	opts := authz_service.PolicyListOptions{Page: 1, Limit: 20}
	for key, dst := range map[string]*int{"page": &opts.Page, "limit": &opts.Limit} {
		if value := ctx.FormString(key); value != "" {
			n, err := strconv.Atoi(value)
			if err != nil {
				return opts, authz_service.ErrInvalidPolicy
			}
			*dst = n
		}
	}
	if opts.Page < 1 || opts.Page > 1000000 || opts.Limit < 1 || opts.Limit > 100 {
		return opts, authz_service.ErrInvalidPolicy
	}
	return opts, nil
}

func authzPager(ctx *context.Context, opts authz_service.PolicyListOptions, total int64) {
	ctx.Data["Page"] = context.NewPagerBuilder(ctx).TotalCount(total).PerPageLimit(opts.Limit).CurPage(opts.Page).Build()
	ctx.Data["AuthzTotal"] = total
}

func EnterpriseAuthzHome(ctx *context.Context) {
	ctx.Redirect(setting.AppSubURL + authzRoot + "/scopes/system/roles")
}

func EnterpriseAuthzScopeSelect(ctx *context.Context) {
	scope := authz_model.Scope{Type: authz_model.ScopeType(ctx.FormString("scope_type"))}
	if scope.Type != authz_model.ScopeSystem {
		id, err := strconv.ParseInt(ctx.FormString("scope_id"), 10, 64)
		if err != nil {
			authzError(ctx, authz_service.ErrInvalidPolicy)
			return
		}
		scope.ID = id
	}
	if _, err := authz_service.NewManagementUI(ctx, ctx.Doer, scope); err != nil {
		authzError(ctx, err)
		return
	}
	path := setting.AppSubURL + authzRoot + "/scopes/" + string(scope.Type)
	if scope.ID > 0 {
		path += fmt.Sprintf("/%d", scope.ID)
	}
	ctx.Redirect(path + "/roles")
}

func authzCheckFields(ctx *context.Context, allowed ...string) error {
	for key := range ctx.Req.Form {
		if key == "authz_csrf" {
			continue
		}
		found := slices.Contains(allowed, key)
		if !found || len(ctx.Req.Form[key]) != 1 {
			return authz_service.ErrInvalidPolicy
		}
	}
	return nil
}

func authzPatternLines(value string) ([]string, error) {
	var result []string
	for line := range strings.SplitSeq(strings.ReplaceAll(value, "\r\n", "\n"), "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, `"`) {
			var decoded string
			if err := json.Unmarshal([]byte(line), &decoded); err != nil {
				return nil, authz_service.ErrInvalidPolicy
			}
			line = decoded
		}
		result = append(result, line)
	}
	return result, nil
}

func authzPatternText(values []string) string {
	lines := make([]string, 0, len(values))
	for _, value := range values {
		if strings.ContainsAny(value, "\r\n") || strings.HasPrefix(value, `"`) {
			encoded, _ := json.Marshal(value)
			value = string(encoded)
		}
		lines = append(lines, value)
	}
	return strings.Join(lines, "\n")
}
