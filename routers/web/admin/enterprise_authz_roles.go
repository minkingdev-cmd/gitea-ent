// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package admin

import (
	"fmt"
	"net/http"
	"strconv"

	authz_model "gitea.dev/models/enterpriseauthz"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	api "gitea.dev/modules/structs"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func EnterpriseAuthzRoles(ctx *context.Context) {
	ui := authzUI(ctx)
	if ui == nil {
		return
	}
	ctx.Data["AuthzTab"] = "roles"
	opts, err := authzPaging(ctx)
	if err != nil {
		authzError(ctx, err)
		return
	}
	rows, total, err := ui.Roles(opts)
	if err != nil {
		authzError(ctx, err)
		return
	}
	scope, ok := ctx.Data["AuthzScope"].(authz_model.Scope)
	if !ok {
		authzError(ctx, authz_service.ErrPolicyStorage)
		return
	}
	roles := make([]authzRoleListView, 0, len(rows))
	names := make(map[authz_model.Scope]string)
	for _, r := range rows {
		dto, e := authz_service.RoleDTO(r)
		if e != nil {
			authzError(ctx, e)
			return
		}
		origin := "current"
		if dto.IsBuiltin {
			origin = "builtin"
		} else if dto.Scope.Type != string(scope.Type) || dto.Scope.ID != scope.ID {
			origin = "ancestor"
		}
		scopeName, ok := names[r.Definition.Scope()]
		if !ok {
			scopeName, e = authzScopeName(ctx, r.Definition.Scope())
			if e != nil {
				authzError(ctx, e)
				return
			}
			names[r.Definition.Scope()] = scopeName
		}
		roles = append(roles, authzRoleListView{EnterpriseAuthzRole: dto, OriginLabel: ctx.Locale.TrString("admin.enterprise_authz.label." + origin), ScopeLabel: scopeName})
	}
	ctx.Data["AuthzRoles"] = roles
	authzPager(ctx, opts, total)
	authzRender(ctx, http.StatusOK, "admin/enterpriseauthz/roles")
}

type authzRoleListView struct {
	*api.EnterpriseAuthzRole
	OriginLabel string
	ScopeLabel  string
}

type authzPermissionForm struct {
	Action  string
	Branch  string
	Paths   string
	Sources string
}

type authzRoleForm struct {
	ID               int64
	Name             string
	Description      string
	ExpectedRevision int64
	CopyFromRoleID   int64
	Mode             string
	Permissions      []authzPermissionForm
	ReadOnly         bool
}

func authzRoleFromDTO(role *api.EnterpriseAuthzRole, scope authz_model.Scope) authzRoleForm {
	form := authzRoleForm{ID: role.ID, Name: role.Name, Description: role.Description, ExpectedRevision: role.Revision, Mode: "replace", ReadOnly: role.IsBuiltin || role.Scope.Type != string(scope.Type) || role.Scope.ID != scope.ID}
	for _, p := range role.Permissions {
		row := authzPermissionForm{Action: p.Action}
		if p.Condition != nil {
			row.Branch = authzPatternText(p.Condition.BranchPattern)
			row.Paths = authzPatternText(p.Condition.PathPattern)
			row.Sources = authzPatternText(p.Condition.RequestSources)
		}
		form.Permissions = append(form.Permissions, row)
	}
	return form
}

func authzRoleRender(ctx *context.Context, form authzRoleForm, status int, err error) {
	ctx.Data["AuthzTab"] = "roles"
	ctx.Data["AuthzRoleForm"] = form
	ctx.Data["AuthzEmptyPermission"] = authzPermissionForm{}
	if err != nil {
		_, reason := authzFailure(err)
		ctx.Data["AuthzError"] = ctx.Locale.TrString("admin.enterprise_authz.error." + reason)
	}
	authzRender(ctx, status, "admin/enterpriseauthz/role")
}

func EnterpriseAuthzRole(ctx *context.Context) {
	ui := authzUI(ctx)
	if ui == nil {
		return
	}
	id, err := strconv.ParseInt(ctx.PathParam("id"), 10, 64)
	if err != nil || id <= 0 {
		authzError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	role, err := ui.Role(id)
	if err != nil {
		authzError(ctx, err)
		return
	}
	dto, err := authz_service.RoleDTO(role)
	if err != nil {
		authzError(ctx, err)
		return
	}
	scope, ok := ctx.Data["AuthzScope"].(authz_model.Scope)
	if !ok {
		authzError(ctx, authz_service.ErrPolicyStorage)
		return
	}
	authzRoleRender(ctx, authzRoleFromDTO(dto, scope), http.StatusOK, nil)
}

func EnterpriseAuthzRoleNew(ctx *context.Context) {
	ui := authzUI(ctx)
	if ui == nil {
		return
	}
	form := authzRoleForm{Mode: "replace"}
	if raw := ctx.FormString("copy_from"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || id <= 0 {
			authzError(ctx, authz_service.ErrInvalidPolicy)
			return
		}
		source, err := ui.Role(id)
		if err != nil {
			authzError(ctx, err)
			return
		}
		dto, err := authz_service.RoleDTO(source)
		if err != nil {
			authzError(ctx, err)
			return
		}
		scope, ok := ctx.Data["AuthzScope"].(authz_model.Scope)
		if !ok {
			authzError(ctx, authz_service.ErrPolicyStorage)
			return
		}
		form = authzRoleFromDTO(dto, scope)
		form.ID, form.ExpectedRevision, form.ReadOnly = 0, 0, false
		form.CopyFromRoleID = id
		form.Name = ""
	}
	authzRoleRender(ctx, form, http.StatusOK, nil)
}

func authzParseRoleForm(ctx *context.Context) (authzRoleForm, *[]authz_service.PermissionInput, error) {
	form := authzRoleForm{Name: ctx.FormString("name"), Description: ctx.FormString("description"), Mode: ctx.FormString("permissions_mode")}
	count, err := strconv.Atoi(ctx.FormString("permission_count"))
	if err != nil || count < 0 || count > authz.MaxRolePermissions {
		return form, nil, authz_service.ErrInvalidPolicy
	}
	allowed := []string{"name", "description", "permissions_mode", "permission_count", "expected_revision", "copy_from_role_id"}
	for i := range count {
		prefix := fmt.Sprintf("permission_%d_", i)
		form.Permissions = append(form.Permissions, authzPermissionForm{Action: ctx.FormString(prefix + "action"), Branch: ctx.FormString(prefix + "branch"), Paths: ctx.FormString(prefix + "paths"), Sources: ctx.FormString(prefix + "sources")})
		for _, field := range []string{"action", "branch", "paths", "sources"} {
			allowed = append(allowed, prefix+field)
		}
	}
	if err := authzCheckFields(ctx, allowed...); err != nil {
		return form, nil, err
	}
	for field, dst := range map[string]*int64{"expected_revision": &form.ExpectedRevision, "copy_from_role_id": &form.CopyFromRoleID} {
		if raw := ctx.FormString(field); raw != "" {
			id, e := strconv.ParseInt(raw, 10, 64)
			if e != nil || id < 0 {
				return form, nil, authz_service.ErrInvalidPolicy
			}
			*dst = id
		}
	}
	if form.Mode == "unchanged" {
		return form, nil, nil
	}
	if form.Mode != "replace" {
		return form, nil, authz_service.ErrInvalidPolicy
	}
	permissions := make([]authz_service.PermissionInput, 0, count)
	seen := map[string]bool{}
	for _, row := range form.Permissions {
		if authz.ValidatePermission(authz.Action(row.Action), "allow") != nil {
			return form, nil, authz_service.ErrInvalidPolicy
		}
		branches, e := authzPatternLines(row.Branch)
		if e != nil {
			return form, nil, e
		}
		paths, e := authzPatternLines(row.Paths)
		if e != nil {
			return form, nil, e
		}
		sources, e := authzPatternLines(row.Sources)
		if e != nil {
			return form, nil, e
		}
		condition := authz.Condition{BranchPattern: branches, PathPattern: paths, RequestSources: sources}
		data, e := json.Marshal(condition)
		if e != nil {
			return form, nil, authz_service.ErrInvalidPolicy
		}
		_, canonical, hash, e := authz.ParseCondition(data)
		if e != nil || seen[row.Action+hash] {
			return form, nil, authz_service.ErrInvalidPolicy
		}
		seen[row.Action+hash] = true
		permissions = append(permissions, authz_service.PermissionInput{Action: authz.Action(row.Action), Effect: "allow", Condition: []byte(canonical)})
	}
	return form, &permissions, nil
}

func EnterpriseAuthzRoleSave(ctx *context.Context) {
	ui := authzUI(ctx)
	if ui == nil {
		return
	}
	form, permissions, err := authzParseRoleForm(ctx)
	if raw := ctx.PathParam("id"); raw != "" {
		id, e := strconv.ParseInt(raw, 10, 64)
		if e != nil || id <= 0 {
			authzError(ctx, authz_service.ErrInvalidPolicy)
			return
		}
		form.ID = id
		if form.CopyFromRoleID != 0 {
			err = authz_service.ErrInvalidPolicy
		}
	}
	if err != nil {
		authzRoleRender(ctx, form, http.StatusUnprocessableEntity, err)
		return
	}
	var role *authz_service.Role
	if form.ID == 0 {
		role, err = ui.CreateRole(authz_service.CreateRoleInput{Name: form.Name, Description: form.Description, CopyFromRoleID: form.CopyFromRoleID, Permissions: permissions})
	} else {
		role, err = ui.UpdateRole(form.ID, authz_service.UpdateRoleInput{ExpectedRevision: form.ExpectedRevision, Name: &form.Name, Description: &form.Description, Permissions: permissions})
	}
	if err != nil {
		status, _ := authzFailure(err)
		if status == http.StatusForbidden || status == http.StatusNotFound {
			authzError(ctx, err)
			return
		}
		authzRoleRender(ctx, form, status, err)
		return
	}
	ctx.Flash.Success(ctx.Tr("admin.enterprise_authz.saved"))
	ctx.Redirect(fmt.Sprintf("%s/roles/%d", ctx.Data["AuthzBase"], role.Definition.ID), http.StatusSeeOther)
}

func EnterpriseAuthzRoleDelete(ctx *context.Context) {
	ui := authzUI(ctx)
	if ui == nil {
		return
	}
	if err := authzCheckFields(ctx, "expected_revision", "confirm"); err != nil {
		authzError(ctx, err)
		return
	}
	id, err := strconv.ParseInt(ctx.PathParam("id"), 10, 64)
	revision, e := strconv.ParseInt(ctx.FormString("expected_revision"), 10, 64)
	if err != nil || e != nil || id <= 0 || revision <= 0 || ctx.FormString("confirm") != "yes" {
		authzError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	if err = ui.DeleteRole(id, revision); err != nil {
		authzError(ctx, err)
		return
	}
	ctx.Flash.Success(ctx.Tr("admin.enterprise_authz.saved"))
	ctx.Redirect(fmt.Sprintf("%s/roles", ctx.Data["AuthzBase"]), http.StatusSeeOther)
}
