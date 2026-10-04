// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package admin

import (
	"net/http"
	"strconv"

	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func EnterpriseAuthzSelector(ctx *context.Context) {
	EnterpriseAuthzRequired(ctx)
	if ctx.Written() {
		return
	}
	scope := authz_model.Scope{Type: authz_model.ScopeType(ctx.FormString("scope_type", "system"))}
	if raw := ctx.FormString("scope_id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			authzError(ctx, authz_service.ErrInvalidPolicy)
			return
		}
		scope.ID = id
	}
	if err := authzCheckFields(ctx, "scope_type", "scope_id", "q", "page", "limit"); err != nil {
		authzError(ctx, err)
		return
	}
	if !scope.Valid() {
		authzError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	ui, err := authz_service.NewManagementUI(ctx, ctx.Doer, scope)
	if err != nil {
		authzError(ctx, err)
		return
	}
	opts, err := authzPaging(ctx)
	if err != nil {
		authzError(ctx, err)
		return
	}
	items, total, err := ui.Select(ctx.PathParam("kind"), ctx.FormString("q"), opts)
	if err != nil {
		authzError(ctx, err)
		return
	}
	for i := range items {
		if err := authzSelectorDisplay(ctx, ctx.PathParam("kind"), &items[i]); err != nil {
			authzError(ctx, err)
			return
		}
	}

	ctx.JSON(http.StatusOK, map[string]any{"items": items, "total": total, "page": opts.Page, "limit": opts.Limit})
}
