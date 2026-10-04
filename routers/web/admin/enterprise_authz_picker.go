// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package admin

import (
	"errors"
	"fmt"
	"strconv"

	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/util"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
)

type authzPickerView struct {
	ID, Name, Kind, Title, Value, Label, Context string
	Required                                     bool
	Unavailable                                  bool
}

func authzScopeName(ctx *context.Context, scope authz_model.Scope) (string, error) {
	label := ctx.Locale.TrString("admin.enterprise_authz.scope." + string(scope.Type))
	switch scope.Type {
	case authz_model.ScopeOrg:
		row, err := user_model.GetUserByID(ctx, scope.ID)
		if err != nil {
			return "", authz_service.ErrPolicyStorage
		}
		label += " · " + row.Name
	case authz_model.ScopeRepo:
		row, err := repo_model.GetRepositoryByID(ctx, scope.ID)
		if err != nil {
			return "", authz_service.ErrPolicyStorage
		}
		if err = row.LoadOwner(ctx); err != nil {
			return "", authz_service.ErrPolicyStorage
		}
		label += " · " + row.FullName()
	}
	return label, nil
}

func authzSelectorDisplay(ctx *context.Context, kind string, item *authz_service.UISelectorItem) error {
	if item.Missing {
		key := "deleted_user"
		if kind == "history_repo" {
			key = "deleted_repo"
		}
		item.Label = ctx.Locale.TrString("admin.enterprise_authz." + key)
		item.Context = fmt.Sprintf("#%d", item.ID)
	}
	if item.Scope != nil {
		label, err := authzScopeName(ctx, *item.Scope)
		if err != nil {
			return err
		}
		item.Context = label
	}
	return nil
}

func authzPicker(ctx *context.Context, ui *authz_service.ManagementUI, key, id, name, kind, title, value string, required bool) bool {
	view := authzPickerView{ID: id, Name: name, Kind: kind, Title: ctx.Locale.TrString("admin.enterprise_authz." + title), Required: required}
	if value != "" {
		number, err := strconv.ParseInt(value, 10, 64)
		if err == nil {
			item, e := ui.Selection(kind, number)
			if errors.Is(e, util.ErrNotExist) && (kind == "history_repo" || kind == "history_actor") {
				fallback := "repo"
				if kind == "history_actor" {
					fallback = "user"
				}
				item, e = ui.Selection(fallback, number)
			}
			if e != nil && !errors.Is(e, util.ErrNotExist) && !errors.Is(e, authz_service.ErrInvalidPolicy) {
				authzError(ctx, e)
				return false
			}
			if e != nil {
				view.Value, view.Label, view.Unavailable = value, ctx.Locale.TrString("admin.enterprise_authz.selection_unavailable"), true
			}
			if e == nil {
				if e = authzSelectorDisplay(ctx, kind, item); e != nil {
					authzError(ctx, e)
					return false
				}
				view.Value, view.Label, view.Context = value, item.Label, item.Context
			}
		}
	}
	ctx.Data[key] = view
	return true
}
