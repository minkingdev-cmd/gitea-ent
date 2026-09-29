// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package context

import (
	stdContext "context"

	wecom_model "gitea.dev/models/enterprisewecom"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
)

func CanUserAccessSiteAdminPanel(ctx stdContext.Context, user *user_model.User) (bool, error) {
	if user == nil {
		return false, nil
	}
	if !setting.EnterpriseWeCom.Enabled {
		return user.IsAdmin, nil
	}
	return wecom_model.IsActiveManagementAuthorityBoundUser(ctx, setting.EnterpriseWeCom.CorpID, setting.EnterpriseWeCom.AgentID, user.ID)
}

func (ctx *Context) CanAccessSiteAdminPanel() (bool, error) {
	if !ctx.IsSigned {
		return false, nil
	}
	return CanUserAccessSiteAdminPanel(ctx, ctx.Doer)
}

func (ctx *APIContext) CanAccessSiteAdminPanel() (bool, error) {
	if !ctx.IsSigned {
		return false, nil
	}
	return CanUserAccessSiteAdminPanel(ctx, ctx.Doer)
}
