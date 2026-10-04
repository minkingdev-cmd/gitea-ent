// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"net/http"

	auth_model "gitea.dev/models/auth"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/web/middleware"
)

func OrganizationAccessCredentialCeiling(ctx context.Context, actor *user_model.User, orgID int64) (CredentialCeiling, error) {
	invalid := &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	if actor == nil || actor.ID <= 0 || orgID <= 0 {
		return CredentialCeiling{}, invalid
	}
	org, err := user_model.GetUserByID(ctx, orgID)
	if err != nil {
		if user_model.IsErrUserNotExist(err) {
			return CredentialCeiling{}, invalid
		}
		return CredentialCeiling{}, &ExecutionError{Reason: "policy_read_failed", Status: http.StatusServiceUnavailable}
	}
	if !org.IsOrganization() {
		return CredentialCeiling{}, invalid
	}
	ceiling := RequestCredentialCeiling(ctx, actor)
	ceiling.organizationID = orgID
	if ceiling.Read && ceiling.Write {
		return ceiling, nil
	}
	scope, exists := middleware.GetContextData(ctx)["ApiTokenScope"].(auth_model.AccessTokenScope)
	if !exists {
		return ceiling, nil
	}
	read, err := scope.HasScope(auth_model.AccessTokenScopeReadOrganization)
	if err != nil {
		return CredentialCeiling{}, invalid
	}
	write, err := scope.HasScope(auth_model.AccessTokenScopeWriteOrganization)
	if err != nil || !read || !write {
		return CredentialCeiling{}, invalid
	}
	ceiling.Read, ceiling.Write = true, true
	ceiling.Actions = []authz.Action{authz.ManageAccess}
	return ceiling, nil
}
