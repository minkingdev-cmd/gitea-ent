// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"

	authz_model "gitea.dev/models/enterpriseauthz"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
)

type managementScope struct {
	actor   *user_model.User
	scope   authz_model.Scope
	ownerID int64
	repo    *repo_model.Repository
}

func CheckManagementAuthority(ctx context.Context, actor *user_model.User, scope authz_model.Scope) error {
	_, err := resolveManagementScope(ctx, actor, scope)
	return err
}

func resolveManagementScope(ctx context.Context, actor *user_model.User, scope authz_model.Scope) (*managementScope, error) {
	if actor == nil || actor.ID <= 0 || actor.ExtDoerData != nil {
		return nil, util.ErrPermissionDenied
	}
	freshActor, err := user_model.GetUserByID(ctx, actor.ID)
	if user_model.IsErrUserNotExist(err) {
		return nil, util.ErrPermissionDenied
	}
	if err != nil {
		return nil, errors.New("policy_read_failed")
	}
	if !roleEligible(freshActor) {
		return nil, util.ErrPermissionDenied
	}
	if !scope.Valid() {
		return nil, util.ErrNotExist
	}
	resolved := &managementScope{actor: freshActor, scope: scope}
	var allowed bool
	switch scope.Type {
	case authz_model.ScopeSystem:
		allowed, err = access_model.HasSystemManagementAuthority(ctx, freshActor)
	case authz_model.ScopeOrg:
		var org *user_model.User
		org, err = user_model.GetUserByID(ctx, scope.ID)
		if user_model.IsErrUserNotExist(err) || err == nil && !org.IsOrganization() {
			return nil, util.ErrNotExist
		}
		if err == nil {
			resolved.ownerID = org.ID
			allowed, err = access_model.HasOrganizationManagementAuthority(ctx, freshActor, org.ID)
		}
	case authz_model.ScopeRepo:
		resolved.repo, err = repo_model.GetRepositoryByID(ctx, scope.ID)
		if repo_model.IsErrRepoNotExist(err) {
			return nil, util.ErrNotExist
		}
		if err != nil {
			break
		}
		resolved.ownerID = resolved.repo.OwnerID
		permission, permissionErr := access_model.GetDoerRepoPermission(ctx, resolved.repo, freshActor)
		if permissionErr != nil {
			err = permissionErr
			break
		}
		if !permission.HasAnyUnitAccessOrPublicAccess() {
			return nil, util.ErrPermissionDenied
		}
		if setting.EnterpriseWeCom.Enabled {
			allowed, err = access_model.HasEnterpriseRepoAuthorization(ctx, freshActor, resolved.repo)
		} else {
			allowed = permission.IsAdmin()
		}
	}
	if err != nil {
		return nil, errors.New("policy_read_failed")
	}
	if !allowed {
		return nil, util.ErrPermissionDenied
	}
	return resolved, nil
}
