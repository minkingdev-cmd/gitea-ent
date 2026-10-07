// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"slices"
	"strconv"
	"strings"

	auth_model "gitea.dev/models/auth"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/web/middleware"
)

type CredentialCeiling struct {
	PublicOnly     bool           `json:"public_only,omitempty"`
	Read           bool           `json:"read"`
	Write          bool           `json:"write"`
	NativeOnly     bool           `json:"native_only"`
	Reference      string         `json:"reference,omitempty"`
	Actions        []authz.Action `json:"actions,omitempty"`
	organizationID int64
}

func roleEligible(actor *user_model.User) bool {
	return actor != nil && actor.ID > 0 && actor.ExtDoerData == nil && actor.IsIndividual() && actor.IsActive && !actor.ProhibitLogin && !actor.IsRestricted
}

func visibleAction(key authz.Action, permission *access_model.Permission, ceiling CredentialCeiling, archived bool) bool {
	if len(ceiling.Actions) > 0 && !slices.Contains(ceiling.Actions, key) {
		return false
	}
	entry, exists := authz.LookupAction(key)
	if !exists || permission == nil || !ceiling.Read || !permission.HasAnyUnitAccessOrPublicAccess() {
		return false
	}
	if entry.Mutating && !ceiling.Write {
		return false
	}
	if archived && slices.Contains([]authz.Action{authz.CreateBranch, authz.PushBranch, authz.PushProtectedBranch, authz.CreatePullRequest, authz.ReviewPullRequest, authz.MergePullRequest, authz.ManageCodeowners}, key) {
		return false
	}
	anyVisible := false
	for _, required := range entry.Units {
		typ := map[string]unit.Type{"code": unit.TypeCode, "pull_requests": unit.TypePullRequests, "actions": unit.TypeActions}[required]
		if permission.CanRead(typ) {
			anyVisible = true
		} else if !entry.UnitsAny {
			return false
		}
	}
	return !entry.UnitsAny || anyVisible
}

func NativeActions(repo *repo_model.Repository, permission *access_model.Permission, ceiling CredentialCeiling) []authz.Action {
	if repo == nil || permission == nil {
		return nil
	}
	var result []authz.Action
	for _, entry := range authz.Catalog() {
		if !visibleAction(entry.Key, permission, ceiling, repo.IsArchived) {
			continue
		}
		allowed := permission.IsOwner()
		if !allowed {
			switch entry.Key {
			case authz.ViewMetadata, authz.ReadCode, authz.Clone:
				allowed = true
			case authz.CreateBranch, authz.PushBranch:
				allowed = permission.CanWrite(unit.TypeCode)
			case authz.CreatePullRequest, authz.ReviewPullRequest:
				allowed = permission.CanWrite(unit.TypePullRequests)
			case authz.MergePullRequest:
				allowed = permission.CanWrite(unit.TypeCode)
			case authz.ManageBranchProtection, authz.ManageCodeowners, authz.ManageWebhook, authz.ManageCI:
				allowed = permission.IsAdmin()
			}
		}
		if allowed {
			result = append(result, entry.Key)
		}
	}
	slices.Sort(result)
	return result
}

func safeCredentialReference(reference string) string {
	kind, rawID, ok := strings.Cut(reference, ":")
	if !ok || !slices.Contains([]string{"access-token", "oauth2-grant", "gitea-actions", "deploy-key", "ssh-key", "runner-registration-token"}, kind) {
		return ""
	}
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 {
		return ""
	}
	return kind + ":" + strconv.FormatInt(id, 10)
}

func RequestCredentialCeiling(ctx context.Context, actor *user_model.User) CredentialCeiling {
	ceiling := CredentialCeiling{Read: true, Write: actor != nil}
	data := middleware.GetContextData(ctx)
	if scope, exists := data["ApiTokenScope"].(auth_model.AccessTokenScope); exists {
		var err error
		ceiling.Read, err = scope.HasScope(auth_model.AccessTokenScopeReadRepository)
		if err != nil {
			ceiling.Read = false
		}
		ceiling.Write, err = scope.HasScope(auth_model.AccessTokenScopeWriteRepository)
		if err != nil {
			ceiling.Write = false
		}
	}
	ceiling.Reference, _ = data[middleware.ContextDataKeyAuthCredential].(string)
	if actor != nil && actor.ExtDoerData != nil {
		ceiling.NativeOnly = true
		ceiling.Reference = actor.ExtDoerData.EncodeToString()
	}
	return ceiling
}
