// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"testing"

	auth_model "gitea.dev/models/auth"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/web/middleware"

	"github.com/stretchr/testify/require"
)

func TestOrganizationAccessCredentialBounds(t *testing.T) {
	for _, tc := range []struct {
		name           string
		scope          auth_model.AccessTokenScope
		orgID          int64
		valid, limited bool
	}{
		{"organization", auth_model.AccessTokenScopeWriteOrganization, 3, true, true},
		{"repository", auth_model.AccessTokenScopeWriteRepository, 3, true, false},
		{"organization-read", auth_model.AccessTokenScopeReadOrganization, 3, false, false},
		{"repository-read", auth_model.AccessTokenScopeReadRepository, 3, false, false},
		{"unrelated", auth_model.AccessTokenScopeWriteUser, 3, false, false},
		{"unknown", "write:made-up", 3, false, false},
		{"non-org", auth_model.AccessTokenScopeWriteOrganization, 2, false, false},
		{"missing", auth_model.AccessTokenScopeWriteOrganization, 99999, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			enableObservation(t)
			setting.EnterpriseAuthz.Enforce = true
			ctx := reqctx.NewRequestContextForTest(t)
			ctx.GetData()["ApiTokenScope"] = tc.scope
			ctx.GetData()[middleware.ContextDataKeyAuthCredential] = "access-token:42"
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			ceiling, err := OrganizationAccessCredentialCeiling(ctx, actor, tc.orgID)
			if !tc.valid {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.True(t, ceiling.Read && ceiling.Write)
			require.Equal(t, "access-token:42", ceiling.Reference)
			require.Equal(t, tc.orgID, ceiling.organizationID)
			if tc.limited {
				require.Equal(t, []authz.Action{authz.ManageAccess}, ceiling.Actions)
			} else {
				require.Empty(t, ceiling.Actions)
			}
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
			permission, e := access_model.GetDoerRepoPermission(ctx, repo, actor)
			require.NoError(t, e)
			for _, action := range []authz.Action{authz.ManageAccess, authz.ReadCode, authz.ManageSecret} {
				decision, e := Evaluate(ctx, EvaluateInput{Actor: actor, Repo: repo, Permission: &permission, Action: action, Credential: ceiling, ConditionContext: authz.ConditionContext{Source: "api"}})
				require.NoError(t, e)
				expected := "allow"
				if tc.limited && action != authz.ManageAccess {
					expected = "deny"
				}
				require.Equal(t, expected, decision.CandidateDecision)
			}
			repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
			decision, e := Evaluate(ctx, EvaluateInput{Actor: actor, Repo: repo, Permission: &permission, Action: authz.ManageAccess, Credential: ceiling, ConditionContext: authz.ConditionContext{Source: "api"}})
			require.NoError(t, e)
			require.Equal(t, "deny", decision.CandidateDecision)
		})
	}
}
