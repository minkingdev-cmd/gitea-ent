// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package private

import (
	"context"
	"net/http"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/private"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/contexttest"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReceiveAdmissionRechecksNativeWriteAfterRevocation(t *testing.T) {
	for _, variant := range []string{"unchanged", "write-revoked", "push-rule-revoked", "native-read-failed"} {
		t.Run(variant, func(t *testing.T) {
			require.NoError(t, unittest.PrepareTestDatabase())
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true))
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true))
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz.FailClosedOnError, false))
			t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
			t.Cleanup(test.MockVariableValue(&setting.InternalToken, "receive-current-native-test"))
			access := &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}
			require.NoError(t, db.Insert(t.Context(), access))
			rule := &git_model.ProtectedBranch{RepoID: 1, RuleName: "master", CanPush: true}
			require.NoError(t, db.Insert(t.Context(), rule))
			role := &authz_model.RoleDefinition{Name: "receive-native", LowerName: "receive-native", ScopeType: authz_model.ScopeRepo, ScopeID: 1, Revision: 1}
			require.NoError(t, db.Insert(t.Context(), role))
			_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
			require.NoError(t, err)
			require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.PushProtectedBranch, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
			require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{RoleID: role.ID, SubjectType: authz_model.SubjectUser, SubjectID: 4, ScopeType: authz_model.ScopeRepo, ScopeID: 1, ScopeOwnerID: 2}))
			ctx, response := contexttest.MockPrivateContext(t, "/")
			ctx.SetPathParam("owner", "user2")
			ctx.SetPathParam("repo", "repo1")
			RepoAssignment(ctx)
			require.False(t, ctx.Written(), response.Body.String())
			t.Cleanup(func() { ctx.Repo.GitRepo.Close() })
			require.True(t, loadContextDoerPermission(ctx, 4, ""))
			commit, err := ctx.Repo.GitRepo.GetBranchCommitID(t.Context(), "master")
			require.NoError(t, err)
			opts := &private.HookOptions{UserID: 4, OldCommitIDs: []string{commit}, NewCommitIDs: []string{commit}, RefFullNames: []git.RefName{git.RefNameFromBranch("master")}}
			opts.AuthzOperation = authz_service.NewHookOperationTicket(ctx, authz_service.EvaluateInput{Actor: ctx.Doer, Repo: ctx.Repo.Repository, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "git_http"}}, nil)
			preReceiveBranch(&preReceiveContext{PrivateContext: ctx, opts: opts}, commit, commit, opts.RefFullNames[0])
			require.False(t, ctx.Written(), response.Body.String())
			status, reason := http.StatusForbidden, "native_visibility_denied"
			switch variant {
			case "write-revoked":
				access.Mode = perm.AccessModeRead
				_, err = db.GetEngine(t.Context()).ID(access.ID).Cols("mode").Update(access)
			case "push-rule-revoked":
				rule.CanPush = false
				_, err = db.GetEngine(t.Context()).ID(rule.ID).Cols("can_push").Update(rule)
			case "native-read-failed":
				status, reason = http.StatusServiceUnavailable, "policy_read_failed"
				_, err = db.Exec(t.Context(), "ALTER TABLE access RENAME TO native_access_unavailable")
				t.Cleanup(func() {
					_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE native_access_unavailable RENAME TO access")
					require.NoError(t, err)
				})
			}
			require.NoError(t, err)
			operationCtx, operation := receiveOperation(ctx, opts)
			require.NotNil(t, operation)
			admitted := admitReceiveBranches(operationCtx, ctx, operation, opts)
			if variant == "unchanged" {
				require.True(t, admitted, response.Body.String())
				unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, Action: authz.PushProtectedBranch, DecisionMode: "enforce", AuthorizationDecision: "allow", ExecutionStarted: true, NativeOutcome: "unknown"})
				return
			}
			require.False(t, admitted)
			require.Equal(t, status, response.Code, response.Body.String())
			require.Contains(t, response.Body.String(), reason)
			require.NotContains(t, response.Body.String(), "native_access_unavailable")
			require.NotContains(t, response.Body.String(), "master")
			unittest.AssertNotExistsBean(t, &authz_model.DecisionRecord{ActorID: 4, DecisionMode: "enforce", AuthorizationDecision: "allow"})
		})
	}
}

// TestPreReceiveCanWriteCodePerBranch ensures the maintainer-edit write grant is evaluated against
// the exact ref being pushed on every call, derived from that ref rather than shared mutable state.
// Otherwise, a per-branch grant (an open PR with "allow edits from maintainers") could be batched
// together with a protected branch or a tag to escalate into full repository write.
func TestPreReceiveCanWriteCodePerBranch(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())

	baseRepo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 10})
	headRepo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 11})
	require.NoError(t, baseRepo.LoadOwner(t.Context()))
	require.NoError(t, headRepo.LoadOwner(t.Context()))

	// An open PR from the head repo owner, with maintainer edits allowed: this grants the base
	// repo owner write access to exactly this head branch and nothing else.
	pr := &issues_model.PullRequest{
		Issue: &issues_model.Issue{
			RepoID:   baseRepo.ID,
			PosterID: headRepo.OwnerID,
		},
		HeadRepoID:          headRepo.ID,
		BaseRepoID:          baseRepo.ID,
		HeadBranch:          "granted-branch",
		BaseBranch:          "master",
		AllowMaintainerEdit: true,
	}
	require.NoError(t, issues_model.NewPullRequest(t.Context(), baseRepo, pr.Issue, nil, nil, pr))

	// The pusher is the base repo owner (the maintainer) with only read access on the head repo.
	mockCtx, _ := contexttest.MockPrivateContext(t, "/")
	ctx := &preReceiveContext{PrivateContext: mockCtx}
	ctx.SetPathParam("owner", headRepo.OwnerName)
	ctx.SetPathParam("repo", headRepo.Name)
	RepoAssignment(ctx.PrivateContext)
	loadContextDoerPermission(ctx.PrivateContext, baseRepo.OwnerID, "")

	// The granted branch must be writable...
	assert.True(t, ctx.canWriteCodeRef(git.RefNameFromBranch("granted-branch")))

	// ...but another branch in the same push must NOT inherit that grant.
	assert.False(t, ctx.canWriteCodeRef(git.RefNameFromBranch("master")))

	// ...and a tag sharing the granted branch's name must NOT inherit it either: the grant is
	// scoped to PR head branches, so a non-branch ref can never match it. (A tag ref already
	// yields an empty branch name, so this guards the per-ref evaluation, not the IsBranch check.)
	assert.False(t, ctx.canWriteCodeRef(git.RefNameFromTag("granted-branch")))
}
