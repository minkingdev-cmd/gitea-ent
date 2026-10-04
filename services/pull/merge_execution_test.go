// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"testing"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/timeutil"
	"gitea.dev/services/audit"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func mergeExecutionContext(t *testing.T) context.Context {
	t.Helper()
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	return audit.WithOrigin(t.Context(), audit_model.OriginAPI)
}

func TestMergeExecutionManualContextBounds(t *testing.T) {
	for _, invalid := range []string{"scope", "canceled", "merge-base", "inactive", "archived", "native-style"} {
		t.Run(invalid, func(t *testing.T) {
			ctx := mergeExecutionContext(t)
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			require.NoError(t, pr.LoadBaseRepo(ctx))
			prUnit, err := pr.BaseRepo.GetUnit(ctx, unit.TypePullRequests)
			require.NoError(t, err)
			prUnit.PullRequestsConfig().AllowManualMerge = true
			require.NoError(t, repo_model.UpdateRepoUnitConfig(ctx, prUnit))
			repository, err := git.OpenRepository(ctx, pr.BaseRepo)
			require.NoError(t, err)
			defer repository.Close()
			commitID, err := repository.GetBranchCommitID(ctx, pr.BaseBranch)
			require.NoError(t, err)
			switch invalid {
			case "scope":
				request := reqctx.NewRequestContextForTest(t)
				request.GetData()["ApiTokenScope"] = auth_model.AccessTokenScopeReadRepository
				ctx = audit.WithOrigin(request, audit_model.OriginAPI)
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "merge-base":
				_, err = db.GetEngine(ctx).ID(pr.ID).Cols("merge_base").Update(&issues_model.PullRequest{MergeBase: ""})
			case "inactive":
				_, err = db.GetEngine(ctx).ID(actor.ID).Cols("is_active").Update(&user_model.User{IsActive: false})
			case "archived":
				_, err = db.GetEngine(ctx).ID(pr.BaseRepoID).Cols("is_archived").Update(&repo_model.Repository{IsArchived: true})
			case "native-style":
				prUnit.PullRequestsConfig().AllowManualMerge = false
				err = repo_model.UpdateRepoUnitConfig(ctx, prUnit)
			}
			require.NoError(t, err)
			err = MergedManually(ctx, pr, actor, repository, commitID)
			require.Error(t, err)
			stored := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
			require.False(t, stored.HasMerged)
		})
	}
}

func TestMergeExecutionDirectSetMergedHasNoPermit(t *testing.T) {
	ctx := mergeExecutionContext(t)
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	merged, err := SetMerged(ctx, pr, pr.MergeBase, timeutil.TimeStampNow(), actor, issues_model.PullRequestStatusManuallyMerged)
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.False(t, merged)
	require.False(t, pr.HasMerged)
	stored := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
	require.False(t, stored.HasMerged)
}

func TestMergeExecutionSharedNativeQualification(t *testing.T) {
	ctx := mergeExecutionContext(t)
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	err := Merge(ctx, pr, actor, repo_model.MergeStyleMerge, "", "merge execution qualification", false)
	require.ErrorIs(t, err, ErrNoPermissionToMerge)
	stored := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
	require.False(t, stored.HasMerged)
}

func TestMergeExecutionAutodetectRequiresCurrentAction(t *testing.T) {
	ctx := mergeExecutionContext(t)
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(ctx))
	prUnit, err := pr.BaseRepo.GetUnit(ctx, unit.TypePullRequests)
	require.NoError(t, err)
	prUnit.PullRequestsConfig().AutodetectManualMerge = true
	require.NoError(t, repo_model.UpdateRepoUnitConfig(ctx, prUnit))
	head, err := git.GetFullCommitID(ctx, pr.BaseRepo, pr.GetGitHeadRefName())
	require.NoError(t, err)
	require.NoError(t, gitcmd.NewCommand("update-ref").AddDynamicArguments(git.BranchPrefix+pr.BaseBranch, head).WithRepo(pr.BaseRepo).RunWithStderr(ctx))
	_, err = db.GetEngine(ctx).Where("repo_id = ? AND name = ?", pr.BaseRepoID, pr.BaseBranch).Cols("pusher_id").Update(&git_model.Branch{PusherID: 4})
	require.NoError(t, err)
	require.NoError(t, db.Insert(ctx, &git_model.ProtectedBranch{RepoID: pr.BaseRepoID, RuleName: pr.BaseBranch, CanPush: true, EnableMergeWhitelist: true, MergeWhitelistUserIDs: []int64{4}}))
	require.False(t, manuallyMerged(ctx, pr))
	stored := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
	require.False(t, stored.HasMerged)
	row := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: pr.BaseRepoID, Action: authz.MergePullRequest})
	require.Equal(t, "deny", row.AuthorizationDecision)
	role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, Name: "manual-autodetect", LowerName: "manual-autodetect", Revision: 1, CreatedBy: 2}
	require.NoError(t, db.Insert(ctx, role))
	_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	require.NoError(t, db.Insert(ctx, &authz_model.RolePermission{RoleID: role.ID, Action: authz.MergePullRequest, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}, &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: 4, ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, ScopeOwnerID: pr.BaseRepo.OwnerID, RoleID: role.ID}))
	require.True(t, manuallyMerged(ctx, pr))
	stored = unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
	require.True(t, stored.HasMerged)
	require.Equal(t, int64(4), stored.MergerID)
	unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: pr.BaseRepoID, Action: authz.MergePullRequest, RequestSource: "auto_merge", AuthorizationDecision: "allow", ExecutionStarted: true, NativeOutcome: "success"})
}

func TestMergeExecutionManualReaderRequiresAction(t *testing.T) {
	ctx := mergeExecutionContext(t)
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	require.NoError(t, pr.LoadBaseRepo(ctx))
	prUnit, err := pr.BaseRepo.GetUnit(ctx, unit.TypePullRequests)
	require.NoError(t, err)
	prUnit.PullRequestsConfig().AllowManualMerge = true
	require.NoError(t, repo_model.UpdateRepoUnitConfig(ctx, prUnit))
	require.NoError(t, db.Insert(ctx, &git_model.ProtectedBranch{RepoID: pr.BaseRepoID, RuleName: pr.BaseBranch, CanPush: true, EnableMergeWhitelist: true, MergeWhitelistUserIDs: []int64{actor.ID}}))
	repository, err := git.OpenRepository(ctx, pr.BaseRepo)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, repository.Close()) })
	commitID, err := repository.GetBranchCommitID(ctx, pr.BaseBranch)
	require.NoError(t, err)
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, MergedManually(ctx, pr, actor, repository, commitID), &rejection)
	require.Equal(t, 403, rejection.Status)
	stored := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
	require.False(t, stored.HasMerged)
	row := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: pr.BaseRepoID, ActorID: actor.ID, Action: authz.MergePullRequest})
	require.Equal(t, "deny", row.AuthorizationDecision)
	require.False(t, row.ExecutionStarted)
}
