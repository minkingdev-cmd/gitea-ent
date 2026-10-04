// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package automerge

import (
	"context"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	organization_model "gitea.dev/models/organization"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	pull_model "gitea.dev/models/pull"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/globallock"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/audit"
	"gitea.dev/services/automergequeue"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func TestAutoMergeExecutionCleanupHasHeadAttribution(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce = true, true
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	base := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 10})
	head := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 11})
	ctx, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: base, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, Action: authz.MergePullRequest, ConditionContext: authz.ConditionContext{Source: "auto_merge"}})
	ctx, observation, err := autoMergeBranchCleanupContext(ctx, actor, head.ID, "branch2")
	require.NoError(t, err)
	source, ceiling := authz_service.ExecutionAttributionForActor(ctx, actor, head.ID)
	require.Equal(t, "auto_merge", source)
	require.True(t, ceiling.Read)
	require.True(t, ceiling.Write)
	observation.Finish(context.WithoutCancel(ctx), authz_service.NativeUnknown, authz_service.StageOperation)
}

func TestAutoMergeExecutionTeamMembershipAfterQueue(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	t.Cleanup(test.MockVariableValue(&automergequeue.AddToQueue, func(automergequeue.AutoMergeItem) {}))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	ctx := audit.WithOrigin(t.Context(), audit_model.OriginAPI)
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 6})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	require.NoError(t, pr.LoadBaseRepo(ctx))
	_, err := db.GetEngine(ctx).ID(2).Cols("authorize").Update(&organization_model.Team{AccessMode: perm.AccessModeRead})
	require.NoError(t, err)
	_, err = db.GetEngine(ctx).Where("team_id = ?", 2).Cols("access_mode").Update(&organization_model.TeamUnit{AccessMode: perm.AccessModeRead})
	require.NoError(t, err)
	_, err = db.GetEngine(ctx).Where("repo_id = ? AND user_id = ?", 3, 4).Cols("mode").Update(&access_model.Access{Mode: perm.AccessModeRead})
	require.NoError(t, err)
	require.NoError(t, db.Insert(ctx, &repo_model.Collaboration{RepoID: 3, UserID: 4, Mode: perm.AccessModeRead}, &git_model.ProtectedBranch{RepoID: 3, RuleName: "master", CanPush: true, EnableMergeWhitelist: true, MergeWhitelistUserIDs: []int64{4}}))
	head, err := git.GetFullCommitID(ctx, pr.BaseRepo, git.BranchPrefix+pr.HeadBranch)
	require.NoError(t, err)
	require.NoError(t, gitcmd.NewCommand("update-ref").AddDynamicArguments(pr.GetGitHeadRefName(), head).WithRepo(pr.BaseRepo).RunWithStderr(ctx))
	role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: 3, Name: "queued-team-merge", LowerName: "queued-team-merge", Revision: 1, CreatedBy: 2}
	require.NoError(t, db.Insert(ctx, role))
	_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	require.NoError(t, db.Insert(ctx, &authz_model.RolePermission{RoleID: role.ID, Action: authz.MergePullRequest, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}, &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectTeam, SubjectID: 2, ScopeType: authz_model.ScopeRepo, ScopeID: 3, ScopeOwnerID: 3, RoleID: role.ID}))
	scheduled, err := ScheduleAutoMerge(ctx, actor, pr, repo_model.MergeStyleMerge, "queued team merge", false)
	require.NoError(t, err)
	require.True(t, scheduled)
	unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 3, Action: authz.MergePullRequest, ExecutionStarted: true, NativeOutcome: "unknown", AuthorizationDecision: "allow"})
	_, err = db.GetEngine(ctx).Delete(&organization_model.TeamUser{OrgID: 3, TeamID: 2, UID: 4})
	require.NoError(t, err)
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, handlePullRequestAutoMerge(t.Context(), pr, head), &rejection)
	require.Equal(t, 403, rejection.Status)
	stored := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
	require.False(t, stored.HasMerged)
	unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 3, Action: authz.MergePullRequest, RequestSource: "auto_merge", AuthorizationDecision: "deny"})
}

func TestMain(m *testing.M) {
	unittest.MainTest(m)
}

func TestAutoMergeExecutionDispatchDoesNotHoldPullLock(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	ctx := audit.WithOrigin(t.Context(), audit_model.OriginAPI)
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	dispatched := false
	t.Cleanup(test.MockVariableValue(&automergequeue.AddToQueue, func(automergequeue.AutoMergeItem) {
		dispatched = true
		ok, release, err := globallock.TryLock(ctx, "pull_working_2")
		require.NoError(t, err)
		defer release()
		require.True(t, ok)
	}))
	scheduled, err := ScheduleAutoMerge(ctx, actor, pr, repo_model.MergeStyleMerge, "ready for background merge", false)
	require.NoError(t, err)
	require.True(t, scheduled)
	require.True(t, dispatched)
}

func TestAutoMergeExecutionCurrentActorAndGrantAfterQueue(t *testing.T) {
	for _, change := range []string{"role", "native", "inactive", "fallback-mode"} {
		t.Run(change, func(t *testing.T) {
			unittest.PrepareTestEnv(t)
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
			t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
			t.Cleanup(test.MockVariableValue(&automergequeue.AddToQueue, func(automergequeue.AutoMergeItem) {}))
			setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
			ctx := audit.WithOrigin(t.Context(), audit_model.OriginAPI)
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
			require.NoError(t, pr.LoadBaseRepo(ctx))
			if change == "native" || change == "inactive" {
				require.NoError(t, db.Insert(ctx, &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}, &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}))
			} else {
				require.NoError(t, db.Insert(ctx, &git_model.ProtectedBranch{RepoID: 1, RuleName: pr.BaseBranch, CanPush: true, EnableMergeWhitelist: true, MergeWhitelistUserIDs: []int64{4}}))
				role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: 1, Name: "queued-merge", LowerName: "queued-merge", Revision: 1, CreatedBy: 2}
				binding := &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: 4, ScopeType: authz_model.ScopeRepo, ScopeID: 1, ScopeOwnerID: 2}
				require.NoError(t, db.Insert(ctx, role))
				_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
				require.NoError(t, err)
				binding.RoleID = role.ID
				require.NoError(t, db.Insert(ctx, &authz_model.RolePermission{RoleID: role.ID, Action: authz.MergePullRequest, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}, binding))
			}
			scheduled, err := ScheduleAutoMerge(ctx, actor, pr, repo_model.MergeStyleMerge, "queued merge", false)
			require.NoError(t, err)
			require.True(t, scheduled)
			unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, Action: authz.MergePullRequest, RequestSource: "api", ExecutionStarted: true, NativeOutcome: "unknown"})
			switch change {
			case "native":
				_, err = db.GetEngine(ctx).Delete(&repo_model.Collaboration{RepoID: 1, UserID: 4})
				require.NoError(t, err)
				_, err = db.GetEngine(ctx).Delete(&access_model.Access{RepoID: 1, UserID: 4})
			case "inactive":
				_, err = db.GetEngine(ctx).ID(4).Cols("is_active").Update(&user_model.User{IsActive: false})
			default:
				_, err = db.GetEngine(ctx).Delete(&authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: 4, ScopeType: authz_model.ScopeRepo, ScopeID: 1})
			}
			require.NoError(t, err)
			if change == "fallback-mode" {
				setting.EnterpriseAuthz.Enforce = false
				setting.EnterpriseAuthz.Enabled = false
				unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: pr.ID, DoerID: 4})
				setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce = true, true
			}
			head, err := git.GetFullCommitID(ctx, pr.BaseRepo, pr.GetGitHeadRefName())
			require.NoError(t, err)
			err = handlePullRequestAutoMerge(t.Context(), pr, head)
			require.Error(t, err)
			stored := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
			require.False(t, stored.HasMerged)
			if change == "role" || change == "fallback-mode" {
				var rejection *authz_service.ExecutionError
				require.ErrorAs(t, err, &rejection)
				require.Equal(t, 403, rejection.Status)
				unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, Action: authz.MergePullRequest, RequestSource: "auto_merge", AuthorizationDecision: "deny"})
			} else {
				unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, Action: authz.MergePullRequest, RequestSource: "auto_merge", NativeOutcome: "denied"})
			}
		})
	}
}

func TestAutoMergeExecutionScheduleRejectsBeforeMutation(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	t.Cleanup(test.MockVariableValue(&automergequeue.AddToQueue, func(automergequeue.AutoMergeItem) {}))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	ctx := audit.WithOrigin(t.Context(), audit_model.OriginAPI)
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	require.NoError(t, db.Insert(ctx, &git_model.ProtectedBranch{RepoID: pr.BaseRepoID, RuleName: pr.BaseBranch, CanPush: true, EnableMergeWhitelist: true, MergeWhitelistUserIDs: []int64{actor.ID}}))
	before := unittest.GetCount(t, &issues_model.Comment{IssueID: pr.IssueID})
	scheduled, err := ScheduleAutoMerge(ctx, actor, pr, repo_model.MergeStyleMerge, "private scheduling message", false)
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, 403, rejection.Status)
	require.False(t, scheduled)
	unittest.AssertNotExistsBean(t, &pull_model.AutoMerge{PullID: pr.ID})
	require.Equal(t, before, unittest.GetCount(t, &issues_model.Comment{IssueID: pr.IssueID}))
	row := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: pr.BaseRepoID, ActorID: actor.ID, Action: authz.MergePullRequest})
	require.False(t, row.ExecutionStarted)
	require.NotContains(t, row.SnapshotJSON, "private scheduling message")
}
