// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package automerge

import (
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	pull_model "gitea.dev/models/pull"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/commitstatus"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/repository"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/timeutil"
	"gitea.dev/services/audit"
	"gitea.dev/services/automergequeue"
	authz_service "gitea.dev/services/enterpriseauthz"
	pull_service "gitea.dev/services/pull"

	"github.com/stretchr/testify/require"
)

func TestMergeGateScheduleWaitsWithAtomicAttribution(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	t.Cleanup(test.MockVariableValue(&automergequeue.AddToQueue, func(automergequeue.AutoMergeItem) {}))
	ctx := audit.WithOrigin(t.Context(), audit_model.OriginUI)
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, db.Insert(ctx, &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["security/queue"]}`}))
	scheduled, err := ScheduleAutoMerge(ctx, actor, pr, repo_model.MergeStyleMerge, "waiting", false)
	require.NoError(t, err)
	require.True(t, scheduled)
	queue := unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: pr.ID})
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "schedule"})
	require.Equal(t, queue.ID, record.ScheduledMergeID)
	require.Equal(t, "not_admitted", record.AdmissionDecision)
	require.Equal(t, "not_started", record.ExecutionState)
	require.Equal(t, "deny", record.CandidateDecision)
	require.Contains(t, record.SnapshotJSON, "credential_attribution")
	require.Contains(t, record.SnapshotJSON, "session_delegation")
	require.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateEvaluation}, 1)
}

func TestMergeGateWorkerConsumesScheduleAttribution(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	t.Cleanup(test.MockVariableValue(&automergequeue.AddToQueue, func(automergequeue.AutoMergeItem) {}))
	ctx := audit.WithOrigin(t.Context(), audit_model.OriginUI)
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, db.Insert(ctx, &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["security/queue"]}`}))
	scheduled, err := ScheduleAutoMerge(ctx, actor, pr, repo_model.MergeStyleMerge, "waiting", false)
	require.NoError(t, err)
	require.True(t, scheduled)
	queue := unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: pr.ID})
	require.NoError(t, pr.LoadBaseRepo(ctx))
	head, err := git.GetFullCommitID(ctx, pr.BaseRepo, pr.GetGitHeadRefName())
	require.NoError(t, err)
	err = handlePullRequestAutoMerge(t.Context(), pr, head)
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, 409, rejection.Status)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "auto_admission"})
	require.Equal(t, queue.ID, record.ScheduledMergeID)
	require.Contains(t, record.ReasonsJSON, "required_check")
	require.NotContains(t, record.ReasonsJSON, "credential_denied")
	require.Error(t, handlePullRequestAutoMerge(t.Context(), pr, head))
	unittest.AssertCount(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "auto_admission"}, 1)
	_, err = db.GetEngine(ctx).Where("scope_type=? AND scope_id=? AND feature_key=?", authz_model.ScopeRepo, pr.BaseRepoID, authz.FeatureGitleaksScan).Cols("config_json").Update(&authz_model.FeatureGrant{ConfigJSON: `{"check_contexts":["security/changed"]}`})
	require.NoError(t, err)
	require.Error(t, handlePullRequestAutoMerge(t.Context(), pr, head))
	unittest.AssertCount(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "auto_admission"}, 2)
	_, err = db.GetEngine(ctx).ID(actor.ID).Cols("is_active").Update(&user_model.User{IsActive: false})
	require.NoError(t, err)
	require.Error(t, handlePullRequestAutoMerge(t.Context(), pr, head))
	latest := new(authz_model.MergeGateEvaluation)
	found, err := db.GetEngine(ctx).Where("pull_id=? AND phase=?", pr.ID, "auto_admission").Desc("id").Get(latest)
	require.NoError(t, err)
	require.True(t, found)
	require.Contains(t, latest.ReasonsJSON, "actor_invalid")
}

func TestMergeGatePolicyWakeScopesCurrentQueues(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, pull_model.ScheduleAutoMerge(t.Context(), actor, 2, repo_model.MergeStyleMerge, "", false))
	var items []automergequeue.AutoMergeItem
	t.Cleanup(test.MockVariableValue(&automergequeue.AddToQueue, func(item automergequeue.AutoMergeItem) { items = append(items, item) }))
	handleAutoMergeItem("gate-scope:repo:999:change")
	require.Empty(t, items)
	handleAutoMergeItem("gate-scope:repo:1:change")
	require.Len(t, items, 1)
	require.Contains(t, string(items[0]), "pr:2:")
	items = nil
	_, err := db.GetEngine(t.Context()).Where("pull_id=?", 2).Cols("created_unix").Update(&pull_model.AutoMerge{CreatedUnix: timeutil.TimeStampNow().AddDuration(-48 * time.Hour)})
	require.NoError(t, err)
	populateRecentAutoMergeItems(t.Context())
	require.Len(t, items, 1, "enforce 重启必须复核旧暂停队列，而非只看 24 小时")
}

func TestMergeGateNotifierWakesNegativeFacts(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	var items []automergequeue.AutoMergeItem
	t.Cleanup(test.MockVariableValue(&automergequeue.AddToQueue, func(item automergequeue.AutoMergeItem) { items = append(items, item) }))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	NewNotifier().PullRequestReview(t.Context(), pr, &issues_model.Review{Type: issues_model.ReviewTypeReject}, nil, nil)
	require.Len(t, items, 1)
	require.NoError(t, pr.LoadBaseRepo(t.Context()))
	head, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, pr.GetGitHeadRefName())
	require.NoError(t, err)
	NewNotifier().CreateCommitStatus(t.Context(), pr.BaseRepo, &repository.PushCommit{Sha1: head}, nil, &git_model.CommitStatus{State: "failure"})
	require.Len(t, items, 2)
}

func TestMergeGateScheduleMandatoryDenialKeepsEvidence(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	_, err := db.GetEngine(t.Context()).ID(actor.ID).Cols("is_active").Update(&user_model.User{IsActive: false})
	require.NoError(t, err)
	scheduled, err := ScheduleAutoMerge(t.Context(), actor, pr, repo_model.MergeStyleMerge, "", false)
	require.Error(t, err)
	require.False(t, scheduled)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "schedule"})
	require.Contains(t, record.ReasonsJSON, "actor_invalid")
	require.Equal(t, "not_started", record.ExecutionState)
	unittest.AssertCount(t, &pull_model.AutoMerge{PullID: pr.ID}, 0)
}

func TestMergeGateQueueCredentialAndCancellationBoundaries(t *testing.T) {
	for _, mutation := range []string{"revoked", "narrowed", "generation", "legacy", "cancelled", "replace", "read_error"} {
		t.Run(mutation, func(t *testing.T) {
			unittest.PrepareTestEnv(t)
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true}))
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
			t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
			t.Cleanup(test.MockVariableValue(&setting.InternalToken, "merge-gate-unit-generation"))
			t.Cleanup(test.MockVariableValue(&automergequeue.AddToQueue, func(automergequeue.AutoMergeItem) {}))
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			require.NoError(t, pr.LoadBaseRepo(t.Context()))
			token := &auth_model.AccessToken{UID: actor.ID, Name: "queued", Scope: auth_model.AccessTokenScopeWriteRepository}
			require.NoError(t, auth_model.NewAccessToken(t.Context(), token))
			ctx, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true, Reference: fmt.Sprintf("access-token:%d", token.ID)}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
			require.NoError(t, db.Insert(ctx, &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["security/credential"]}`}))
			scheduled, err := ScheduleAutoMerge(ctx, actor, pr, repo_model.MergeStyleMerge, "", false)
			require.NoError(t, err)
			require.True(t, scheduled)
			queue := unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: pr.ID})
			record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "schedule"})
			require.NotContains(t, record.SnapshotJSON, token.TokenHash)
			ceiling, err := authz_service.MergeGateAutoCredential(ctx, queue.ID, pr.ID, actor.ID, pr.BaseRepo)
			require.NoError(t, err)
			require.True(t, ceiling.Read && ceiling.Write)
			switch mutation {
			case "revoked":
				_, err = db.GetEngine(ctx).ID(token.ID).Delete(new(auth_model.AccessToken))
			case "narrowed":
				_, err = db.GetEngine(ctx).ID(token.ID).Cols("scope").Update(&auth_model.AccessToken{Scope: auth_model.AccessTokenScopeReadRepository})
			case "read_error":
				_, err = db.GetEngine(ctx).ID(token.ID).Cols("scope").Update(&auth_model.AccessToken{Scope: "unknown:scope"})
			case "generation":
				_, err = db.GetEngine(ctx).ID(token.ID).Cols("token_hash").Update(&auth_model.AccessToken{TokenHash: strings.Repeat("e", 64)})
			case "legacy":
				_, err = db.GetEngine(ctx).ID(record.ID).Delete(new(authz_model.MergeGateEvaluation))
			case "cancelled":
				err = RemoveScheduledAutoMerge(ctx, actor, pr)
			case "replace":
				replacement, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: ceiling, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
				scheduled, err = ScheduleAutoMerge(replacement, actor, pr, repo_model.MergeStyleMerge, "replacement", false, ScheduleOptions{ReplaceExisting: true})
				require.True(t, scheduled)
			}
			require.NoError(t, err)
			ceiling, err = authz_service.MergeGateAutoCredential(ctx, queue.ID, pr.ID, actor.ID, pr.BaseRepo)
			if mutation == "read_error" {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.False(t, ceiling.Write)
			if mutation == "cancelled" || mutation == "replace" {
				require.Equal(t, "cancelled", unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{ID: record.ID}).ExecutionState)
				if mutation == "replace" {
					currentQueue := unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: pr.ID})
					require.NotEqual(t, queue.ID, currentQueue.ID)
					currentCeiling, currentErr := authz_service.MergeGateAutoCredential(ctx, currentQueue.ID, pr.ID, actor.ID, pr.BaseRepo)
					require.NoError(t, currentErr)
					require.True(t, currentCeiling.Write)
				}
			} else {
				head, err := git.GetFullCommitID(ctx, pr.BaseRepo, pr.GetGitHeadRefName())
				require.NoError(t, err)
				workerErr := handlePullRequestAutoMerge(t.Context(), pr, head)
				var rejection *authz_service.ExecutionError
				require.ErrorAs(t, workerErr, &rejection)
				denial := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "auto_admission"})
				if mutation == "read_error" {
					require.Equal(t, 503, rejection.Status)
					require.Equal(t, "error", denial.CandidateDecision)
					require.Contains(t, denial.ReasonsJSON, "facts_read_failed")
				} else {
					require.Equal(t, 403, rejection.Status)
					require.Contains(t, denial.ReasonsJSON, "credential_denied")
				}
			}
			require.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
		})
	}
}

func TestMergeGateRolloutPreservesNativeQueue(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			unittest.PrepareTestEnv(t)
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true}))
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: enabled}))
			t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
			t.Cleanup(test.MockVariableValue(&automergequeue.AddToQueue, func(automergequeue.AutoMergeItem) {}))
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["security/shadow"]}`}))
			require.NoError(t, pr.LoadBaseRepo(t.Context()))
			ctx, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "web", Branch: pr.BaseBranch, BranchKnown: true}})
			scheduled, err := ScheduleAutoMerge(ctx, actor, pr, repo_model.MergeStyleMerge, "", false, ScheduleOptions{MergeOptions: pull_service.MergeOptions{Force: true}})
			require.NoError(t, err)
			require.True(t, scheduled)
			if enabled {
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "schedule"})
				require.Equal(t, "not_enforced", record.AdmissionDecision)
				require.True(t, record.BypassRequested)
				require.False(t, record.BypassUsed)
			} else {
				unittest.AssertCount(t, &authz_model.MergeGateEvaluation{}, 0)
			}
		})
	}
}

func TestMergeGateWorkerRejectsChangedAuthorityFeatureAndStatus(t *testing.T) {
	for _, change := range []string{"role", "feature", "status"} {
		t.Run(change, func(t *testing.T) {
			unittest.PrepareTestEnv(t)
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true}))
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
			t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
			t.Cleanup(test.MockVariableValue(&automergequeue.AddToQueue, func(automergequeue.AutoMergeItem) {}))
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
			require.NoError(t, pr.LoadBaseRepo(t.Context()))
			require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: pr.BaseRepoID, UserID: actor.ID, Mode: perm.AccessModeRead}, &access_model.Access{RepoID: pr.BaseRepoID, UserID: actor.ID, Mode: perm.AccessModeRead}, &git_model.ProtectedBranch{RepoID: pr.BaseRepoID, RuleName: pr.BaseBranch, CanPush: true, EnableMergeWhitelist: true, MergeWhitelistUserIDs: []int64{actor.ID}}))
			role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, Name: "queued-gate", LowerName: "queued-gate", Revision: 1, CreatedBy: 2}
			require.NoError(t, db.Insert(t.Context(), role))
			_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
			require.NoError(t, err)
			binding := &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: actor.ID, ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, ScopeOwnerID: pr.BaseRepo.OwnerID, RoleID: role.ID}
			require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.MergePullRequest, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}, binding))
			head, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, pr.GetGitHeadRefName())
			require.NoError(t, err)
			base, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
			require.NoError(t, err)
			status := &git_model.CommitStatus{RepoID: pr.BaseRepoID, SHA: head, Context: "security/changed-after-queue", ContextHash: "after-queue", State: commitstatus.CommitStatusSuccess, Index: 1, CreatorID: actor.ID}
			require.NoError(t, db.Insert(t.Context(), status, &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["security/changed-after-queue"]}`}))
			ctx, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
			scheduled, err := ScheduleAutoMerge(ctx, actor, pr, repo_model.MergeStyleMerge, "", false)
			require.NoError(t, err)
			require.True(t, scheduled)
			require.Equal(t, "allow", unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "schedule"}).CandidateDecision)
			code, expectedStatus := "missing_action", 403
			switch change {
			case "role":
				_, err = db.GetEngine(ctx).ID(binding.ID).Delete(new(authz_model.SubjectRoleBinding))
			case "feature":
				err = db.Insert(ctx, &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, FeatureKey: authz.FeaturePullRequests, State: authz.FeatureDisabled, Revision: 1, ConfigJSON: `{}`})
				code = "feature_disabled"
			case "status":
				_, err = db.GetEngine(ctx).ID(status.ID).Cols("state").Update(&git_model.CommitStatus{State: commitstatus.CommitStatusFailure})
				code, expectedStatus = "required_check", 409
			}
			require.NoError(t, err)
			var rejection *authz_service.ExecutionError
			require.ErrorAs(t, handlePullRequestAutoMerge(t.Context(), pr, head), &rejection)
			require.Equal(t, expectedStatus, rejection.Status)
			record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "auto_admission"})
			require.Contains(t, record.ReasonsJSON, code)
			require.Equal(t, "not_started", record.ExecutionState)
			require.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
			unittest.AssertCount(t, &pull_model.AutoMerge{PullID: pr.ID}, 1)
			after, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
			require.NoError(t, err)
			require.Equal(t, base, after)
		})
	}
}
