// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"errors"
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
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/commitstatus"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/git/gitrepo"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

func TestMergeGateDirectServiceRejectsBeforeGit(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: false}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(t.Context()))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["security/gate-write"]}`}))
	repo, err := git.OpenRepository(t.Context(), pr.BaseRepo)
	require.NoError(t, err)
	defer repo.Close()
	before, err := repo.GetRefCommitID(t.Context(), git.BranchPrefix+pr.BaseBranch)
	require.NoError(t, err)
	ctx, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
	err = Merge(ctx, pr, actor, repo_model.MergeStyleMerge, "", "gate test", false)
	var denied *authz_service.ExecutionError
	require.ErrorAs(t, err, &denied)
	require.Equal(t, "merge_gate_denied", denied.Reason)
	require.Equal(t, 409, denied.Status)
	after, err := repo.GetRefCommitID(t.Context(), git.BranchPrefix+pr.BaseBranch)
	require.NoError(t, err)
	require.Equal(t, before, after)
	current := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
	require.False(t, current.HasMerged)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID})
	require.Equal(t, "deny", record.AdmissionDecision)
	require.Equal(t, "not_started", record.ExecutionState)
	require.Contains(t, record.ReasonsJSON, "required_check")
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.Action("enterprise:merge-gate:evaluation")}, 1)
	setting.Audit.RecordOutput = setting.AuditRecordOutputDisabled
	err = Merge(ctx, pr, actor, repo_model.MergeStyleMerge, "", "gate test", false)
	require.ErrorAs(t, err, &denied)
	require.Equal(t, "merge_gate_evidence_persist_failed", denied.Reason)
	require.Equal(t, 503, denied.Status)
	unittest.AssertCount(t, &authz_model.MergeGateEvaluation{}, 1)
}

func TestMergeGateShadowWithoutActionEnforce(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(t.Context()))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["security/shadow"]}`}))
	current, cancel, err := prepareMergeGateGit(t.Context(), pr)
	require.NoError(t, err)
	defer cancel()
	ctx, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "api"}})
	execution := &mergeExecution{gateGuard: func(ctx context.Context, repo gitrepo.RepositoryFacade, oldSHA, newSHA string) (*authz_model.MergeGateEvaluation, error) {
		return admitMergeGate(ctx, pr, actor, repo_model.MergeStyleMerge, MergeOptions{}, false, current, newSHA, true)
	}}
	_, _, release, err := beginPullGitExecution(ctx, actor, pr.BaseRepo, current.Repo, pr.BaseBranch, current.BaseSHA, current.HeadSHA, true, true, execution)
	require.NoError(t, err)
	defer release()
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID})
	require.Equal(t, "shadow", record.Mode)
	require.Equal(t, "deny", record.CandidateDecision)
	require.Equal(t, "not_enforced", record.AdmissionDecision)
	require.Equal(t, "started", record.ExecutionState)
	require.NoError(t, execution.finishMergeGate(errors.New("execution stopped before Git")))
	record = unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{ID: record.ID})
	require.Equal(t, "failed", record.ExecutionState)
}

func TestMergeGateShadowDoesNotRelaxExistingEnforcement(t *testing.T) {
	for _, guard := range []string{"action", "feature"} {
		t.Run(guard, func(t *testing.T) {
			ctx := mergeExecutionContext(t)
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			require.NoError(t, pr.LoadBaseRepo(ctx))
			require.NoError(t, db.Insert(ctx, &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["security/shadow-existing"]}`}))
			if guard == "action" {
				actor = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
				require.NoError(t, db.Insert(ctx, &git_model.ProtectedBranch{RepoID: pr.BaseRepoID, RuleName: pr.BaseBranch, CanPush: true, EnableMergeWhitelist: true, MergeWhitelistUserIDs: []int64{actor.ID}}))
			} else {
				require.NoError(t, db.Insert(ctx, &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, FeatureKey: authz.FeaturePullRequests, State: authz.FeatureDisabled, Revision: 1, ConfigJSON: `{}`}))
			}
			ceiling := authz_service.CredentialCeiling{Read: true, Write: true}
			if guard == "action" {
				ceiling.Actions = []authz.Action{authz.CreatePullRequest}
			}
			ctx, _ = authz_service.WithObservationContext(ctx, authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: ceiling, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
			before, err := git.GetFullCommitID(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
			require.NoError(t, err)
			var rejected *authz_service.ExecutionError
			require.ErrorAs(t, Merge(ctx, pr, actor, repo_model.MergeStyleMerge, "", "shadow must preserve existing guards", false), &rejected)
			require.Equal(t, 403, rejected.Status)
			if guard == "action" {
				unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: pr.BaseRepoID, ActorID: actor.ID, Action: authz.MergePullRequest, AuthorizationDecision: "deny"})
			} else {
				require.Equal(t, "feature_disabled", rejected.Reason)
			}
			after, err := git.GetFullCommitID(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
			require.NoError(t, err)
			require.Equal(t, before, after)
			require.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
		})
	}
}

func TestMergeGateBypassRequiresIndependentAction(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(t.Context()))
	current, cancel, err := prepareMergeGateGit(t.Context(), pr)
	require.NoError(t, err)
	defer cancel()
	ceiling := authz_service.CredentialCeiling{Read: true, Write: true, Actions: []authz.Action{authz.MergePullRequest}}
	evaluation, err := collectMergeGateEvaluation(t.Context(), pr, actor, repo_model.MergeStyleMerge, "enforce", "admission", "api", ceiling, authz.MergeGateBypass{Requested: true, Reason: "approved incident", Categories: []string{"required_check"}}, current, "")
	require.NoError(t, err)
	require.False(t, evaluation.Snapshot.BypassAuthorized)
	var rejected *authz_service.ExecutionError
	require.ErrorAs(t, mergeGateRejection(evaluation.Result), &rejected)
	require.Equal(t, 403, rejected.Status)
	ceiling.Actions = []authz.Action{authz.MergePullRequest, authz.BypassMergeGate}
	bypass := authz.MergeGateBypass{Requested: true, Reason: "approved incident", Categories: []string{"required_check"}}
	collect := func(request authz.MergeGateBypass) mergeGateEvaluation {
		t.Helper()
		result, err := collectMergeGateEvaluation(t.Context(), pr, actor, repo_model.MergeStyleMerge, "enforce", "admission", "api", ceiling, request, current, "")
		require.NoError(t, err)
		return result
	}
	evaluation = collect(bypass)
	require.Equal(t, "allow", evaluation.Result.AdmissionDecision)
	require.True(t, evaluation.Result.BypassRequested)
	require.False(t, evaluation.Result.BypassUsed)
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{ScopeType: authz_model.ScopeSystem, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["security/bypass"]}`}))
	for _, request := range []authz.MergeGateBypass{
		{Requested: true, Reason: "", Categories: []string{"required_check"}},
		{Requested: true, Reason: "incident\ncontrol", Categories: []string{"required_check"}},
		{Requested: true, Reason: "incident", Categories: []string{"skip_everything"}},
	} {
		evaluation = collect(request)
		require.ErrorAs(t, mergeGateRejection(evaluation.Result), &rejected)
		require.Equal(t, 422, rejected.Status)
	}
	partial := bypass
	partial.Categories = []string{"required_approvals"}
	evaluation = collect(partial)
	require.Equal(t, "deny", evaluation.Result.AdmissionDecision)
	require.False(t, evaluation.Result.BypassUsed)
	evaluation = collect(bypass)
	require.Equal(t, "bypass", evaluation.Result.AdmissionDecision)
	require.True(t, evaluation.Result.BypassUsed)
	require.Contains(t, evaluation.Result.BypassedReasons, authz.MergeGateFact{Code: "required_check", Source: "feature", Context: "security/bypass", State: "missing"})
	ctx, _ := authz_service.WithObservationContext(authz_service.WithOperation(t.Context()), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: ceiling, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
	record, err := admitMergeGate(ctx, pr, actor, repo_model.MergeStyleMerge, MergeOptions{Force: true, BypassReason: bypass.Reason, BypassCategories: bypass.Categories}, false, current, current.HeadSHA, true)
	require.NoError(t, err)
	require.Equal(t, "bypass", record.AdmissionDecision)
	require.True(t, record.BypassUsed)
	require.Equal(t, bypass.Reason, record.BypassReason)
	require.Contains(t, record.ReasonsJSON, "security/bypass")
	policy := unittest.AssertExistsAndLoadBean(t, &authz_model.FeatureGrant{ScopeType: authz_model.ScopeSystem, FeatureKey: authz.FeatureGitleaksScan})
	require.Equal(t, authz.FeatureRequired, policy.State)
	require.EqualValues(t, 1, policy.Revision)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateEvaluation}, 1)
	review := &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 4, Type: issues_model.ReviewTypeComment}
	require.NoError(t, db.Insert(t.Context(), review))
	require.NoError(t, db.Insert(t.Context(), &issues_model.Comment{IssueID: pr.IssueID, ReviewID: review.ID, Type: issues_model.CommentTypeCode, TreePath: "README.md", Line: 1}))
	evaluation = collect(bypass)
	require.Equal(t, "deny", evaluation.Result.AdmissionDecision)
	require.False(t, evaluation.Result.BypassUsed)
	require.Contains(t, evaluation.Result.BlockingReasons, authz.MergeGateFact{Code: "unresolved_conversation", Source: "native", State: "failed"})
}

func TestMergeGateAdmissionRejectsDeletedHeadWithEvidence(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(t.Context()))
	current, cancel, err := prepareMergeGateGit(t.Context(), pr)
	require.NoError(t, err)
	defer cancel()
	_, err = db.GetEngine(t.Context()).ID(pr.ID).Cols("head_repo_id").Update(&issues_model.PullRequest{HeadRepoID: 0})
	require.NoError(t, err)
	ctx, _ := authz_service.WithObservationContext(authz_service.WithOperation(t.Context()), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "api"}})
	record, err := admitMergeGate(ctx, pr, actor, repo_model.MergeStyleMerge, MergeOptions{}, false, current, current.HeadSHA, true)
	var rejected *authz_service.ExecutionError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, 409, rejected.Status)
	require.NotNil(t, record)
	require.Equal(t, "error", record.AdmissionDecision)
	require.Equal(t, "not_started", record.ExecutionState)
	require.Contains(t, record.ReasonsJSON, "state_changed")
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateEvaluation}, 1)
}

func TestMergeGateManualRejectsUnprovenHistoryBeforeMarker(t *testing.T) {
	ctx := mergeExecutionContext(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(ctx))
	prUnit, err := pr.BaseRepo.GetUnit(ctx, unit.TypePullRequests)
	require.NoError(t, err)
	prUnit.PullRequestsConfig().AllowManualMerge = true
	require.NoError(t, repo_model.UpdateRepoUnitConfig(ctx, prUnit))
	repo, err := git.OpenRepository(ctx, pr.BaseRepo)
	require.NoError(t, err)
	defer repo.Close()
	baseSHA, err := repo.GetBranchCommitID(ctx, pr.BaseBranch)
	require.NoError(t, err)
	err = MergedManually(ctx, pr, actor, repo, baseSHA)
	require.Error(t, err)
	unittest.AssertCount(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "manual_recognition"}, 1)
	stored := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
	require.False(t, stored.HasMerged)
	after, err := repo.GetBranchCommitID(ctx, pr.BaseBranch)
	require.NoError(t, err)
	require.Equal(t, baseSHA, after)
}

func TestMergeGateManualHistoryUsesReceiveOldRef(t *testing.T) {
	ctx := mergeExecutionContext(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(ctx))
	repo, err := git.OpenRepository(ctx, pr.BaseRepo)
	require.NoError(t, err)
	defer repo.Close()
	oldSHA, err := repo.GetBranchCommitID(ctx, pr.BaseBranch)
	require.NoError(t, err)
	headSHA, err := repo.GetRefCommitID(ctx, pr.GetGitHeadRefName())
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, git.UpdateRef(context.WithoutCancel(ctx), pr.BaseRepo, git.BranchPrefix+pr.BaseBranch, oldSHA))
	})
	require.NoError(t, git.UpdateRef(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch, headSHA))
	require.NoError(t, RecordManualMergePush(ctx, actor, pr.BaseRepo, pr.BaseBranch, oldSHA, headSHA, "git_http", authz_service.CredentialCeiling{Read: true, Write: true}))
	head, err := repo.GetCommit(ctx, headSHA)
	require.NoError(t, err)
	next, _, err := gitcmd.NewCommand("commit-tree").AddDynamicArguments(head.TreeID.String()).AddArguments("-p").AddDynamicArguments(headSHA).AddArguments("-m", "later base update").WithEnv([]string{"GIT_AUTHOR_NAME=Gate Test", "GIT_AUTHOR_EMAIL=gate@example.invalid", "GIT_COMMITTER_NAME=Gate Test", "GIT_COMMITTER_EMAIL=gate@example.invalid"}).WithRepo(pr.BaseRepo).RunStdString(ctx)
	require.NoError(t, err)
	require.NoError(t, git.UpdateRef(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch, strings.TrimSpace(next)))
	current, err := prepareManualMergeGateGit(ctx, pr, headSHA, false)
	require.NoError(t, err)
	require.Equal(t, oldSHA, current.BaseSHA)
	require.Equal(t, headSHA, current.HeadSHA)
	require.Equal(t, actor.ID, current.PusherID)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID})
	require.Contains(t, record.SnapshotJSON, `"credential_attribution"`)
	require.NotEmpty(t, current.Paths)
	unittest.AssertCount(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "manual_recognition"}, 1)
}

func TestMergeGateFinalFingerprintConsumesConcurrentChanges(t *testing.T) {
	for _, change := range []struct{ name, code, state string }{
		{"status", "required_check", "failure"},
		{"feature", "required_check", "missing"},
		{"path_rule", "sensitive_path_approval", "failed"},
		{"role_binding", "sensitive_path_approval", "failed"},
		{"approval", "sensitive_path_approval", "failed"},
		{"conversation", "unresolved_conversation", "failed"},
		{"draft", "draft", "failed"},
	} {
		t.Run(change.name, func(t *testing.T) {
			ctx := mergeExecutionContext(t)
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
			t.Cleanup(test.MockVariableValue(&setting.Repository.PullRequest.WorkInProgressPrefixes, []string{"WIP:"}))
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			require.NoError(t, pr.LoadBaseRepo(ctx))
			current, cancel, err := prepareMergeGateGit(ctx, pr)
			require.NoError(t, err)
			defer cancel()
			scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: pr.BaseRepoID}
			var mutate func(context.Context) error
			switch change.name {
			case "status", "feature":
				grant := &authz_model.FeatureGrant{ScopeType: scope.Type, ScopeID: scope.ID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureEnabled, Revision: 1, ConfigJSON: `{"check_contexts":["security/fingerprint"]}`}
				if change.name == "status" {
					grant.State = authz.FeatureRequired
				}
				require.NoError(t, db.Insert(ctx, grant))
				if change.name == "status" {
					status := &git_model.CommitStatus{RepoID: pr.BaseRepoID, SHA: current.HeadSHA, Context: "security/fingerprint", ContextHash: "fingerprint", State: commitstatus.CommitStatusSuccess, Index: 1, CreatorID: actor.ID}
					require.NoError(t, db.Insert(ctx, status))
					mutate = func(ctx context.Context) error {
						_, err := db.GetEngine(ctx).ID(status.ID).Cols("state").Update(&git_model.CommitStatus{State: commitstatus.CommitStatusFailure})
						return err
					}
				} else {
					mutate = func(ctx context.Context) error {
						_, err := authz_service.PutFeatureGrant(ctx, actor, scope, authz.FeatureGitleaksScan, authz_service.FeatureGrantInput{State: authz.FeatureRequired, Config: []byte(grant.ConfigJSON), ExpectedRevision: 1})
						return err
					}
				}
			case "path_rule", "role_binding", "approval":
				role, err := authz_service.CreateRole(ctx, actor, scope, authz_service.CreateRoleInput{Name: "Concurrent gate reviewer"})
				require.NoError(t, err)
				config := []byte(fmt.Sprintf(`{"path_pattern":"**","required_role_id":%d}`, role.Definition.ID))
				if change.name == "path_rule" {
					mutate = func(ctx context.Context) error {
						_, err := authz_service.PutProtectedPathRule(ctx, actor, scope, 0, authz_service.ProtectedPathRuleInput{Config: config})
						return err
					}
				} else {
					_, err := authz_service.PutProtectedPathRule(ctx, actor, scope, 0, authz_service.ProtectedPathRuleInput{Config: config})
					require.NoError(t, err)
					binding, _, err := authz_service.PutBinding(ctx, actor, scope, authz_service.BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: role.Definition.ID})
					require.NoError(t, err)
					approval := &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 4, Type: issues_model.ReviewTypeApprove, CommitID: current.HeadSHA}
					require.NoError(t, db.Insert(ctx, approval))
					if change.name == "role_binding" {
						mutate = func(ctx context.Context) error { return authz_service.DeleteBinding(ctx, actor, scope, binding.ID) }
					} else {
						mutate = func(ctx context.Context) error {
							_, err := db.GetEngine(ctx).ID(approval.ID).Cols("dismissed").Update(&issues_model.Review{Dismissed: true})
							return err
						}
					}
				}
			case "conversation":
				review := &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 4, Type: issues_model.ReviewTypeComment}
				require.NoError(t, db.Insert(ctx, review))
				thread := &issues_model.Comment{IssueID: pr.IssueID, ReviewID: review.ID, Type: issues_model.CommentTypeCode, TreePath: "file.go", Line: 1}
				require.NoError(t, db.Insert(ctx, thread))
				require.NoError(t, ResolveReviewConversation(ctx, thread, actor, true))
				mutate = func(ctx context.Context) error { return ResolveReviewConversation(ctx, thread, actor, false) }
			case "draft":
				mutate = func(ctx context.Context) error {
					_, err := db.GetEngine(ctx).ID(pr.IssueID).Cols("name").Update(&issues_model.Issue{Title: "WIP: changed after snapshot"})
					return err
				}
			}
			bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			firstRead := make(chan struct{})
			changed := make(chan error, 1)
			finished := make(chan struct{})
			defer func() { cancel(); <-finished }()
			go func() {
				defer close(finished)
				select {
				case <-firstRead:
					changed <- mutate(bounded)
				case <-bounded.Done():
					changed <- bounded.Err()
				}
			}()
			reads := 0
			firstHash := ""
			evaluation, err := collectStableMergeGateEvaluation(bounded, func(ctx context.Context) (mergeGateEvaluation, error) {
				reads++
				result, err := collectMergeGateEvaluation(ctx, pr, actor, repo_model.MergeStyleMerge, "enforce", "admission", "api", authz_service.CredentialCeiling{Read: true, Write: true}, authz.MergeGateBypass{}, current, current.HeadSHA)
				if err == nil && reads == 1 {
					require.Equal(t, "allow", result.Result.AdmissionDecision)
					firstHash = result.Hash
					close(firstRead)
					select {
					case err = <-changed:
					case <-bounded.Done():
						err = bounded.Err()
					}
				}
				return result, err
			})
			require.NoError(t, err)
			require.Equal(t, "deny", evaluation.Result.AdmissionDecision)
			require.Equal(t, 3, reads)
			require.NotEqual(t, firstHash, evaluation.Hash)
			found := false
			for _, fact := range evaluation.Result.BlockingReasons {
				found = found || fact.Code == change.code && fact.State == change.state
			}
			require.True(t, found, change.code)
			require.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
			base, err := git.GetFullCommitID(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
			require.NoError(t, err)
			require.Equal(t, current.BaseSHA, base)
			unittest.AssertCount(t, &authz_model.MergeGateEvaluation{PullID: pr.ID}, 0)
		})
	}
}

func TestMergeGateMandatoryRejectionLeavesEvidence(t *testing.T) {
	for _, inactive := range []bool{false, true} {
		t.Run(strconv.FormatBool(inactive), func(t *testing.T) {
			ctx := mergeExecutionContext(t)
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			require.NoError(t, pr.LoadBaseRepo(ctx))
			style := repo_model.MergeStyle("not-allowed")
			code := "merge_style_denied"
			if inactive {
				style = repo_model.MergeStyleMerge
				code = "actor_invalid"
				_, err := db.GetEngine(ctx).ID(actor.ID).Cols("is_active").Update(&user_model.User{IsActive: false})
				require.NoError(t, err)
			}
			ctx, _ = authz_service.WithObservationContext(ctx, authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
			require.Error(t, Merge(ctx, pr, actor, style, "", "", false))
			record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID})
			require.Contains(t, record.ReasonsJSON, code)
			require.Equal(t, "not_started", record.ExecutionState)
			require.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
		})
	}
}

func TestMergeGateUnknownManualPusherLeavesHonestEvidence(t *testing.T) {
	ctx := mergeExecutionContext(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(ctx))
	prUnit, err := pr.BaseRepo.GetUnit(ctx, unit.TypePullRequests)
	require.NoError(t, err)
	prUnit.PullRequestsConfig().AutodetectManualMerge = true
	require.NoError(t, repo_model.UpdateRepoUnitConfig(ctx, prUnit))
	head, err := git.GetFullCommitID(ctx, pr.BaseRepo, pr.GetGitHeadRefName())
	require.NoError(t, err)
	before, err := git.GetFullCommitID(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
	require.NoError(t, err)
	require.NoError(t, gitcmd.NewCommand("update-ref").AddDynamicArguments(git.BranchPrefix+pr.BaseBranch, head, before).WithRepo(pr.BaseRepo).Run(ctx))
	require.False(t, manuallyMerged(ctx, pr))
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "manual_recognition"})
	require.Zero(t, record.ActorID)
	require.Equal(t, "error", record.CandidateDecision)
	require.Contains(t, record.ReasonsJSON, "paths_incomplete")
	require.Contains(t, record.SnapshotJSON, `"git_already_present":true`)
	require.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
	after, err := git.GetFullCommitID(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
	require.NoError(t, err)
	require.Equal(t, head, after)
}

func TestMergeGateRequestPrecheckAggregatesAndKeepsEvidence(t *testing.T) {
	ctx := mergeExecutionContext(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(ctx))
	_, err := db.GetEngine(ctx).ID(pr.IssueID).Cols("name").Update(&issues_model.Issue{Title: "WIP: request"})
	require.NoError(t, err)
	require.NoError(t, db.Insert(ctx, &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["security/request"]}`}))
	permission, err := access_model.GetDoerRepoPermission(ctx, pr.BaseRepo, actor)
	require.NoError(t, err)
	ctx, _ = authz_service.WithObservationContext(ctx, authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, CheckPullMergeableForRequest(ctx, actor, &permission, pr, MergeCheckTypeGeneral, repo_model.MergeStyleMerge, MergeOptions{}, ""), &rejection)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID})
	require.Contains(t, record.ReasonsJSON, "draft")
	require.Contains(t, record.ReasonsJSON, "required_check")
	require.Equal(t, "not_started", record.ExecutionState)
	_, err = db.GetEngine(ctx).ID(pr.IssueID).Cols("name").Update(&issues_model.Issue{Title: "ready request"})
	require.NoError(t, err)
	pr = unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
	require.NoError(t, CheckPullMergeableForRequest(ctx, actor, &permission, pr, MergeCheckTypeAuto, repo_model.MergeStyleMerge, MergeOptions{}, ""))
	unittest.AssertCount(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "schedule"}, 0)
}

func TestMergeGateRequestPrecheckRequiresActor(t *testing.T) {
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	for _, input := range []struct {
		actor *user_model.User
		pr    *issues_model.PullRequest
	}{
		{nil, &issues_model.PullRequest{ID: 2}},
		{&user_model.User{}, &issues_model.PullRequest{ID: 2}},
		{&user_model.User{ID: 2}, nil},
	} {
		var denied *authz_service.ExecutionError
		require.ErrorAs(t, CheckPullMergeableForRequest(t.Context(), input.actor, nil, input.pr, MergeCheckTypeGeneral, repo_model.MergeStyleMerge, MergeOptions{}, ""), &denied)
		require.Equal(t, 403, denied.Status)
	}
}

func TestMergeGateDisabledEntryPointsDoNotReadStorage(t *testing.T) {
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{}))
	ctx := t.Context()
	record, err := admitMergeGate(ctx, nil, nil, "", MergeOptions{}, false, nil, "", false)
	require.NoError(t, err)
	require.Nil(t, record)
	require.NoError(t, RecordManualMergePush(ctx, nil, nil, "", "", "", "", authz_service.CredentialCeiling{}))
	require.NoError(t, ReconcileMergeGateEvaluations(ctx))
	require.NoError(t, authz_service.CancelMergeGateSchedulesTx(ctx, 0))
	require.NoError(t, authz_service.RecordMergeGateMarkerTx(ctx, 0, 0, 0, "", ""))
}

func TestMergeGateQueueCredentialReadErrorIsNotKnownDenial(t *testing.T) {
	ctx := mergeExecutionContext(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(ctx))
	token := &auth_model.AccessToken{UID: actor.ID, Name: "invalid-scope", Scope: auth_model.AccessTokenScopeWriteRepository}
	require.NoError(t, auth_model.NewAccessToken(ctx, token))
	_, err := db.GetEngine(ctx).ID(token.ID).Cols("scope").Update(&auth_model.AccessToken{Scope: "unknown:scope"})
	require.NoError(t, err)
	ctx, _ = authz_service.WithObservationContext(ctx, authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true, Reference: fmt.Sprintf("access-token:%d", token.ID)}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, PersistDeniedMergeGateSchedule(authz_service.WithOperation(ctx), actor, pr, repo_model.MergeStyleMerge, MergeOptions{}), &rejection)
	require.Equal(t, 503, rejection.Status)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "schedule"})
	require.Equal(t, "error", record.CandidateDecision)
	require.Contains(t, record.ReasonsJSON, "facts_read_failed")
	current, cancel, err := prepareMergeGateGit(ctx, pr)
	require.NoError(t, err)
	defer cancel()
	_, err = admitMergeGate(authz_service.WithOperation(ctx), pr, actor, repo_model.MergeStyleMerge, MergeOptions{}, false, current, current.HeadSHA, true)
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, 503, rejection.Status)
	require.Equal(t, "merge_gate_unavailable", rejection.Reason)
	admission := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "admission"})
	require.Equal(t, "error", admission.CandidateDecision)
	require.Equal(t, "not_started", admission.ExecutionState)
	require.Contains(t, admission.ReasonsJSON, "facts_read_failed")
	require.NotContains(t, admission.ReasonsJSON, "credential_denied")
	require.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
}

type mergeGateCredentialAbortedTransaction struct {
	enabled, aborted, fired bool
}

func (h *mergeGateCredentialAbortedTransaction) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if !h.enabled {
		return c.Ctx, nil
	}
	if strings.HasPrefix(c.SQL, "ROLLBACK TO SAVEPOINT") {
		h.aborted = false
		return c.Ctx, nil
	}
	if h.aborted {
		return c.Ctx, errors.New("simulated PostgreSQL transaction is aborted")
	}
	if !h.fired && strings.HasPrefix(c.SQL, "SELECT") && strings.Contains(c.SQL, "access_token") {
		h.aborted, h.fired = true, true
		return c.Ctx, errors.New("simulated PostgreSQL credential SQL failure")
	}
	return c.Ctx, nil
}

func (*mergeGateCredentialAbortedTransaction) AfterProcess(*contexts.ContextHook) error { return nil }

func TestMergeGateCredentialSQLFailureKeepsIndependentEvidence(t *testing.T) {
	ctx := mergeExecutionContext(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(ctx))
	token := &auth_model.AccessToken{UID: actor.ID, Name: "sql-failure", Scope: auth_model.AccessTokenScopeWriteRepository}
	require.NoError(t, auth_model.NewAccessToken(ctx, token))
	ctx, _ = authz_service.WithObservationContext(ctx, authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true, Reference: fmt.Sprintf("access-token:%d", token.ID)}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
	current, cancel, err := prepareMergeGateGit(ctx, pr)
	require.NoError(t, err)
	defer cancel()
	hook := &mergeGateCredentialAbortedTransaction{enabled: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	t.Cleanup(func() { hook.enabled = false })
	record, err := admitMergeGate(authz_service.WithOperation(ctx), pr, actor, repo_model.MergeStyleMerge, MergeOptions{}, false, current, current.HeadSHA, true)
	var rejected *authz_service.ExecutionError
	require.ErrorAs(t, err, &rejected)
	require.Equal(t, "merge_gate_unavailable", rejected.Reason)
	require.Equal(t, 503, rejected.Status)
	require.True(t, hook.fired)
	require.False(t, hook.aborted)
	require.Equal(t, "error", record.AdmissionDecision)
	require.Equal(t, "not_started", record.ExecutionState)
	require.Contains(t, record.ReasonsJSON, "facts_read_failed")
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateEvaluation}, 1)
	hook.fired = false
	require.ErrorAs(t, PersistDeniedMergeGateSchedule(authz_service.WithOperation(ctx), actor, pr, repo_model.MergeStyleMerge, MergeOptions{}), &rejected)
	require.Equal(t, "merge_gate_unavailable", rejected.Reason)
	require.True(t, hook.fired)
	require.False(t, hook.aborted)
	schedule := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "schedule"})
	require.Equal(t, "error", schedule.CandidateDecision)
	require.Equal(t, "not_admitted", schedule.AdmissionDecision)
	require.Contains(t, schedule.ReasonsJSON, "facts_read_failed")
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateEvaluation}, 2)
}

type mergeGateSQLiteCredentialChangeDuringRead struct {
	enabled, changed bool
	reads            int
	tokenID          int64
	readOnly         bool
	sqlContext       context.Context
}

func (h *mergeGateSQLiteCredentialChangeDuringRead) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if !h.enabled {
		return c.Ctx, nil
	}
	if strings.HasPrefix(c.SQL, "SELECT") && strings.Contains(c.SQL, "access_token") && db.InTransaction(c.Ctx) {
		h.sqlContext = c.Ctx
	}
	if strings.HasPrefix(c.SQL, "SELECT") && strings.Contains(c.SQL, "pull_request") {
		h.reads++
		if h.reads == 2 && !h.changed {
			if h.sqlContext == nil {
				return c.Ctx, errors.New("SQLite test transaction context unavailable")
			}
			h.changed = true
			if h.readOnly {
				_, err := db.Exec(h.sqlContext, "UPDATE access_token SET scope=? WHERE id=?", auth_model.AccessTokenScopeReadRepository, h.tokenID)
				return c.Ctx, err
			}
			_, err := db.Exec(h.sqlContext, "DELETE FROM access_token WHERE id=?", h.tokenID)
			return c.Ctx, err
		}
	}
	return c.Ctx, nil
}

func (*mergeGateSQLiteCredentialChangeDuringRead) AfterProcess(*contexts.ContextHook) error {
	return nil
}

func TestMergeGateAdmissionRechecksCredentialBeforeSealing(t *testing.T) {
	for _, readOnly := range []bool{false, true} {
		t.Run(strconv.FormatBool(readOnly), func(t *testing.T) {
			ctx := mergeExecutionContext(t)
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			require.NoError(t, pr.LoadBaseRepo(ctx))
			token := &auth_model.AccessToken{UID: actor.ID, Name: "admission-credential-change", Scope: auth_model.AccessTokenScopeWriteRepository}
			require.NoError(t, auth_model.NewAccessToken(ctx, token))
			ctx, _ = authz_service.WithObservationContext(ctx, authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true, Reference: fmt.Sprintf("access-token:%d", token.ID)}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
			current, cancel, err := prepareMergeGateGit(ctx, pr)
			require.NoError(t, err)
			defer cancel()
			hook := &mergeGateSQLiteCredentialChangeDuringRead{enabled: true, tokenID: token.ID, readOnly: readOnly}
			db.GetXORMEngineForTesting().AddHook(hook)
			t.Cleanup(func() { hook.enabled = false })
			record, err := admitMergeGate(authz_service.WithOperation(ctx), pr, actor, repo_model.MergeStyleMerge, MergeOptions{}, false, current, current.HeadSHA, true)
			var rejected *authz_service.ExecutionError
			require.True(t, hook.changed)
			require.ErrorAs(t, err, &rejected)
			require.Equal(t, 403, rejected.Status)
			require.Equal(t, "deny", record.AdmissionDecision)
			require.Equal(t, "not_started", record.ExecutionState)
			require.Contains(t, record.ReasonsJSON, "credential_denied")
			require.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
			base, err := git.GetFullCommitID(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
			require.NoError(t, err)
			require.Equal(t, current.BaseSHA, base)
			unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateEvaluation}, 1)
		})
	}
}

func TestMergeGateNativeEvidenceChangesWithoutDecisionChange(t *testing.T) {
	ctx := mergeExecutionContext(t)
	t.Cleanup(test.MockVariableValue(&setting.API.MaxResponseItems, 1))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(ctx))
	current, cancel, err := prepareMergeGateGit(ctx, pr)
	require.NoError(t, err)
	defer cancel()
	pb := &git_model.ProtectedBranch{RepoID: pr.BaseRepoID, RuleName: pr.BaseBranch, CanPush: true, RequiredApprovals: 1}
	require.NoError(t, db.Insert(ctx, pb))
	review := &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 4, Type: issues_model.ReviewTypeApprove, Official: true, CommitID: current.HeadSHA, Content: "private-review-text"}
	require.NoError(t, db.Insert(ctx, review))
	collect := func() mergeGateEvaluation {
		t.Helper()
		result, err := collectMergeGateEvaluation(ctx, pr, actor, repo_model.MergeStyleMerge, "enforce", "admission", "api", authz_service.CredentialCeiling{Read: true, Write: true}, authz.MergeGateBypass{}, current, current.HeadSHA)
		require.NoError(t, err)
		require.Equal(t, "allow", result.Result.AdmissionDecision)
		require.NotContains(t, result.JSON, "private-review-text")
		return result
	}
	before := collect()
	_, err = db.GetEngine(ctx).ID(pb.ID).Cols("required_approvals").Update(&git_model.ProtectedBranch{RequiredApprovals: 0})
	require.NoError(t, err)
	afterPolicy := collect()
	require.NotEqual(t, before.Hash, afterPolicy.Hash, "different native policy cannot share the sealed fingerprint")
	review.ID = 0
	require.NoError(t, db.Insert(ctx, review))
	afterReview := collect()
	require.NotEqual(t, afterPolicy.Hash, afterReview.Hash, "new native approval evidence cannot disappear behind the same boolean result")
	var existing []*issues_model.Review
	require.NoError(t, db.GetEngine(ctx).Where("issue_id = ?", pr.IssueID).Find(&existing))
	reviews := make([]*issues_model.Review, authz.MaxMergeGateFacts+1-len(existing))
	for i := range reviews {
		reviews[i] = &issues_model.Review{IssueID: pr.IssueID, ReviewerTeamID: 1, Type: issues_model.ReviewTypeRequest}
	}
	require.NoError(t, db.Insert(ctx, reviews))
	_, _, err = collectMergeGateNativeState(ctx, pr, actor, repo_model.MergeStyleMerge, "admission", current)
	require.EqualError(t, err, "merge_gate_native_reviews_limit_exceeded")
}
