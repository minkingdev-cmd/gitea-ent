// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"
	"gitea.dev/services/notify"
	pull_service "gitea.dev/services/pull"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

func TestEnterpriseMergeGateActualMergeConsumesStatus(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		featureTestMode(t)
		setting.EnterpriseAuthz.Enforce = true
		setting.EnterpriseAuthz.FailClosedOnError = false
		t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
		actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		require.NoError(t, pr.LoadBaseRepo(t.Context()))
		require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["security/gate-write"]}`}))
		repo, err := git.OpenRepository(t.Context(), pr.BaseRepo)
		require.NoError(t, err)
		defer repo.Close()
		before, err := repo.GetRefCommitID(t.Context(), git.BranchPrefix+pr.BaseBranch)
		require.NoError(t, err)
		head, err := repo.GetRefCommitID(t.Context(), git.BranchPrefix+pr.HeadBranch)
		require.NoError(t, err)
		token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteRepository)
		accessToken, err := auth_model.GetAccessTokenBySHA(t.Context(), token)
		require.NoError(t, err)
		attempt := func() error {
			ctx, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true, Reference: fmt.Sprintf("access-token:%d", accessToken.ID)}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
			return pull_service.Merge(ctx, pr, actor, repo_model.MergeStyleMerge, head, "merge gate integration", false)
		}
		var rejected *authz_service.ExecutionError
		require.ErrorAs(t, attempt(), &rejected)
		require.Equal(t, http.StatusConflict, rejected.Status)
		require.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
		after, err := repo.GetRefCommitID(t.Context(), git.BranchPrefix+pr.BaseBranch)
		require.NoError(t, err)
		require.Equal(t, before, after)
		unittest.AssertCount(t, &git_model.CommitStatus{RepoID: pr.BaseRepoID, Context: "security/gate-write"}, 0)
		readonly := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeReadRepository)
		statusURL := "/api/v1/repos/user2/repo1/statuses/" + head
		MakeRequest(t, NewRequestWithJSON(t, "POST", statusURL, map[string]any{"context": "security/gate-write", "state": "success"}).AddTokenAuth(readonly), http.StatusForbidden)
		MakeRequest(t, NewRequestWithJSON(t, "POST", statusURL, map[string]any{"context": "security/gate-write", "state": "skipped"}).AddTokenAuth(token), http.StatusCreated)
		require.ErrorAs(t, attempt(), &rejected)
		require.Equal(t, http.StatusConflict, rejected.Status)
		require.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
		after, err = repo.GetRefCommitID(t.Context(), git.BranchPrefix+pr.BaseBranch)
		require.NoError(t, err)
		require.Equal(t, before, after)
		MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/statuses/"+head, map[string]any{"context": "security/gate-write", "state": "success", "description": "private result detail", "target_url": "https://private.example.invalid/check"}).AddTokenAuth(token), http.StatusCreated)
		require.NoError(t, attempt())
		current := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
		require.True(t, current.HasMerged)
		record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, AdmissionDecision: "allow"})
		require.Equal(t, "succeeded", record.ExecutionState)
		require.Equal(t, current.MergedCommitID, record.MergedSHA)
		require.Equal(t, head, record.HeadSHA)
		require.Equal(t, before, record.BaseSHA)
		require.NotContains(t, record.SnapshotJSON, "private result detail")
		require.NotContains(t, record.SnapshotJSON, "private.example.invalid")
		require.NotContains(t, record.SnapshotJSON, token)
		unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateEvaluation}, 3)
		unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateExecution}, 1)
	})
}

func TestEnterpriseMergeGateActualAuditFailures(t *testing.T) {
	for _, action := range []audit_model.Action{audit_model.EnterpriseMergeGateEvaluation, audit_model.EnterpriseMergeGateExecution} {
		t.Run(string(action), func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, _ *url.URL) {
				featureTestMode(t)
				setting.EnterpriseAuthz.Enforce = true
				setting.EnterpriseAuthz.FailClosedOnError = false
				t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
				pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
				actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
				require.NoError(t, pr.LoadBaseRepo(t.Context()))
				repo, err := git.OpenRepository(t.Context(), pr.BaseRepo)
				require.NoError(t, err)
				defer repo.Close()
				before, err := repo.GetRefCommitID(t.Context(), git.BranchPrefix+pr.BaseBranch)
				require.NoError(t, err)
				headBefore, err := repo.GetRefCommitID(t.Context(), git.BranchPrefix+pr.HeadBranch)
				require.NoError(t, err)
				hook := &mergeGateAuditFault{action: action}
				hook.enabled.Store(true)
				db.GetXORMEngineForTesting().AddHook(hook)
				t.Cleanup(func() { hook.enabled.Store(false) })
				counter := &mergeGateMergeNotificationCounter{pullID: pr.ID}
				counter.enabled.Store(true)
				notify.RegisterNotifier(counter)
				t.Cleanup(func() { counter.enabled.Store(false) })
				ctx, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
				err = pull_service.Merge(ctx, pr, actor, repo_model.MergeStyleMerge, "", "audit fault integration", false)
				var failure *authz_service.ExecutionError
				require.ErrorAs(t, err, &failure)
				require.Equal(t, http.StatusServiceUnavailable, failure.Status)
				require.True(t, hook.fired.Load())
				current := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
				after, err := repo.GetRefCommitID(t.Context(), git.BranchPrefix+pr.BaseBranch)
				require.NoError(t, err)
				if action == audit_model.EnterpriseMergeGateEvaluation {
					require.False(t, current.HasMerged)
					require.Equal(t, before, after)
					unittest.AssertCount(t, &authz_model.MergeGateEvaluation{}, 0)
				} else {
					require.True(t, current.HasMerged)
					require.NotEqual(t, before, after)
					record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID})
					require.Equal(t, "started", record.ExecutionState)
					require.Empty(t, record.MergedSHA)
					require.Zero(t, record.TerminalUnix)
					unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateExecution}, 0)
				}
				headAfter, err := repo.GetRefCommitID(t.Context(), git.BranchPrefix+pr.HeadBranch)
				require.NoError(t, err)
				require.Equal(t, headBefore, headAfter)
				require.Zero(t, counter.count.Load())
			})
		})
	}
}

type mergeGateAuditFault struct {
	action         audit_model.Action
	enabled, fired atomic.Bool
}

func (h *mergeGateAuditFault) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.enabled.Load() && strings.HasPrefix(c.SQL, "INSERT INTO") && strings.Contains(c.SQL, "audit_event") {
		for _, arg := range c.Args {
			if fmt.Sprint(arg) == string(h.action) {
				h.fired.Store(true)
				return c.Ctx, errors.New("injected_merge_gate_audit_failure")
			}
		}
	}
	return c.Ctx, nil
}

func (*mergeGateAuditFault) AfterProcess(*contexts.ContextHook) error { return nil }

type mergeGateMergeNotificationCounter struct {
	notify.NullNotifier
	pullID  int64
	enabled atomic.Bool
	count   atomic.Int32
}

func (n *mergeGateMergeNotificationCounter) MergePullRequest(_ context.Context, _ *user_model.User, pr *issues_model.PullRequest) {
	if n.enabled.Load() && pr.ID == n.pullID {
		n.count.Add(1)
	}
}

func (n *mergeGateMergeNotificationCounter) AutoMergePullRequest(ctx context.Context, actor *user_model.User, pr *issues_model.PullRequest) {
	n.MergePullRequest(ctx, actor, pr)
}

func TestEnterpriseMergeGateActualShadowDoesNotBlock(t *testing.T) {
	for _, actionEnforce := range []bool{false, true} {
		t.Run(fmt.Sprintf("action_enforce=%t", actionEnforce), func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, _ *url.URL) {
				featureTestMode(t)
				setting.EnterpriseAuthz.Enforce = actionEnforce
				t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
				pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
				actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
				require.NoError(t, pr.LoadBaseRepo(t.Context()))
				require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["security/shadow"]}`}))
				ctx, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
				require.NoError(t, pull_service.Merge(ctx, pr, actor, repo_model.MergeStyleMerge, "", "shadow integration", false))
				current := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
				require.True(t, current.HasMerged)
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID})
				require.Equal(t, "deny", record.CandidateDecision)
				require.Equal(t, "not_enforced", record.AdmissionDecision)
				require.Equal(t, "succeeded", record.ExecutionState)
				require.Equal(t, current.MergedCommitID, record.MergedSHA)
			})
		})
	}
}

func TestEnterpriseMergeGateForceRequestFields(t *testing.T) {
	for _, source := range []string{"api", "web"} {
		t.Run(source, func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, _ *url.URL) {
				featureTestMode(t)
				setting.EnterpriseAuthz.Enforce = true
				t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
				pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
				require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["security/force"]}`}))
				session := loginUser(t, "user2")
				token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
				request := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/merge", map[string]any{"do": "merge", "force_merge": true, "bypass_reason": " approved incident ", "bypass_categories": []string{"required_check"}}).AddTokenAuth(token)
				if source == "web" {
					request = NewRequestWithURLValues(t, "POST", "/user2/repo1/pulls/3/merge", url.Values{"do": {"merge"}, "force_merge": {"true"}, "bypass_reason": {" approved incident "}, "bypass_categories": {"required_check"}})
				}
				session.MakeRequest(t, request, http.StatusOK)
				require.True(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID})
				require.Equal(t, "bypass", record.AdmissionDecision)
				require.True(t, record.BypassRequested)
				require.True(t, record.BypassUsed)
				require.Equal(t, "approved incident", record.BypassReason)
				require.Equal(t, source, record.Source)
				require.Equal(t, "succeeded", record.ExecutionState)
				require.Contains(t, record.ReasonsJSON, "required_check")
			})
		})
	}
}

type mergeGateCredentialSQLFault struct {
	enabled, fired atomic.Bool
	serverError    atomic.Bool
}

func (h *mergeGateCredentialSQLFault) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.enabled.Load() && strings.HasPrefix(c.SQL, "SELECT") && strings.Contains(c.SQL, "access_token") && len(c.Args) > 0 && h.fired.CompareAndSwap(false, true) {
		c.Args[0] = "invalid-merge-gate-token-id"
	}
	return c.Ctx, nil
}

func (h *mergeGateCredentialSQLFault) AfterProcess(c *contexts.ContextHook) error {
	if h.enabled.Load() && c.Err != nil && strings.Contains(c.Err.Error(), "invalid input syntax") {
		h.serverError.Store(true)
	}
	return nil
}

func TestEnterpriseMergeGatePGCredentialSQLFailureEvidence(t *testing.T) {
	if !setting.Database.Type.IsPostgreSQL() {
		t.Skip("PostgreSQL server-side transaction abort")
	}
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		featureTestMode(t)
		setting.EnterpriseAuthz.Enforce = true
		t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
		actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		require.NoError(t, pr.LoadBaseRepo(t.Context()))
		token := &auth_model.AccessToken{UID: actor.ID, Name: "gate-sql-fault", Scope: auth_model.AccessTokenScopeWriteRepository}
		require.NoError(t, auth_model.NewAccessToken(t.Context(), token))
		ctx, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true, Reference: fmt.Sprintf("access-token:%d", token.ID)}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
		before, err := git.GetFullCommitID(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
		require.NoError(t, err)
		hook := &mergeGateCredentialSQLFault{}
		hook.enabled.Store(true)
		db.GetXORMEngineForTesting().AddHook(hook)
		t.Cleanup(func() { hook.enabled.Store(false) })
		var rejected *authz_service.ExecutionError
		require.ErrorAs(t, pull_service.Merge(ctx, pr, actor, repo_model.MergeStyleMerge, "", "credential SQL error", false), &rejected)
		require.True(t, hook.fired.Load())
		require.True(t, hook.serverError.Load())
		require.Equal(t, "merge_gate_unavailable", rejected.Reason)
		require.Equal(t, http.StatusServiceUnavailable, rejected.Status)
		record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "admission"})
		require.Equal(t, "error", record.CandidateDecision)
		require.Equal(t, "not_started", record.ExecutionState)
		require.Contains(t, record.ReasonsJSON, "facts_read_failed")
		hook.fired.Store(false)
		hook.serverError.Store(false)
		require.ErrorAs(t, pull_service.PersistDeniedMergeGateSchedule(authz_service.WithOperation(ctx), actor, pr, repo_model.MergeStyleMerge, pull_service.MergeOptions{}), &rejected)
		require.True(t, hook.fired.Load())
		require.True(t, hook.serverError.Load())
		require.Equal(t, "merge_gate_unavailable", rejected.Reason)
		schedule := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, Phase: "schedule"})
		require.Equal(t, "error", schedule.CandidateDecision)
		require.Equal(t, "not_admitted", schedule.AdmissionDecision)
		unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateEvaluation}, 2)
		require.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
		after, err := git.GetFullCommitID(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
		require.NoError(t, err)
		require.Equal(t, before, after)
	})
}
