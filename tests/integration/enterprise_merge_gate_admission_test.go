// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/commitstatus"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"
	pull_service "gitea.dev/services/pull"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

type mergeGateAdmissionBarrierKey struct{}

type mergeGateAdmissionBarrier struct {
	enabled       atomic.Bool
	reads         atomic.Int32
	locks         atomic.Int32
	policy        bool
	held, release chan struct{}
	once          sync.Once
}

func (h *mergeGateAdmissionBarrier) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if !h.enabled.Load() || c.Ctx.Value(mergeGateAdmissionBarrierKey{}) != h {
		return c.Ctx, nil
	}
	stop := false
	if h.policy && strings.HasPrefix(c.SQL, "UPDATE") && strings.Contains(c.SQL, "enterprise_feature_definition") {
		stop = h.locks.Add(1) == 2
	}
	if !h.policy && strings.HasPrefix(c.SQL, "SELECT") && strings.Contains(c.SQL, "access_token") {
		stop = h.reads.Add(1) == 4
	}
	if stop {
		h.once.Do(func() {
			close(h.held)
			select {
			case <-h.release:
			case <-c.Ctx.Done():
			}
		})
	}
	return c.Ctx, nil
}

func (*mergeGateAdmissionBarrier) AfterProcess(*contexts.ContextHook) error { return nil }

func TestEnterpriseMergeGatePGAdmissionConsumesConcurrentChanges(t *testing.T) {
	if !setting.Database.Type.IsPostgreSQL() {
		t.Skip("PostgreSQL concurrent committed facts")
	}
	for _, change := range []struct {
		name, code string
		status     int
		policy     bool
	}{
		{"status", "required_check", http.StatusConflict, false},
		{"credential_revocation", "credential_denied", http.StatusForbidden, false},
		{"credential_scope", "credential_denied", http.StatusForbidden, false},
		{"approval", "sensitive_path_approval", http.StatusConflict, false},
		{"conversation", "unresolved_conversation", http.StatusConflict, false},
		{"draft", "draft", http.StatusConflict, false},
		{"head", "state_changed", http.StatusConflict, false},
		{"base", "state_changed", http.StatusConflict, false},
		{"feature", "required_check", http.StatusConflict, true},
		{"path_rule", "sensitive_path_approval", http.StatusConflict, true},
		{"role_binding", "sensitive_path_approval", http.StatusConflict, true},
	} {
		t.Run(change.name, func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, _ *url.URL) {
				featureTestMode(t)
				setting.EnterpriseAuthz.Enforce = true
				t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
				t.Cleanup(test.MockVariableValue(&setting.Repository.PullRequest.WorkInProgressPrefixes, []string{"WIP:"}))
				pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
				actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
				require.NoError(t, pr.LoadBaseRepo(t.Context()))
				base, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
				require.NoError(t, err)
				head, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.HeadBranch)
				require.NoError(t, err)
				token := &auth_model.AccessToken{UID: actor.ID, Name: "concurrent-gate", Scope: auth_model.AccessTokenScopeWriteRepository}
				require.NoError(t, auth_model.NewAccessToken(t.Context(), token))
				scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: pr.BaseRepoID}
				var mutate func(context.Context) error
				switch change.name {
				case "status", "feature":
					grant := &authz_model.FeatureGrant{ScopeType: scope.Type, ScopeID: scope.ID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureEnabled, Revision: 1, ConfigJSON: `{"check_contexts":["security/concurrent"]}`}
					if change.name == "status" {
						grant.State = authz.FeatureRequired
					}
					require.NoError(t, db.Insert(t.Context(), grant))
					if change.name == "status" {
						status := &git_model.CommitStatus{RepoID: scope.ID, SHA: head, Context: "security/concurrent", ContextHash: "concurrent", State: commitstatus.CommitStatusSuccess, Index: 1, CreatorID: actor.ID}
						require.NoError(t, db.Insert(t.Context(), status))
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
					role, err := authz_service.CreateRole(t.Context(), actor, scope, authz_service.CreateRoleInput{Name: "Admission reviewer"})
					require.NoError(t, err)
					config := []byte(fmt.Sprintf(`{"path_pattern":"**","required_role_id":%d}`, role.Definition.ID))
					if change.name == "path_rule" {
						mutate = func(ctx context.Context) error {
							_, err := authz_service.PutProtectedPathRule(ctx, actor, scope, 0, authz_service.ProtectedPathRuleInput{Config: config})
							return err
						}
					} else {
						_, err := authz_service.PutProtectedPathRule(t.Context(), actor, scope, 0, authz_service.ProtectedPathRuleInput{Config: config})
						require.NoError(t, err)
						binding, _, err := authz_service.PutBinding(t.Context(), actor, scope, authz_service.BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: role.Definition.ID})
						require.NoError(t, err)
						approval := &issues_model.Review{IssueID: pr.IssueID, ReviewerID: 4, Type: issues_model.ReviewTypeApprove, CommitID: head}
						require.NoError(t, db.Insert(t.Context(), approval))
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
					require.NoError(t, db.Insert(t.Context(), review))
					root := &issues_model.Comment{IssueID: pr.IssueID, ReviewID: review.ID, Type: issues_model.CommentTypeCode, TreePath: "concurrent.go", Line: 1, ResolveDoerID: actor.ID}
					require.NoError(t, db.Insert(t.Context(), root))
					mutate = func(ctx context.Context) error {
						return pull_service.ResolveReviewConversation(ctx, root, actor, false)
					}
				case "draft":
					mutate = func(ctx context.Context) error {
						_, err := db.GetEngine(ctx).ID(pr.IssueID).Cols("name").Update(&issues_model.Issue{Title: "WIP: concurrent change"})
						return err
					}
				case "credential_revocation":
					mutate = func(ctx context.Context) error {
						_, err := db.GetEngine(ctx).ID(token.ID).Delete(new(auth_model.AccessToken))
						return err
					}
				case "credential_scope":
					mutate = func(ctx context.Context) error {
						_, err := db.GetEngine(ctx).ID(token.ID).Cols("scope").Update(&auth_model.AccessToken{Scope: auth_model.AccessTokenScopeReadRepository})
						return err
					}
				case "head":
					mutate = func(ctx context.Context) error {
						return git.UpdateRef(ctx, pr.BaseRepo, git.BranchPrefix+pr.HeadBranch, base)
					}
				case "base":
					mutate = func(ctx context.Context) error {
						return git.UpdateRef(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch, head)
					}
				}
				bounded, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				defer cancel()
				hook := &mergeGateAdmissionBarrier{policy: change.policy, held: make(chan struct{}), release: make(chan struct{})}
				hook.enabled.Store(true)
				db.GetXORMEngineForTesting().AddHook(hook)
				var release sync.Once
				done := make(chan error, 1)
				finished := make(chan struct{})
				defer func() { release.Do(func() { close(hook.release) }); cancel(); <-finished; hook.enabled.Store(false) }()
				ctx, _ := authz_service.WithObservationContext(context.WithValue(bounded, mergeGateAdmissionBarrierKey{}, hook), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true, Reference: fmt.Sprintf("access-token:%d", token.ID)}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
				go func() {
					defer close(finished)
					done <- pull_service.Merge(ctx, pr, actor, repo_model.MergeStyleMerge, "", "concurrent admission", false)
				}()
				select {
				case <-hook.held:
				case err := <-done:
					t.Fatalf("merge did not reach the admission barrier: %v", err)
				case <-bounded.Done():
					t.Fatal(bounded.Err())
				}
				require.NoError(t, mutate(bounded))
				release.Do(func() { close(hook.release) })
				var rejected *authz_service.ExecutionError
				select {
				case err := <-done:
					require.ErrorAs(t, err, &rejected)
				case <-bounded.Done():
					t.Fatal(bounded.Err())
				}
				require.Equal(t, change.status, rejected.Status)
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID})
				require.Equal(t, "not_started", record.ExecutionState)
				require.Contains(t, record.SnapshotJSON, `"result_sha":`, "the barrier must reach the final gate after staging the merge commit")
				require.Contains(t, record.ReasonsJSON, change.code)
				require.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
				if change.name == "head" {
					head = base
				}
				if change.name == "base" {
					base = head
				}
				actualBase, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
				require.NoError(t, err)
				require.Equal(t, base, actualBase)
				actualHead, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.HeadBranch)
				require.NoError(t, err)
				require.Equal(t, head, actualHead)
			})
		})
	}
}
