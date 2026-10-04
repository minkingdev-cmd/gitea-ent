// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	pull_model "gitea.dev/models/pull"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/commitstatus"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/queue"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	commitstatus_service "gitea.dev/services/repository/commitstatus"

	"github.com/stretchr/testify/require"
)

func enableMergeEnforcement(t *testing.T) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
}

func TestEnterpriseAuthzMergeEnforceManualEvidenceFaults(t *testing.T) {
	for _, table := range []string{"enterprise_role_permission", "enterprise_authz_decision", "audit_event"} {
		for _, failClosed := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/closed=%t", table, failClosed), func(t *testing.T) {
				onGiteaRun(t, func(t *testing.T, _ *url.URL) {
					enableMergeEnforcement(t)
					setting.EnterpriseAuthz.FailClosedOnError = failClosed
					repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
					mergeEnforceRole(t, repo, 2, authz.MergePullRequest)
					prUnit, err := repo.GetUnit(t.Context(), unit.TypePullRequests)
					require.NoError(t, err)
					prUnit.PullRequestsConfig().AllowManualMerge = true
					require.NoError(t, repo_model.UpdateRepoUnitConfig(t.Context(), prUnit))
					old, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+"master")
					require.NoError(t, err)
					session := loginUser(t, "user2")
					token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
					_, err = db.Exec(t.Context(), "ALTER TABLE "+table+" RENAME TO merge_evidence_fault")
					require.NoError(t, err)
					t.Cleanup(func() {
						_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE merge_evidence_fault RENAME TO "+table)
						require.NoError(t, err)
					})
					status := 200
					if failClosed {
						status = 503
						webResponse := session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/pulls/3/merge", map[string]string{"do": "manually-merged", "merge_commit_id": old}), status)
						require.NotContains(t, webResponse.Body.String(), table)
					}
					response := session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/merge", map[string]any{"do": "manually-merged", "merge_commit_id": old}).AddTokenAuth(token), status)
					require.NotContains(t, response.Body.String(), table)
					pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
					require.Equal(t, !failClosed, pr.HasMerged)
					if table == "enterprise_role_permission" {
						row := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.MergePullRequest, RequestSource: "api"})
						require.Equal(t, !failClosed, row.ExecutionStarted)
						if failClosed {
							require.Equal(t, "error", row.AuthorizationDecision)
						} else {
							require.Equal(t, "fallback", row.AuthorizationDecision)
							require.Equal(t, "success", row.NativeOutcome)
						}
					}
				})
			})
		}
	}
}

func TestEnterpriseAuthzMergeEnforceQueuedModeRecheck(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		enableMergeEnforcement(t)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: 1, RuleName: "master", CanPush: true, EnableMergeWhitelist: true, MergeWhitelistUserIDs: []int64{4}, EnableStatusCheck: true, StatusCheckContexts: []string{"required-queue-check"}}))
		binding := mergeEnforceRole(t, repo, 4, authz.MergePullRequest)
		session := loginUser(t, "user4")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		endpoint := "/api/v1/repos/user2/repo1/pulls/3/merge"
		session.MakeRequest(t, NewRequestWithJSON(t, "POST", endpoint, map[string]any{"do": "merge", "merge_when_checks_succeed": true}).AddTokenAuth(token), 201)
		require.NoError(t, queue.GetManager().FlushAll(t.Context(), 0))
		unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: 2, DoerID: 4})
		unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, Action: authz.MergePullRequest, ExecutionStarted: true, NativeOutcome: "unknown", AuthorizationDecision: "allow"})
		setting.EnterpriseAuthz.Enforce = false
		setting.EnterpriseAuthz.Enabled = false
		unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: 2, DoerID: 4})
		_, err := db.GetEngine(t.Context()).ID(binding.ID).Delete(&authz_model.SubjectRoleBinding{})
		require.NoError(t, err)
		setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce = true, true
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
		head, err := git.GetFullCommitID(t.Context(), repo, pr.GetGitHeadRefName())
		require.NoError(t, err)
		owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		require.NoError(t, commitstatus_service.CreateCommitStatus(t.Context(), repo, owner, head, &git_model.CommitStatus{State: commitstatus.CommitStatusSuccess, Context: "required-queue-check"}))
		require.Eventually(t, func() bool {
			exists, err := db.GetEngine(t.Context()).Exist(&authz_model.DecisionRecord{ActorID: 4, RepoID: 1, Action: authz.MergePullRequest, RequestSource: "auto_merge", AuthorizationDecision: "deny"})
			require.NoError(t, err)
			return exists
		}, 3*time.Second, 10*time.Millisecond)
		pr = unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
		require.False(t, pr.HasMerged)
		unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: 2, DoerID: 4})
		unittest.AssertNotExistsBean(t, &authz_model.DecisionRecord{ActorID: 4, RequestSource: "auto_merge", NativeOutcome: "success"})
	})
}

func TestEnterpriseAuthzMergeEnforceForceKeepsNativeGate(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		enableMergeEnforcement(t)
		require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}, &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}))
		rule := &git_model.ProtectedBranch{RepoID: 1, RuleName: "master", CanPush: true, EnableStatusCheck: true, StatusCheckContexts: []string{"missing-force-check"}, BlockAdminMergeOverride: true}
		require.NoError(t, db.Insert(t.Context(), rule))
		session := loginUser(t, "user4")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		endpoint := "/api/v1/repos/user2/repo1/pulls/3/merge"
		for _, force := range []bool{false, true} {
			session.MakeRequest(t, NewRequestWithJSON(t, "POST", endpoint, map[string]any{"do": "merge", "force_merge": force}).AddTokenAuth(token), 405)
		}
		rule.EnableBypassAllowlist, rule.BypassAllowlistUserIDs = true, []int64{4}
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		require.NoError(t, git_model.UpdateProtectBranch(t.Context(), repo, rule, git_model.WhitelistOptions{BypassUserIDs: []int64{4}}))
		session.MakeRequest(t, NewRequestWithJSON(t, "POST", endpoint, map[string]any{"do": "merge", "force_merge": true}).AddTokenAuth(token), 200)
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
		require.True(t, pr.HasMerged)
		unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, Action: authz.MergePullRequest, ExecutionStarted: true, NativeOutcome: "success"})
		unittest.AssertNotExistsBean(t, &authz_model.DecisionRecord{ActorID: 4, Action: authz.PushProtectedBranch})
	})
}

func mergeEnforceRole(t *testing.T, repo *repo_model.Repository, actorID int64, actions ...authz.Action) *authz_model.SubjectRoleBinding {
	t.Helper()
	role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: repo.ID, Name: "merge-execution", LowerName: "merge-execution", Revision: 1, CreatedBy: repo.OwnerID}
	require.NoError(t, db.Insert(t.Context(), role))
	_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	for _, action := range actions {
		require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: action, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
	}
	binding := &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: actorID, ScopeType: authz_model.ScopeRepo, ScopeID: repo.ID, ScopeOwnerID: repo.OwnerID, RoleID: role.ID}
	require.NoError(t, db.Insert(t.Context(), binding))
	return binding
}

func mergeFixtureCommit(t *testing.T, repo *repo_model.Repository, branch, parent, commands string) string {
	t.Helper()
	stream := fmt.Sprintf("commit refs/heads/%s\ncommitter merge-test <merge@example.com> 1700000000 +0000\ndata 13\nmerge fixture\nfrom %s\n%s\n", branch, parent, commands)
	require.NoError(t, gitcmd.NewCommand("fast-import", "--quiet", "--force").WithRepo(repo).WithStdinBytes([]byte(stream)).RunWithStderr(t.Context()))
	commit, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+branch)
	require.NoError(t, err)
	return commit
}

func TestEnterpriseAuthzMergeEnforceRoutes(t *testing.T) {
	for _, style := range []string{"merge", "manually-merged", "force"} {
		t.Run(style, func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, _ *url.URL) {
				enableMergeEnforcement(t)
				repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
				require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: 1, RuleName: "master", CanPush: true, EnableMergeWhitelist: true, MergeWhitelistUserIDs: []int64{4}}))
				prUnit, err := repo.GetUnit(t.Context(), unit.TypePullRequests)
				require.NoError(t, err)
				prUnit.PullRequestsConfig().AllowManualMerge = true
				require.NoError(t, repo_model.UpdateRepoUnitConfig(t.Context(), prUnit))
				old, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+"master")
				require.NoError(t, err)
				session := loginUser(t, "user4")
				token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
				actualStyle := style
				if style == "force" {
					actualStyle = "merge"
				}
				apiEndpoint, webEndpoint := "/api/v1/repos/user2/repo1/pulls/3/merge", "/user2/repo1/pulls/3/merge"
				body := map[string]any{"do": actualStyle, "merge_commit_id": old, "force_merge": style == "force"}
				session.MakeRequest(t, NewRequestWithJSON(t, "POST", apiEndpoint, body).AddTokenAuth(token), 403)
				session.MakeRequest(t, NewRequestWithValues(t, "POST", webEndpoint, map[string]string{"do": actualStyle, "merge_commit_id": old, "force_merge": strconv.FormatBool(style == "force")}), 403)
				pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
				require.False(t, pr.HasMerged)
				after, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+"master")
				require.NoError(t, err)
				require.Equal(t, old, after)
				mergeEnforceRole(t, repo, 4, authz.MergePullRequest)
				status, outcome := 409, "failed"
				if style == "manually-merged" {
					status, outcome = 200, "success"
				}
				session.MakeRequest(t, NewRequestWithJSON(t, "POST", apiEndpoint, body).AddTokenAuth(token), status)
				pr = unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
				require.Equal(t, style == "manually-merged", pr.HasMerged)
				if pr.HasMerged {
					require.Equal(t, int64(4), pr.MergerID)
				}
				row := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, ActorID: 4, Action: authz.MergePullRequest, AuthorizationDecision: "allow", NativeOutcome: outcome, ExecutionStarted: true})
				require.NotEmpty(t, row.OperationID)
				unittest.AssertNotExistsBean(t, &authz_model.DecisionRecord{RepoID: 1, ActorID: 4, Action: authz.PushProtectedBranch})
			})
		})
	}
}

func TestEnterpriseAuthzMergeEnforceCodeownersDiff(t *testing.T) {
	for _, mutation := range []string{"add", "modify", "rename", "delete"} {
		t.Run(mutation, func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, _ *url.URL) {
				enableMergeEnforcement(t)
				repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
				require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}, &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}))
				old, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+"master")
				require.NoError(t, err)
				if mutation != "add" {
					old = mergeFixtureCommit(t, repo, "master", old, "M 100644 inline CODEOWNERS\ndata 9\n* @user2\n")
				}
				commands := "M 100644 inline CODEOWNERS\ndata 9\n* @user4\n"
				switch mutation {
				case "rename":
					commands = "R CODEOWNERS owners.txt\n"
				case "delete":
					commands = "D CODEOWNERS\n"
				}
				head := mergeFixtureCommit(t, repo, "branch2", old, commands)
				require.NoError(t, gitcmd.NewCommand("update-ref").AddDynamicArguments("refs/pull/3/head", head).WithRepo(repo).RunWithStderr(t.Context()))
				_, err = db.GetEngine(t.Context()).ID(2).Cols("merge_base").Update(&issues_model.PullRequest{MergeBase: old})
				require.NoError(t, err)
				session := loginUser(t, "user4")
				token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
				endpoint := "/api/v1/repos/user2/repo1/pulls/3/merge"
				body := map[string]any{"do": "merge", "head_commit_id": head, "merge_message_field": "private final merge message"}
				session.MakeRequest(t, NewRequestWithJSON(t, "POST", endpoint, body).AddTokenAuth(token), 403)
				pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
				require.False(t, pr.HasMerged)
				after, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+"master")
				require.NoError(t, err)
				require.Equal(t, old, after)
				denied := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, ActorID: 4, Action: authz.ManageCodeowners, AuthorizationDecision: "deny"})
				require.False(t, denied.ExecutionStarted)
				require.NotContains(t, denied.SnapshotJSON, "private final merge message")
				mergeEnforceRole(t, repo, 4, authz.ManageCodeowners)
				session.MakeRequest(t, NewRequestWithJSON(t, "POST", endpoint, body).AddTokenAuth(token), 200)
				mergedPR := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
				require.True(t, mergedPR.HasMerged)
				var records []*authz_model.DecisionRecord
				require.NoError(t, db.GetEngine(t.Context()).Where("repo_id = 1 AND actor_id = 4 AND authorization_decision = ? AND native_outcome = ?", "allow", "success").Find(&records))
				require.Len(t, records, 2)
				require.Equal(t, records[0].OperationID, records[1].OperationID)
				for _, record := range records {
					require.True(t, record.ExecutionStarted)
					require.NotContains(t, record.SnapshotJSON, "* @user4")
				}
				merged, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+"master")
				require.NoError(t, err)
				require.NotEqual(t, old, merged)
				require.NotEmpty(t, strings.TrimSpace(merged))
			})
		})
	}
}

func TestEnterpriseAuthzMergeEnforceHeadUpdateDiff(t *testing.T) {
	for _, rebase := range []bool{false, true} {
		t.Run(fmt.Sprintf("rebase=%t", rebase), func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, _ *url.URL) {
				enableMergeEnforcement(t)
				repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
				pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 5})
				require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}, &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}, &git_model.ProtectedBranch{RepoID: 1, RuleName: pr.HeadBranch, CanPush: true, CanForcePush: true}))
				updateRepoPullRequestConfig(t, 1, func(config *repo_model.PullRequestsConfig) { config.AllowRebaseUpdate = true })
				base, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+pr.BaseBranch)
				require.NoError(t, err)
				mergeFixtureCommit(t, repo, pr.BaseBranch, base, "M 100644 inline CODEOWNERS\ndata 9\n* @user2\n")
				old, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+pr.HeadBranch)
				require.NoError(t, err)
				session := loginUser(t, "user4")
				token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
				style := "merge"
				if rebase {
					style = "rebase"
				}
				endpoint := "/api/v1/repos/user2/repo1/pulls/5/update?style=" + style
				session.MakeRequest(t, NewRequest(t, "POST", endpoint).AddTokenAuth(token), 403)
				session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/pulls/5/update", map[string]string{"style": style}), 403)
				after, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+pr.HeadBranch)
				require.NoError(t, err)
				require.Equal(t, old, after)
				binding := mergeEnforceRole(t, repo, 4, authz.PushProtectedBranch)
				session.MakeRequest(t, NewRequest(t, "POST", endpoint).AddTokenAuth(token), 403)
				_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
				require.NoError(t, err)
				require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: binding.RoleID, Action: authz.ManageCodeowners, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
				session.MakeRequest(t, NewRequest(t, "POST", endpoint).AddTokenAuth(token), 200)
				after, err = git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+pr.HeadBranch)
				require.NoError(t, err)
				require.NotEqual(t, old, after)
				var records []*authz_model.DecisionRecord
				require.NoError(t, db.GetEngine(t.Context()).Where("repo_id = 1 AND actor_id = 4 AND authorization_decision = ? AND native_outcome = ?", "allow", "success").Find(&records))
				require.Len(t, records, 2)
				require.Equal(t, records[0].OperationID, records[1].OperationID)
				unittest.AssertNotExistsBean(t, &authz_model.DecisionRecord{ActorID: 4, Action: authz.MergePullRequest})
				stored := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
				require.False(t, stored.HasMerged)
			})
		})
	}
}

func TestEnterpriseAuthzMergeEnforceManualAndAutoCodeowners(t *testing.T) {
	for _, automatic := range []bool{false, true} {
		t.Run(fmt.Sprintf("automatic=%t", automatic), func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, _ *url.URL) {
				enableMergeEnforcement(t)
				repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
				require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}, &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}))
				updateRepoPullRequestConfig(t, 1, func(config *repo_model.PullRequestsConfig) { config.AllowManualMerge = true })
				old, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+"master")
				require.NoError(t, err)
				branch := "master"
				if automatic {
					branch = "branch2"
					require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: 1, RuleName: "master", CanPush: true, EnableStatusCheck: true, StatusCheckContexts: []string{"manual-auto-check"}}))
				}
				head := mergeFixtureCommit(t, repo, branch, old, "M 100644 inline CODEOWNERS\ndata 9\n* @user4\n")
				require.NoError(t, gitcmd.NewCommand("update-ref").AddDynamicArguments("refs/pull/3/head", head).WithRepo(repo).RunWithStderr(t.Context()))
				_, err = db.GetEngine(t.Context()).ID(2).Cols("merge_base").Update(&issues_model.PullRequest{MergeBase: old})
				require.NoError(t, err)
				session := loginUser(t, "user4")
				token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
				endpoint := "/api/v1/repos/user2/repo1/pulls/3/merge"
				owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
				if automatic {
					session.MakeRequest(t, NewRequestWithJSON(t, "POST", endpoint, map[string]any{"do": "merge", "merge_when_checks_succeed": true, "delete_branch_after_merge": true}).AddTokenAuth(token), 201)
					require.NoError(t, queue.GetManager().FlushAll(t.Context(), 0))
					unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, Action: authz.MergePullRequest, ExecutionStarted: true, NativeOutcome: "unknown", AuthorizationDecision: "allow"})
					require.NoError(t, commitstatus_service.CreateCommitStatus(t.Context(), repo, owner, head, &git_model.CommitStatus{State: commitstatus.CommitStatusSuccess, Context: "manual-auto-check"}))
					require.Eventually(t, func() bool {
						exists, err := db.GetEngine(t.Context()).Exist(&authz_model.DecisionRecord{ActorID: 4, Action: authz.ManageCodeowners, RequestSource: "auto_merge", AuthorizationDecision: "deny"})
						require.NoError(t, err)
						return exists
					}, 3*time.Second, 10*time.Millisecond)
					require.NoError(t, queue.GetManager().FlushAll(t.Context(), 0))
				} else {
					session.MakeRequest(t, NewRequestWithJSON(t, "POST", endpoint, map[string]any{"do": "manually-merged", "merge_commit_id": head}).AddTokenAuth(token), 403)
				}
				unmerged := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
				require.False(t, unmerged.HasMerged)
				current, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+"master")
				require.NoError(t, err)
				if automatic {
					require.Equal(t, old, current)
				} else {
					require.Equal(t, head, current)
				}
				codeownersBinding := mergeEnforceRole(t, repo, 4, authz.ManageCodeowners)
				if automatic {
					_, condition, hash, err := authz.ParseCondition([]byte(`{"branch_pattern":["master"]}`))
					require.NoError(t, err)
					_, err = db.GetEngine(t.Context()).Where("role_id = ?", codeownersBinding.RoleID).Cols("condition_json", "condition_hash").Update(&authz_model.RolePermission{ConditionJSON: condition, ConditionHash: hash})
					require.NoError(t, err)
					require.NoError(t, commitstatus_service.CreateCommitStatus(t.Context(), repo, owner, head, &git_model.CommitStatus{State: commitstatus.CommitStatusSuccess, Context: "manual-auto-check"}))
					require.Eventually(t, func() bool {
						pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
						return pr.HasMerged
					}, 3*time.Second, 10*time.Millisecond)
					require.NoError(t, queue.GetManager().FlushAll(t.Context(), 0))
				} else {
					session.MakeRequest(t, NewRequestWithJSON(t, "POST", endpoint, map[string]any{"do": "manually-merged", "merge_commit_id": head}).AddTokenAuth(token), 200)
				}
				pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
				require.True(t, pr.HasMerged)
				require.Equal(t, int64(4), pr.MergerID)
				if automatic {
					unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, Action: authz.ManageCodeowners, RequestSource: "auto_merge", AuthorizationDecision: "deny", AuthorizationReason: "condition_not_matched"})
					remainingHead, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+"branch2")
					require.NoError(t, err)
					require.Equal(t, head, remainingHead)
				}
				var records []*authz_model.DecisionRecord
				require.NoError(t, db.GetEngine(t.Context()).Where("repo_id = 1 AND actor_id = 4 AND authorization_decision = ? AND native_outcome = ?", "allow", "success").Find(&records))
				require.Len(t, records, 2)
				require.Equal(t, records[0].OperationID, records[1].OperationID)
				for _, record := range records {
					require.True(t, record.ExecutionStarted)
					if automatic {
						require.Equal(t, "auto_merge", record.RequestSource)
					}
				}
				unittest.AssertNotExistsBean(t, &authz_model.DecisionRecord{ActorID: 4, Action: authz.PushProtectedBranch})
			})
		})
	}
}
