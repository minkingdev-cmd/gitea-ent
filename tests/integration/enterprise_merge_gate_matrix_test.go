// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"net/http"
	"net/url"
	"testing"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	wecom_model "gitea.dev/models/enterprisewecom"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/queue"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/automerge"
	authz_service "gitea.dev/services/enterpriseauthz"
	"gitea.dev/services/notify"
	pull_service "gitea.dev/services/pull"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseMergeGateEntryRoleMatrix(t *testing.T) {
	for _, mode := range []string{"disabled", "shadow", "enforce"} {
		for _, entry := range []string{"web", "api", "shared", "force", "manual", "auto"} {
			for _, role := range []string{"owner", "trusted_admin", "admin", "custom", "readonly", "limited_token"} {
				t.Run(mode+"/"+entry+"/"+role, func(t *testing.T) {
					onGiteaRun(t, func(t *testing.T, _ *url.URL) {
						featureTestMode(t)
						setting.EnterpriseAuthz.Enforce = true
						t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: mode != "disabled", Enforce: mode == "enforce"}))
						repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
						pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
						actorID := int64(2)
						if role == "trusted_admin" {
							actorID = 1
							setting.EnterpriseWeCom = setting.EnterpriseWeComConfig{Enabled: true, CorpID: "gate-matrix", AgentID: "gate-app"}
							require.NoError(t, db.Insert(t.Context(), &wecom_model.AdminAuthority{CorpID: "gate-matrix", AgentID: "gate-app", WeComUserID: "trusted", IsManagement: true, IsActive: true}))
							_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 1, CorpID: "gate-matrix", WeComUserID: "trusted", Status: wecom_model.IdentityStatusActive})
							require.NoError(t, err)
						} else if role == "admin" || role == "custom" || role == "readonly" {
							actorID = 4
							level := perm.AccessModeAdmin
							if role == "readonly" {
								level = perm.AccessModeRead
							}
							require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: level}, &access_model.Access{RepoID: 1, UserID: 4, Mode: level}))
							if role == "custom" {
								mergeEnforceRole(t, repo, 4, authz.MergePullRequest, authz.BypassMergeGate)
							}
						}
						actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: actorID})
						session := loginUser(t, actor.Name)
						scope := auth_model.AccessTokenScopeWriteRepository
						if role == "limited_token" {
							scope = auth_model.AccessTokenScopeReadRepository
						}
						token := getTokenForLoggedInUser(t, session, scope)
						credential, err := auth_model.GetAccessTokenBySHA(t.Context(), token)
						require.NoError(t, err)
						ceiling := authz_service.CredentialCeiling{Read: true, Write: role != "limited_token", Reference: fmt.Sprintf("access-token:%d", credential.ID)}
						require.NoError(t, git_model.UpdateProtectBranch(t.Context(), repo, &git_model.ProtectedBranch{RepoID: 1, RuleName: pr.BaseBranch, CanPush: false, EnableStatusCheck: true, StatusCheckContexts: []string{"security/matrix"}}, git_model.WhitelistOptions{}))
						updateRepoPullRequestConfig(t, 1, func(config *repo_model.PullRequestsConfig) { config.AllowManualMerge = true })
						before, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+pr.BaseBranch)
						require.NoError(t, err)
						head, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+pr.HeadBranch)
						require.NoError(t, err)
						statusToken := getUserToken(t, "user2", auth_model.AccessTokenScopeWriteRepository)
						publish := func() {
							MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/statuses/"+head, map[string]any{"context": "security/matrix", "state": "success"}).AddTokenAuth(statusToken), http.StatusCreated)
						}
						if entry != "force" && entry != "auto" {
							publish()
						}
						ctx, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: repo, Action: authz.MergePullRequest, Credential: ceiling, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
						allowed := role != "readonly" && role != "limited_token" && !(entry == "force" && mode == "enforce" && role == "admin")
						counter := &mergeGateMergeNotificationCounter{pullID: pr.ID}
						counter.enabled.Store(true)
						notify.RegisterNotifier(counter)
						t.Cleanup(func() { counter.enabled.Store(false) })
						var mutationErr error
						switch entry {
						case "shared":
							mutationErr = pull_service.Merge(ctx, pr, actor, repo_model.MergeStyleMerge, head, "matrix merge", false)
						case "manual":
							require.NoError(t, git.UpdateRef(t.Context(), repo, git.BranchPrefix+pr.BaseBranch, head))
							captureErr := pull_service.RecordManualMergePush(ctx, actor, repo, pr.BaseBranch, before, head, "git_http", ceiling)
							if role == "limited_token" && mode != "disabled" {
								require.Error(t, captureErr)
							} else {
								require.NoError(t, captureErr)
							}
							opened, err := git.OpenRepository(t.Context(), repo)
							require.NoError(t, err)
							defer opened.Close()
							mutationErr = pull_service.MergedManually(ctx, pr, actor, opened, head)
						case "auto":
							_, mutationErr = automerge.ScheduleAutoMerge(ctx, actor, pr, repo_model.MergeStyleMerge, "matrix auto", true)
							require.NoError(t, queue.GetManager().FlushAll(t.Context(), 0))
							if mutationErr == nil {
								publish()
								require.NoError(t, queue.GetManager().FlushAll(t.Context(), 0))
							}
						default:
							body := map[string]any{"do": "merge", "delete_branch_after_merge": true}
							if entry == "force" {
								body["force_merge"], body["bypass_reason"], body["bypass_categories"] = true, "approved matrix exception", []string{"required_check"}
							}
							request := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/merge", body).AddTokenAuth(token)
							if entry == "web" {
								request = NewRequestWithValues(t, "POST", "/user2/repo1/pulls/3/merge", map[string]string{"do": "merge", "delete_branch_after_merge": "on"})
								if role == "limited_token" {
									request.AddTokenAuth(token)
									session = nil
								}
							}
							response := session.MakeRequest(t, request, NoExpectedStatus)
							if allowed {
								require.Equal(t, http.StatusOK, response.Code, response.Body.String())
							} else {
								require.Contains(t, []int{http.StatusBadRequest, http.StatusForbidden, http.StatusMethodNotAllowed}, response.Code, response.Body.String())
							}
						}
						if entry == "shared" || entry == "manual" || entry == "auto" {
							if allowed {
								require.NoError(t, mutationErr)
							} else {
								require.Error(t, mutationErr)
							}
						}
						current := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
						require.Equal(t, allowed, current.HasMerged)
						if mode == "disabled" {
							unittest.AssertCount(t, &authz_model.MergeGateEvaluation{}, 0)
						} else if allowed {
							unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, ActorID: actor.ID, ExecutionState: "succeeded"})
						}
						after, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+pr.BaseBranch)
						require.NoError(t, err)
						if entry == "manual" {
							require.Equal(t, head, after)
						} else if allowed {
							require.NotEqual(t, before, after)
						} else {
							require.Equal(t, before, after)
						}
						require.NoError(t, queue.GetManager().FlushAll(t.Context(), 0))
						if allowed {
							require.EqualValues(t, 1, counter.count.Load())
						} else {
							require.Zero(t, counter.count.Load())
						}
						remaining, err := git.GetFullCommitID(t.Context(), repo, git.BranchPrefix+pr.HeadBranch)
						if allowed && (entry == "web" || entry == "api" || entry == "force" || entry == "auto") {
							require.Error(t, err)
						} else {
							require.NoError(t, err)
							require.Equal(t, head, remaining)
						}
					})
				})
			}
		}
	}
}
