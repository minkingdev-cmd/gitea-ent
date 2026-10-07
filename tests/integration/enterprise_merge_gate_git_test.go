// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitrepo"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"
	pull_service "gitea.dev/services/pull"
	repo_service "gitea.dev/services/repository"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseMergeGateStylesAndGitGuards(t *testing.T) {
	for _, mode := range []string{"disabled", "shadow", "enforce"} {
		for _, style := range []repo_model.MergeStyle{repo_model.MergeStyleMerge, repo_model.MergeStyleRebase, repo_model.MergeStyleRebaseMerge, repo_model.MergeStyleSquash, repo_model.MergeStyleFastForwardOnly} {
			t.Run(mode+"/"+string(style), func(t *testing.T) {
				onGiteaRun(t, func(t *testing.T, _ *url.URL) {
					featureTestMode(t)
					setting.EnterpriseAuthz.Enforce = true
					t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: mode != "disabled", Enforce: mode == "enforce"}))
					pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
					actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
					require.NoError(t, pr.LoadBaseRepo(t.Context()))
					ctx, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
					before, err := git.GetFullCommitID(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
					require.NoError(t, err)
					protection := &git_model.ProtectedBranch{RepoID: pr.BaseRepoID, RuleName: pr.BaseBranch, CanPush: false, RequireSignedCommits: true}
					require.NoError(t, git_model.UpdateProtectBranch(ctx, pr.BaseRepo, protection, git_model.WhitelistOptions{}))
					err = pull_service.Merge(ctx, pr, actor, style, "", "unsigned merge must not pass", false, pull_service.MergeOptions{Force: true, BypassReason: "signed guard is mandatory", BypassCategories: []string{"required_check"}})
					require.Error(t, err)
					require.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
					after, err := git.GetFullCommitID(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
					require.NoError(t, err)
					require.Equal(t, before, after)
					protection.RequireSignedCommits = false
					require.NoError(t, git_model.UpdateProtectBranch(ctx, pr.BaseRepo, protection, git_model.WhitelistOptions{}))
					hook := filepath.Join(gitrepo.RepoLocalPath(pr.BaseRepo.CodeStorageRepo()), "hooks", "pre-receive.d", "zz-gate-acceptance-deny")
					require.NoError(t, os.WriteFile(hook, []byte("#!/bin/sh\nexit 1\n"), 0o755))
					err = pull_service.Merge(ctx, pr, actor, style, "", "native pre-receive must run", false)
					require.Error(t, err)
					require.False(t, unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID}).HasMerged)
					after, err = git.GetFullCommitID(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
					require.NoError(t, err)
					require.Equal(t, before, after)
					if mode != "disabled" {
						unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, ExecutionState: "unknown"})
					}
					require.NoError(t, os.Remove(hook))
					require.NoError(t, pull_service.Merge(ctx, pr, actor, style, "", "native style compatibility", false))
					current := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
					require.True(t, current.HasMerged)
					after, err = git.GetFullCommitID(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
					require.NoError(t, err)
					require.Equal(t, current.MergedCommitID, after)
					require.NotEqual(t, before, after)
				})
			})
		}
	}
}

func TestEnterpriseMergeGateActualForkAndAGitMerge(t *testing.T) {
	for _, flow := range []string{"fork", "agit"} {
		t.Run(flow, func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, _ *url.URL) {
				featureTestMode(t)
				setting.EnterpriseAuthz.Enforce = true
				t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
				pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
				actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
				require.NoError(t, pr.LoadBaseRepo(t.Context()))
				head, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.HeadBranch)
				require.NoError(t, err)
				if flow == "fork" {
					forkOwner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
					fork, err := repo_service.ForkRepository(t.Context(), actor, forkOwner, repo_service.ForkRepoOptions{BaseRepo: pr.BaseRepo, Name: "gate-real-fork"})
					require.NoError(t, err)
					_, err = db.GetEngine(t.Context()).ID(pr.ID).Cols("head_repo_id").Update(&issues_model.PullRequest{HeadRepoID: fork.ID})
					require.NoError(t, err)
				} else {
					require.NoError(t, git.UpdateRef(t.Context(), pr.BaseRepo, pr.GetGitHeadRefName(), head))
					_, err = db.GetEngine(t.Context()).ID(pr.ID).Cols("flow", "head_branch").Update(&issues_model.PullRequest{Flow: issues_model.PullRequestFlowAGit, HeadBranch: "gate-hidden-no-branch"})
					require.NoError(t, err)
				}
				ctx, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
				require.NoError(t, pull_service.Merge(ctx, pr, actor, repo_model.MergeStyleMerge, head, "fork and AGit acceptance", false))
				current := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
				require.True(t, current.HasMerged)
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID, ExecutionState: "succeeded"})
				require.Equal(t, head, record.HeadSHA)
				require.Equal(t, current.MergedCommitID, record.MergedSHA)
			})
		})
	}
}
