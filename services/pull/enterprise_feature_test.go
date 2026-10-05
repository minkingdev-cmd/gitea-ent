// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	git_service "gitea.dev/services/git"

	"github.com/stretchr/testify/require"
)

func TestPullFeatureRejectsCreationAndMerge(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePullRequests, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	issue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 2})
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{IssueID: 2})
	require.ErrorContains(t, NewPullRequest(t.Context(), &NewPullRequestOptions{Repo: repo, Issue: issue, PullRequest: pr}), "feature_disabled")
	require.ErrorContains(t, Merge(t.Context(), pr, doer, repo_model.MergeStyleMerge, "", "", true), "feature_disabled")
	require.ErrorContains(t, MergedManually(t.Context(), pr, doer, &git.Repository{}, ""), "feature_disabled")
	require.ErrorContains(t, ChangeTargetBranch(t.Context(), pr, doer, "other"), "feature_disabled")
	require.ErrorContains(t, SetAllowEdits(t.Context(), doer, pr, true), "feature_disabled")
	_, _, err := SubmitReview(t.Context(), doer, nil, issue, issues_model.ReviewTypeApprove, "", "", nil)
	require.ErrorContains(t, err, "feature_disabled")
}

func TestCargoIndexPullSourceBoundaries(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	_, err := db.GetEngine(t.Context()).ID(1).Cols("internal_usage").Update(&repo_model.Repository{InternalUsage: repo_model.InternalUsageCargoIndex})
	require.NoError(t, err)
	head := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	base := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
	issue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 2})
	pr := &issues_model.PullRequest{HeadRepoID: head.ID, HeadRepo: head, BaseRepoID: base.ID, BaseRepo: base, IssueID: issue.ID, Issue: issue}
	require.ErrorContains(t, NewPullRequest(t.Context(), &NewPullRequestOptions{Repo: base, Issue: issue, PullRequest: pr}), "feature_disabled")
	require.ErrorContains(t, PushToBaseRepo(t.Context(), pr), "feature_disabled")
	require.ErrorContains(t, UpdateRef(t.Context(), pr), "feature_disabled")
	_, _, err = createTemporaryRepoForPR(t.Context(), pr)
	require.ErrorContains(t, err, "feature_disabled")
	_, err = GetSquashMergeCommitMessages(t.Context(), pr)
	require.ErrorContains(t, err, "feature_disabled")
	_, err = IsHeadEqualWithBranch(t.Context(), pr, "master")
	require.ErrorContains(t, err, "feature_disabled")
	_, err = GetPullRequestCommitStatusState(t.Context(), pr)
	require.ErrorContains(t, err, "feature_disabled")
	_, err = git_service.GetCompareInfo(t.Context(), base, head, nil, "master", "master", false, false)
	require.ErrorContains(t, err, "feature_disabled")
	setting.EnterpriseAuthz.Enforce = false
	require.NoError(t, requirePullCodeFeatures(t.Context(), pr))
	setting.EnterpriseAuthz.Enforce = true
	_, err = db.GetEngine(t.Context()).ID(head.ID).Cols("internal_usage").Update(&repo_model.Repository{})
	require.NoError(t, err)
	require.NoError(t, requirePullCodeFeatures(t.Context(), pr))
}
