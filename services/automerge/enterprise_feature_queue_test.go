// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package automerge

import (
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	issues_model "gitea.dev/models/issues"
	pull_model "gitea.dev/models/pull"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/audit"
	"gitea.dev/services/automergequeue"

	"github.com/stretchr/testify/require"
)

func TestAutoMergeFeatureRevokedAfterQueue(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	var queued []automergequeue.AutoMergeItem
	t.Cleanup(test.MockVariableValue(&automergequeue.AddToQueue, func(item automergequeue.AutoMergeItem) { queued = append(queued, item) }))
	ctx := audit.WithOrigin(t.Context(), audit_model.OriginAPI)
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(t.Context()))
	before, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
	require.NoError(t, err)
	scheduled, err := ScheduleAutoMerge(ctx, actor, pr, repo_model.MergeStyleMerge, "queued before feature revocation", false)
	require.NoError(t, err)
	require.True(t, scheduled)
	require.Len(t, queued, 1)
	unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: pr.ID})
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePullRequests, ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	handleAutoMergeItem(queued[0])
	stored := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
	require.False(t, stored.HasMerged)
	require.Empty(t, stored.MergedCommitID)
	after, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
	require.NoError(t, err)
	require.Equal(t, before, after)
	unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseFeatureDecision}, unittest.Cond("metadata LIKE ? AND metadata LIKE ?", `%"feature_key":"feature.pull_requests"%`, `%"actual_decision":"deny"%`))
}
