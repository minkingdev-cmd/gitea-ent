// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func TestMergeGatePreviewProvidesSafeCapabilitiesWithoutEvidence(t *testing.T) {
	ctx := mergeExecutionContext(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, db.Insert(ctx, &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["private/upper-check"]}`}))
	preview, err := PreviewMergeGate(ctx, actor, pr.BaseRepoID, pr.ID, "")
	require.NoError(t, err)
	encoded, err := json.Marshal(preview)
	require.NoError(t, err)
	require.Contains(t, string(encoded), `"can_bypass":true`)
	require.Contains(t, string(encoded), `"can_schedule":true`)
	require.NotContains(t, string(encoded), "private/upper-check")
	unittest.AssertCount(t, &authz_model.MergeGateEvaluation{}, 0)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateEvaluation}, 0)
}

func TestMergeGateManualPreviewNeverAdmits(t *testing.T) {
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
	oldSHA, err := repo.GetBranchCommitID(ctx, pr.BaseBranch)
	require.NoError(t, err)
	headSHA, err := repo.GetRefCommitID(ctx, pr.GetGitHeadRefName())
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, git.UpdateRef(context.WithoutCancel(ctx), pr.BaseRepo, git.BranchPrefix+pr.BaseBranch, oldSHA))
	})
	require.NoError(t, git.UpdateRef(ctx, pr.BaseRepo, git.BranchPrefix+pr.BaseBranch, headSHA))
	require.NoError(t, RecordManualMergePush(ctx, actor, pr.BaseRepo, pr.BaseBranch, oldSHA, headSHA, "git_http", authz_service.CredentialCeiling{Read: true, Write: true}))
	for _, candidate := range []string{"allow", "deny", "error"} {
		commitID := headSHA
		if candidate == "deny" {
			require.NoError(t, db.Insert(ctx, &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: pr.BaseRepoID, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["manual/check"]}`}))
		}
		if candidate == "error" {
			commitID = "invalid"
		}
		preview, err := PreviewMergeGate(ctx, actor, pr.BaseRepoID, pr.ID, repo_model.MergeStyleManuallyMerged, commitID)
		require.NoError(t, err)
		require.Equal(t, candidate, preview.CandidateDecision)
		require.Equal(t, "not_admitted", preview.AdmissionDecision)
		require.True(t, preview.PreviewOnly)
		unittest.AssertCount(t, &authz_model.MergeGateEvaluation{}, 1)
		unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateMarker}, 0)
	}
}
