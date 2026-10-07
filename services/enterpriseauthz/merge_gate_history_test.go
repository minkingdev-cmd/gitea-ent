// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	wecom_model "gitea.dev/models/enterprisewecom"
	issues_model "gitea.dev/models/issues"
	organization_model "gitea.dev/models/organization"
	"gitea.dev/models/perm"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/util"

	"github.com/stretchr/testify/require"
)

func TestMergeGateHistoryIsolationAndPagination(t *testing.T) {
	enableMergeGate(t)
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	reader := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 1})
	snapshot := `{"snapshot_version":1}`
	var ids []int64
	for i := range 3 {
		record := &authz_model.MergeGateEvaluation{OperationID: fmt.Sprintf("history-%d", i), Attempt: 1, Phase: "admission", RepoID: pr.BaseRepoID, PullID: pr.ID, IssueID: pr.IssueID, ActorID: owner.ID, HeadSHA: strings.Repeat("a", 40), BaseSHA: strings.Repeat("b", 40), Source: "web", Mode: "enforce", CandidateDecision: "allow", AdmissionDecision: "allow", ExecutionState: "not_started", SnapshotVersion: 1, SnapshotJSON: snapshot, SnapshotHash: fmt.Sprintf("%x", sha256.Sum256([]byte(snapshot))), ReasonsJSON: "[]"}
		_, err := authz_model.InsertMergeGateEvaluation(t.Context(), record)
		require.NoError(t, err)
		ids = append(ids, record.ID)
	}
	records, total, err := ListMergeGateEvaluations(t.Context(), owner, pr.BaseRepoID, pr.ID, PolicyListOptions{Page: 2, Limit: 1})
	require.NoError(t, err)
	require.EqualValues(t, 3, total)
	require.Len(t, records, 1)
	require.Equal(t, ids[1], records[0].ID)
	_, err = GetMergeGateEvaluation(t.Context(), owner, pr.BaseRepoID, pr.ID, ids[0])
	require.NoError(t, err)
	_, err = GetMergeGateEvaluation(t.Context(), owner, pr.BaseRepoID, 999999, ids[0])
	require.ErrorIs(t, err, util.ErrNotExist)
	_, err = GetMergeGateEvaluation(t.Context(), owner, 2, pr.ID, ids[0])
	require.Error(t, err)
	_, _, err = ListMergeGateEvaluations(t.Context(), reader, pr.BaseRepoID, pr.ID, PolicyListOptions{})
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	ctx := reqctx.NewRequestContextForTest(t)
	ctx.GetData()["ApiTokenScope"] = auth_model.AccessTokenScopePublicOnly
	_, err = GetMergeGateEvaluation(ctx, owner, pr.BaseRepoID, pr.ID, ids[0])
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	_, _, err = ListMergeGateEvaluations(t.Context(), owner, pr.BaseRepoID, pr.ID, PolicyListOptions{Limit: 101})
	require.ErrorIs(t, err, ErrInvalidPolicy)
	_, err = db.GetEngine(t.Context()).ID(ids[0]).Cols("snapshot_version").Update(&authz_model.MergeGateEvaluation{SnapshotVersion: 999})
	require.NoError(t, err)
	_, err = GetMergeGateEvaluation(t.Context(), owner, pr.BaseRepoID, pr.ID, ids[0])
	require.ErrorIs(t, err, ErrPolicyStorage)
}

func TestMergeGateHistoryRejectsStaleAdminPRVisibility(t *testing.T) {
	enableMergeGate(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "history-corp", AgentID: "history-agent"}))
	creator := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	require.False(t, creator.IsAdmin)
	creator.IsAdmin = true
	require.NoError(t, db.Insert(t.Context(), &wecom_model.RepositoryGovernance{RepoID: 3, CreatorID: creator.ID}))
	_, err := db.GetEngine(t.Context()).Where("team_id=? AND type=?", 2, unit.TypePullRequests).Delete(new(organization_model.TeamUnit))
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).ID(2).Cols("authorize").Update(&organization_model.Team{AccessMode: 0})
	require.NoError(t, err)
	pr := &issues_model.PullRequest{BaseRepoID: 3, HeadRepoID: 3, IssueID: 1, Index: 987}
	require.NoError(t, db.Insert(t.Context(), pr))
	snapshot := `{"snapshot_version":1}`
	record := &authz_model.MergeGateEvaluation{OperationID: "history-stale-admin", Attempt: 1, Phase: "admission", RepoID: 3, PullID: pr.ID, IssueID: pr.IssueID, ActorID: 2, HeadSHA: strings.Repeat("a", 40), BaseSHA: strings.Repeat("b", 40), Source: "web", Mode: "enforce", CandidateDecision: "allow", AdmissionDecision: "allow", ExecutionState: "not_started", SnapshotVersion: 1, SnapshotJSON: snapshot, SnapshotHash: fmt.Sprintf("%x", sha256.Sum256([]byte(snapshot))), ReasonsJSON: "[]"}
	_, err = authz_model.InsertMergeGateEvaluation(t.Context(), record)
	require.NoError(t, err)
	require.NoError(t, authorizeProtectedPaths(t.Context(), creator, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 3}, false))
	_, _, err = ListMergeGateEvaluations(t.Context(), creator, 3, pr.ID, PolicyListOptions{})
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	_, err = GetMergeGateEvaluation(t.Context(), creator, 3, pr.ID, record.ID)
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	_, err = db.GetEngine(t.Context()).ID(creator.ID).Cols("is_admin").Update(&user_model.User{IsAdmin: true})
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Where("team_id=? AND type=?", 2, unit.TypeCode).Delete(new(organization_model.TeamUnit))
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &organization_model.TeamUnit{TeamID: 2, Type: unit.TypePullRequests, AccessMode: perm.AccessModeRead}))
	_, _, err = ListMergeGateEvaluations(t.Context(), creator, 3, pr.ID, PolicyListOptions{})
	require.ErrorIs(t, err, util.ErrPermissionDenied, "revoked WeCom admin cannot replace code visibility")
	_, err = GetMergeGateEvaluation(t.Context(), creator, 3, pr.ID, record.ID)
	require.ErrorIs(t, err, util.ErrPermissionDenied)
}
