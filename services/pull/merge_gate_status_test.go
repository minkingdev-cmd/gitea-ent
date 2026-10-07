// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/commitstatus"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

func TestMergeGateStatusSourcesAndCurrentHead(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	head := strings.Repeat("a", 40)
	pr := &issues_model.PullRequest{BaseRepoID: 1, BaseBranch: "gate-status"}
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: 1, FeatureKey: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Revision: 1, ConfigJSON: `{"check_contexts":["security/check"]}`}))
	add := func(repo int64, sha string, index int64, state commitstatus.CommitStatusState) {
		t.Helper()
		require.NoError(t, db.Insert(t.Context(), &git_model.CommitStatus{RepoID: repo, SHA: sha, Index: index, Context: "security/check", ContextHash: "gate-check", State: state, CreatorID: 2, Description: "must not enter snapshot", TargetURL: "https://example.invalid/private"}))
	}
	add(1, head, 1, commitstatus.CommitStatusSuccess)
	add(1, head, 2, commitstatus.CommitStatusSkipped)
	add(1, strings.Repeat("b", 40), 3, commitstatus.CommitStatusSuccess)
	add(2, head, 4, commitstatus.CommitStatusSuccess)
	result, err := collectMergeGateStatuses(t.Context(), pr, head, nil)
	require.NoError(t, err)
	require.Len(t, result.Statuses, 1)
	require.Equal(t, "skipped", result.Statuses[0].State)
	require.EqualValues(t, 2, result.Statuses[0].CreatorID)
	require.Len(t, result.Facts, 1)
	require.Equal(t, "feature", result.Facts[0].Source)
	require.Equal(t, "failure", result.Facts[0].State)
	require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: 1, RuleName: pr.BaseBranch, EnableStatusCheck: true, StatusCheckContexts: []string{"security/*"}}))
	result, err = collectMergeGateStatuses(t.Context(), pr, head, []authz.MergeGateContext{{Context: "security/check", Source: "path", ReferenceID: 4}})
	require.NoError(t, err)
	require.Len(t, result.Facts, 3)
	for _, fact := range result.Facts {
		if fact.Source == "native" {
			require.Equal(t, "passed", fact.State)
		} else {
			require.Equal(t, "failure", fact.State)
		}
	}
	add(1, head, 5, commitstatus.CommitStatusSuccess)
	result, err = collectMergeGateStatuses(t.Context(), pr, head, nil)
	require.NoError(t, err)
	for _, fact := range result.Facts {
		require.Equal(t, "passed", fact.State)
	}
	add(1, head, 6, commitstatus.CommitStatusFailure)
	_, err = db.GetEngine(t.Context()).Where("feature_key=? AND scope_id=?", authz.FeatureGitleaksScan, 1).Cols("state", "config_json", "revision").Update(&authz_model.FeatureGrant{State: authz.FeatureDisabled, ConfigJSON: `{}`, Revision: 2})
	require.NoError(t, err)
	result, err = collectMergeGateStatuses(t.Context(), pr, head, []authz.MergeGateContext{{Context: "security/check", Source: "path", ReferenceID: 4}})
	require.NoError(t, err)
	require.Len(t, result.Facts, 2, "disabled feature does not revoke native or independent path requirements")
	for _, fact := range result.Facts {
		require.Equal(t, "failure", fact.State)
	}
	hook := &mergeGateStatusReadFault{active: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	defer func() { hook.active = false }()
	_, err = collectMergeGateStatuses(t.Context(), pr, head, nil)
	require.Error(t, err)
	setting.EnterpriseMergeGate.Enabled = false
	result, err = collectMergeGateStatuses(t.Context(), pr, head, nil)
	require.NoError(t, err)
	require.Empty(t, result.Facts)
	require.Empty(t, result.Statuses)
}

type mergeGateStatusReadFault struct {
	active bool
	table  string
}

func (h *mergeGateStatusReadFault) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	table := h.table
	if table == "" {
		table = "commit_status"
	}
	if h.active && strings.HasPrefix(c.SQL, "SELECT") && strings.Contains(c.SQL, table) {
		return c.Ctx, errors.New("status storage fault")
	}
	return c.Ctx, nil
}
func (*mergeGateStatusReadFault) AfterProcess(*contexts.ContextHook) error { return nil }

func TestMergeGateEmptyNativeContextsAggregateAllStatuses(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	head := strings.Repeat("a", 40)
	pr := &issues_model.PullRequest{BaseRepoID: 1, BaseBranch: "all-statuses"}
	require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: 1, RuleName: pr.BaseBranch, EnableStatusCheck: true}))
	statuses := []*git_model.CommitStatus{
		{RepoID: 1, SHA: head, Index: 1, Context: "ok", ContextHash: "ok", State: commitstatus.CommitStatusSuccess},
		{RepoID: 1, SHA: head, Index: 2, Context: "bad\ncheck", ContextHash: "bad", State: commitstatus.CommitStatusFailure},
	}
	for _, status := range statuses {
		require.NoError(t, db.Insert(t.Context(), status))
	}
	require.Equal(t, commitstatus.CommitStatusFailure, MergeRequiredContextsCommitStatus(statuses, nil))
	result, err := collectMergeGateStatuses(t.Context(), pr, head, nil)
	require.NoError(t, err)
	require.Len(t, result.Facts, 1)
	require.Equal(t, "failure", result.Facts[0].State)
}

func TestMergeGateNativePolicyAndWorkflowReadsPreserveErrors(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	pr := &issues_model.PullRequest{BaseRepoID: 1, BaseBranch: "workflow-read"}
	require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: 1, RuleName: pr.BaseBranch, EnableStatusCheck: true}))
	hook := &mergeGateStatusReadFault{active: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	defer func() { hook.active = false }()
	for _, table := range []string{"protected_branch", "action_scoped_workflow_source", "enterprise_feature_grant"} {
		hook.table = table
		result, err := collectMergeGateStatuses(t.Context(), pr, strings.Repeat("a", 40), nil)
		require.Error(t, err, table)
		require.Empty(t, result.Contexts, "unknown requirements cannot become an empty allowed result")
		require.Empty(t, result.Facts)
	}
}
