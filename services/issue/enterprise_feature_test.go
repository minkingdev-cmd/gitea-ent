// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package issue

import (
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	repo_module "gitea.dev/modules/repository"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestIssueFeatureRejectsMutationBeforeSideEffects(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureIssues, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	issue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 1})
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	title := issue.Title
	require.ErrorContains(t, ChangeTitle(t.Context(), issue, doer, "forbidden"), "feature_disabled")
	require.Equal(t, title, issue.Title)
	require.ErrorContains(t, ChangeContent(t.Context(), issue, doer, "forbidden", 0), "feature_disabled")
	require.ErrorContains(t, CloseIssue(t.Context(), issue, doer, ""), "feature_disabled")
	_, err := CreateIssueComment(t.Context(), doer, repo, issue, "forbidden", nil)
	require.ErrorContains(t, err, "feature_disabled")
	require.ErrorContains(t, DeleteIssue(t.Context(), doer, issue), "feature_disabled")
	stored := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 1})
	require.Equal(t, title, stored.Title)
	require.Equal(t, issue.Content, stored.Content)
	require.False(t, stored.IsClosed)
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 2})
	require.NoError(t, ChangeTitle(t.Context(), pr, doer, "permitted PR"))
	setting.EnterpriseAuthz.Enforce = false
	require.NoError(t, ChangeTitle(t.Context(), issue, doer, "shadow allowed"))
}

func TestFeatureStopwatchDoesNotFinishDisabledPreviousIssue(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureIssues, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	next := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 2})
	_, err := CreateIssueStopwatch(t.Context(), doer, next)
	require.ErrorContains(t, err, "feature_disabled")
	unittest.AssertExistsAndLoadBean(t, &issues_model.Stopwatch{ID: 1, IssueID: 1, UserID: 1})
}

func TestFeatureDependencyMutationChecksBothTargets(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureIssues, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	target := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 2})
	dependency := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 1})
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	require.ErrorContains(t, CreateIssueDependency(t.Context(), doer, target, dependency), "feature_disabled")
	unittest.AssertNotExistsBean(t, &issues_model.IssueDependency{IssueID: target.ID, DependencyID: dependency.ID})
	require.NoError(t, db.Insert(t.Context(), &issues_model.IssueDependency{UserID: 1, IssueID: target.ID, DependencyID: dependency.ID}))
	require.ErrorContains(t, RemoveIssueDependency(t.Context(), doer, target, dependency, issues_model.DependencyTypeBlockedBy), "feature_disabled")
	unittest.AssertExistsAndLoadBean(t, &issues_model.IssueDependency{IssueID: target.ID, DependencyID: dependency.ID})
}

func TestFeatureDisabledReferenceDoesNotRejectCodePush(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureIssues, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, UpdateIssuesCommit(t.Context(), doer, repo, []*repo_module.PushCommit{{Sha1: "65f1bf27bc3bf70f64657658635e66094edbcb4d", Message: "closes #1"}}, "master"))
	issue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: 1})
	require.False(t, issue.IsClosed)
}
