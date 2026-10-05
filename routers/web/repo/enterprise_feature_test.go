// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	"net/http"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/context"
	"gitea.dev/services/contexttest"

	"github.com/stretchr/testify/require"
)

func TestWebFeatureGatesIssueAndWiki(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	for _, key := range []authz.FeatureKey{authz.FeatureIssues, authz.FeatureWiki} {
		require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: key, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	}
	ctx, resp := contexttest.MockContext(t, "/user2/repo1/issues")
	contexttest.LoadUser(t, ctx, 2)
	contexttest.LoadRepo(t, ctx, 1)
	MustEnableIssues(ctx)
	require.Equal(t, http.StatusForbidden, resp.Code)
	ctx, resp = contexttest.MockContext(t, "/user2/repo1/wiki")
	contexttest.LoadUser(t, ctx, 2)
	contexttest.LoadRepo(t, ctx, 1)
	MustEnableWiki(ctx)
	require.Equal(t, http.StatusForbidden, resp.Code)
	ctx, _ = contexttest.MockContext(t, "/user2/repo1/pulls")
	contexttest.LoadUser(t, ctx, 2)
	contexttest.LoadRepo(t, ctx, 1)
	MustAllowPulls(ctx)
	require.False(t, ctx.Written())
}

func TestWikiGitHTTPFeatureBoundary(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureWiki, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	ctx, resp := contexttest.MockContext(t, "/user2/repo1.wiki.git/info/refs")
	contexttest.LoadUser(t, ctx, 2)
	ctx.ContextUser = ctx.Doer
	ctx.SetPathParam("reponame", "repo1.wiki.git")
	require.Nil(t, httpBase(ctx, "git-upload-pack"))
	require.Equal(t, http.StatusForbidden, resp.Code)
	ctx, _ = contexttest.MockContext(t, "/user2/repo1.git/info/refs")
	contexttest.LoadUser(t, ctx, 2)
	ctx.ContextUser = ctx.Doer
	ctx.SetPathParam("reponame", "repo1.git")
	require.NotNil(t, httpBase(ctx, "git-upload-pack"))
	require.False(t, ctx.Written())
}

func TestCargoIndexGitHTTPFeatureBoundary(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	_, err := db.GetEngine(t.Context()).ID(1).Cols("internal_usage").Update(&repo_model.Repository{InternalUsage: repo_model.InternalUsageCargoIndex})
	require.NoError(t, err)
	ctx, resp := contexttest.MockContext(t, "/user2/repo1.git/info/refs")
	contexttest.LoadUser(t, ctx, 2)
	ctx.ContextUser = ctx.Doer
	ctx.SetPathParam("reponame", "repo1.git")
	require.Nil(t, httpBase(ctx, "git-upload-pack"))
	require.Equal(t, http.StatusForbidden, resp.Code)
	_, err = db.GetEngine(t.Context()).ID(1).Cols("internal_usage").Update(&repo_model.Repository{})
	require.NoError(t, err)
	ctx, _ = contexttest.MockContext(t, "/user2/repo1.git/info/refs")
	contexttest.LoadUser(t, ctx, 2)
	ctx.ContextUser = ctx.Doer
	ctx.SetPathParam("reponame", "repo1.git")
	require.NotNil(t, httpBase(ctx, "git-upload-pack"))
}

func TestCargoIndexWebReferenceFeatureBoundary(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	ctx, resp := contexttest.MockContext(t, "/user2/repo1/src/branch/master")
	contexttest.LoadUser(t, ctx, 2)
	contexttest.LoadRepo(t, ctx, 1)
	ctx.Repo.Repository.InternalUsage = repo_model.InternalUsageCargoIndex
	ctx.Repo.Repository.IsEmpty = true
	context.RepoRefByType(git.RefTypeBranch)(ctx)
	require.Equal(t, http.StatusForbidden, resp.Code)
	require.True(t, ctx.Written())
}
