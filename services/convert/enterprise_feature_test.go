// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package convert

import (
	"context"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/cache"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestRepositoryFeatureProjection(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	for _, key := range []authz.FeatureKey{authz.FeatureIssues, authz.FeaturePullRequests, authz.FeatureWiki} {
		require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: key, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	}
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	repo.NumOpenIssues, repo.NumOpenPulls = 7, 8
	got := ToRepo(t.Context(), repo, access_model.Permission{AccessMode: perm.AccessModeOwner})
	require.NotNil(t, got)
	require.Zero(t, got.OpenIssues)
	require.Zero(t, got.OpenPulls)
	require.False(t, got.HasIssues)
	require.False(t, got.HasPullRequests)
	require.False(t, got.HasWiki)
	require.Nil(t, got.ExternalTracker)
	require.Nil(t, got.InternalTracker)
	require.Equal(t, 7, repo.NumOpenIssues)
	setting.EnterpriseAuthz.Enforce = false
	got = ToRepo(t.Context(), repo, access_model.Permission{AccessMode: perm.AccessModeOwner})
	require.Equal(t, 7, got.OpenIssues)
	require.True(t, got.HasIssues)
}

func TestRepositoryFeatureProjectionDoesNotReuseCancelledPolicy(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	ctx := cache.WithCacheContext(t.Context())
	visible, err := authz_model.RepoFeatureVisible(ctx, authz.FeaturePullRequests, 1, 2, false)
	require.NoError(t, err)
	require.True(t, visible)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	visible, err = authz_model.RepoFeatureVisible(canceled, authz.FeaturePullRequests, 1, 2, false)
	require.ErrorIs(t, err, context.Canceled)
	require.False(t, visible)
}
