// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

func TestFeatureConfigurationLockOrder(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enforce = true
	hook := &featureConfigurationLocks{enabled: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	t.Cleanup(func() { hook.enabled = false })
	require.NoError(t, WithRepoFeatureConfiguration(t.Context(), 1, []repo_model.RepoUnit{{Type: unit.TypeWiki}}, nil, func(tx context.Context) error {
		return authz_model.LockFeatures(tx, []authz.FeatureKey{authz.FeatureIssues, authz.FeaturePackages, authz.FeaturePullRequests, authz.FeatureWiki})
	}))
	require.GreaterOrEqual(t, len(hook.keys), 4)
	require.Equal(t, []authz.FeatureKey{authz.FeatureIssues, authz.FeaturePackages, authz.FeaturePullRequests, authz.FeatureWiki}, hook.keys[:4])
}

type featureConfigurationLocks struct {
	enabled bool
	keys    []authz.FeatureKey
}

func (h *featureConfigurationLocks) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.enabled && strings.HasPrefix(c.SQL, "UPDATE") && strings.Contains(c.SQL, "enterprise_feature_definition") && strings.Contains(c.SQL, "policy_revision=policy_revision") && len(c.Args) == 1 {
		key, ok := c.Args[0].(authz.FeatureKey)
		if !ok {
			return c.Ctx, errors.New("unexpected feature lock key type")
		}
		h.keys = append(h.keys, key)
	}
	return c.Ctx, nil
}

func (*featureConfigurationLocks) AfterProcess(*contexts.ContextHook) error { return nil }

func TestMergeGateConfigurationLockOrder(t *testing.T) {
	enableMergeGate(t)
	setting.EnterpriseAuthz.Enforce = true
	hook := &mergeGateScopeLocks{enabled: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	t.Cleanup(func() { hook.enabled = false })
	require.NoError(t, WithRepoFeatureConfiguration(t.Context(), 1, nil, nil, func(context.Context) error { return nil }))
	require.GreaterOrEqual(t, len(hook.tables), 2)
	require.Equal(t, []string{"feature", "repository"}, hook.tables[:2])
}

type mergeGateScopeLocks struct {
	enabled bool
	tables  []string
}

func (h *mergeGateScopeLocks) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.enabled && strings.HasPrefix(c.SQL, "UPDATE") {
		if strings.Contains(c.SQL, "enterprise_feature_definition") {
			h.tables = append(h.tables, "feature")
		} else if strings.Contains(c.SQL, "repository") && strings.Contains(c.SQL, "id=id") {
			h.tables = append(h.tables, "repository")
		}
	}
	return c.Ctx, nil
}

func (*mergeGateScopeLocks) AfterProcess(*contexts.ContextHook) error { return nil }
