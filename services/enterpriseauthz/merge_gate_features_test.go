// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"

	"github.com/stretchr/testify/require"
)

func TestMergeGateFeatureRequirements(t *testing.T) {
	enableMergeGate(t)
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	global := authz_model.Scope{Type: authz_model.ScopeSystem}
	org := authz_model.Scope{Type: authz_model.ScopeOrg, ID: 3}
	repo := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 3}
	for _, metadata := range authz.FeatureCatalog() {
		if metadata.CapabilityKind != "policy_only" {
			continue
		}
		_, err := PutFeatureGrant(t.Context(), admin, global, metadata.Key, FeatureGrantInput{State: authz.FeatureRequired, Config: []byte(`{"check_contexts":["security/global"]}`)})
		require.NoError(t, err)
	}
	_, err := PutFeatureGrant(t.Context(), admin, org, authz.FeatureAIReview, FeatureGrantInput{State: authz.FeatureRequired, Config: []byte(`{"check_contexts":["ai/org"]}`)})
	require.NoError(t, err)
	_, err = PutFeatureGrant(t.Context(), admin, repo, authz.FeatureAIReview, FeatureGrantInput{State: authz.FeatureDisabled, Config: []byte(`{}`)})
	require.ErrorIs(t, err, ErrFeatureParentLocked)
	collected, err := CollectMergeGateFeatureRequirements(t.Context(), 3)
	require.NoError(t, err)
	require.Empty(t, collected.Facts)
	require.Len(t, collected.Contexts, 7)
	missing := authz.EvaluateMergeGateContexts(3, "head", collected.Contexts, nil)
	require.Equal(t, "deny", authz.EvaluateMergeGate(authz.MergeGateInput{Mode: "enforce", Phase: "admission", Facts: missing}).AdmissionDecision)
	for _, requirement := range collected.Contexts {
		require.False(t, requirement.Pattern)
	}
	require.Equal(t, "feature", collected.Contexts[0].Source)
	_, err = PutFeatureGrant(t.Context(), admin, global, authz.FeatureGitleaksScan, FeatureGrantInput{State: authz.FeatureEnabled, Config: []byte(`{"check_contexts":["enabled/not-required"]}`), ExpectedRevision: 1})
	require.NoError(t, err)
	_, err = PutFeatureGrant(t.Context(), admin, global, authz.FeatureTrivyScan, FeatureGrantInput{State: authz.FeatureRequired, Config: []byte(`{}`), ExpectedRevision: 1})
	require.NoError(t, err)
	collected, err = CollectMergeGateFeatureRequirements(t.Context(), 3)
	require.NoError(t, err)
	require.Len(t, collected.Contexts, 5)
	require.Len(t, collected.Facts, 1)
	require.Equal(t, "required_contexts_empty", collected.Facts[0].Code)
	setting.EnterpriseAuthz.FailClosedOnError = false
	_, err = db.GetEngine(t.Context()).Where("`key`=?", authz.FeatureAIReview).Cols("catalog_version").Update(&authz_model.FeatureDefinition{CatalogVersion: 99})
	require.NoError(t, err)
	_, err = CollectMergeGateFeatureRequirements(t.Context(), 3)
	require.ErrorIs(t, err, ErrPolicyStorage)
	setting.EnterpriseMergeGate.Enabled = false
	hook := &disabledMergeGateReads{enabled: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	defer func() { hook.enabled = false }()
	_, err = CollectMergeGateFeatureRequirements(t.Context(), 3)
	require.NoError(t, err)
	require.Zero(t, hook.count)
}

func TestMergeGateNativeRequiredStatusPending(t *testing.T) {
	enableMergeGate(t)
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	_, err := PutFeatureGrant(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeSystem}, authz.FeatureRequiredStatusChecks, FeatureGrantInput{State: authz.FeatureRequired, Config: []byte(`{"check_contexts":["ci/build"]}`)})
	require.NoError(t, err)
	_, err = db.Exec(t.Context(), "DELETE FROM protected_branch WHERE repo_id=3")
	require.NoError(t, err)
	collected, err := CollectMergeGateFeatureRequirements(t.Context(), 3)
	require.NoError(t, err)
	require.Len(t, collected.Contexts, 1)
	require.Len(t, collected.Facts, 1)
	require.Equal(t, "feature_native_pending", collected.Facts[0].Code)
}
