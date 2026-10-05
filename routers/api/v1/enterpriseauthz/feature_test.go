// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"testing"

	authz_model "gitea.dev/models/enterpriseauthz"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func TestFeatureDTOIsolation(t *testing.T) {
	policy := &authz_service.FeaturePolicy{Grant: &authz_model.FeatureGrant{FeatureKey: authz.FeatureGitleaksScan, ScopeType: authz_model.ScopeRepo, ScopeID: 42, State: authz.FeatureRequired, ConfigJSON: `{"check_contexts":["internal/check"]}`, Revision: 7, CreatedBy: 66, UpdatedBy: 77}, Effective: authz.ResolvedFeature{Key: authz.FeatureGitleaksScan, State: authz.FeatureRequired, Source: authz.FeatureScope{Scope: "org", ID: 99}, LockedBy: &authz.FeatureScope{Scope: "org", ID: 99}, Config: authz.FeatureConfig{CheckContexts: []string{"internal/check"}}, CapabilityKind: "policy_only"}, Hash: "hash"}
	encoded, err := json.Marshal(featureEffectiveDTO(policy))
	require.NoError(t, err)
	for _, value := range []string{"internal/check", "99", "66", "77", `"config"`, `"chain"`, "hash"} {
		require.NotContains(t, string(encoded), value)
	}
	dto, err := featurePolicyDTO(policy)
	require.NoError(t, err)
	require.EqualValues(t, 7, dto.Grant.Revision)
	require.Equal(t, []string{"internal/check"}, dto.Grant.Config.CheckContexts)
}

func TestFeaturePutBody(t *testing.T) {
	for _, raw := range []string{`{}`, `{"state":"enabled","config":{},"expected_revision":0}`, `{"state":"enabled","config":{},"expected_revision":0,"actor":1}`, `{"state":"enabled","config":{},"expected_revision":0,"state":"disabled"}`, `{"state":null,"config":{},"expected_revision":0}`, `{"state":"enabled","config":{"secret":"hidden"},"expected_revision":0}`} {
		fields, err := strictObject([]byte(raw), "state", "config", "expected_revision")
		if err == nil {
			_, err = parseFeatureInput(authz.FeatureWiki, fields)
		}
		if raw == `{"state":"enabled","config":{},"expected_revision":0}` {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, authz_service.ErrInvalidPolicy)
		}
	}
}
