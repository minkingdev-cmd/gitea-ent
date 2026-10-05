// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFeatureCatalog(t *testing.T) {
	catalog := FeatureCatalog()
	require.Len(t, catalog, 13)
	seen := map[FeatureKey]bool{}
	for _, feature := range catalog {
		require.False(t, seen[feature.Key])
		seen[feature.Key] = true
		require.NotEmpty(t, feature.Description)
		require.Equal(t, []string{"global", "org", "repo"}, feature.SupportedScopes)
		require.Equal(t, 1, feature.ConfigSchemaVersion)
		if feature.CapabilityKind == "policy_only" {
			require.Equal(t, FeatureDisabled, feature.DefaultState)
		} else {
			require.Equal(t, "native_gate", feature.CapabilityKind)
			require.Equal(t, FeatureEnabled, feature.DefaultState)
		}
	}
	require.True(t, seen[FeatureAIReview])
	require.True(t, seen[FeatureRequiredStatusChecks])
	catalog[0].SupportedScopes[0] = "user"
	require.Equal(t, "global", FeatureCatalog()[0].SupportedScopes[0])
	_, found := LookupFeature("feature.typo")
	require.False(t, found)
}

func TestFeatureHierarchy(t *testing.T) {
	definition, found := LookupFeature(FeatureIssues)
	require.True(t, found)
	states := []FeatureState{FeatureInherited, FeatureEnabled, FeatureDisabled, FeatureRequired}
	for _, global := range states {
		for _, org := range states {
			for _, repo := range states {
				t.Run(string(global)+"/"+string(org)+"/"+string(repo), func(t *testing.T) {
					layers := []FeatureLayer{{Scope: "global", State: global}, {Scope: "org", ID: 1, State: org}, {Scope: "repo", ID: 2, State: repo}}
					want := FeatureEnabled
					for _, state := range []FeatureState{global, org, repo} {
						if state != FeatureInherited {
							want = state
							if state == FeatureDisabled || state == FeatureRequired {
								break
							}
						}
					}
					result, err := ResolveFeature(definition, layers)
					require.NoError(t, err)
					require.Equal(t, want, result.State)
				})
			}
		}
	}
	result, err := ResolveFeature(definition, []FeatureLayer{{Scope: "global", State: FeatureRequired}, {Scope: "repo", ID: 2, State: FeatureDisabled}})
	require.NoError(t, err)
	require.Equal(t, "global", result.LockedBy.Scope)
	require.Len(t, result.Conflicts, 1)
	require.Equal(t, "repo", result.Conflicts[0].Scope)
	require.Equal(t, FeatureRequired, result.State)
	_, err = ResolveFeature(definition, []FeatureLayer{{Scope: "user", ID: 2, State: FeatureEnabled}})
	require.Error(t, err)
	_, err = ResolveFeature(definition, []FeatureLayer{{Scope: "repo", ID: 2, State: "typo"}})
	require.Error(t, err)
}

func TestFeatureConfig(t *testing.T) {
	config, canonical, err := ParseFeatureConfig(FeatureGitleaksScan, FeatureRequired, []byte(`{"check_contexts":["security/gitleaks","ci/build","ci/build"]}`))
	require.NoError(t, err)
	require.Equal(t, []string{"ci/build", "security/gitleaks"}, config.CheckContexts)
	require.JSONEq(t, `{"check_contexts":["ci/build","security/gitleaks"]}`, canonical)
	for _, raw := range []string{
		`null`, `[]`, `{} {}`, `{"unknown":1}`, `{"access_token":"secret"}`,
		`{"check_contexts":null}`, `{"check_contexts":[""]}`, `{"check_contexts":[" x"]}`,
		`{"check_contexts":["x\ny"]}`, `{"check_contexts":["x"],"check_contexts":["y"]}`,
		`{"check_contexts":["` + strings.Repeat("x", 129) + `"]}`,
		`{"check_contexts":[` + strings.Repeat(`"x",`, 64) + `"y"]}`,
		strings.Repeat(" ", 16*1024+1), string([]byte{0xff}),
	} {
		_, _, err := ParseFeatureConfig(FeatureGitleaksScan, FeatureEnabled, []byte(raw))
		require.EqualError(t, err, "invalid_feature_config", raw)
	}
	_, _, err = ParseFeatureConfig(FeatureIssues, FeatureEnabled, []byte(`{"check_contexts":["x"]}`))
	require.Error(t, err)
	_, _, err = ParseFeatureConfig(FeatureAIReview, FeatureInherited, []byte(`{"check_contexts":["x"]}`))
	require.Error(t, err)
	_, _, err = ParseFeatureConfig("feature.typo", FeatureEnabled, []byte(`{}`))
	require.Error(t, err)
}

func TestRequiredFeatureContexts(t *testing.T) {
	definition, _ := LookupFeature(FeatureGitleaksScan)
	layers := []FeatureLayer{
		{Scope: "global", State: FeatureRequired, Config: FeatureConfig{CheckContexts: []string{"security/gitleaks"}}},
		{Scope: "org", ID: 1, State: FeatureRequired, Config: FeatureConfig{CheckContexts: []string{"ci/org"}}},
		{Scope: "repo", ID: 2, State: FeatureEnabled, Config: FeatureConfig{CheckContexts: []string{"ci/repo"}}},
	}
	result, err := ResolveFeature(definition, layers)
	require.NoError(t, err)
	require.Equal(t, FeatureRequired, result.State)
	require.Equal(t, []string{"ci/org", "ci/repo", "security/gitleaks"}, result.Config.CheckContexts)
	layers[0].State = FeatureDisabled
	result, err = ResolveFeature(definition, layers)
	require.NoError(t, err)
	require.Empty(t, result.Config.CheckContexts)
	require.Len(t, result.Conflicts, 2)
	layers[0].State = FeatureEnabled
	layers[1].State = FeatureEnabled
	result, err = ResolveFeature(definition, layers)
	require.NoError(t, err)
	require.Equal(t, []string{"ci/repo"}, result.Config.CheckContexts)
	result, err = ResolveFeature(definition, nil)
	require.NoError(t, err)
	require.Equal(t, FeatureDisabled, result.State)
	result, err = ResolveFeature(definition, []FeatureLayer{{Scope: "repo", ID: 2, State: FeatureEnabled}})
	require.NoError(t, err)
	require.Equal(t, FeatureEnabled, result.State)
}
