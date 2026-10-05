// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"strings"
	"testing"

	"gitea.dev/modules/json"

	"github.com/stretchr/testify/require"
)

func TestActionCatalog(t *testing.T) {
	catalog := Catalog()
	require.Len(t, catalog, 20)
	require.Equal(t, 2, CatalogVersion)
	seen := map[Action]bool{}
	for _, entry := range catalog {
		require.False(t, seen[entry.Key])
		seen[entry.Key] = true
		require.NotEmpty(t, entry.Description)
		require.NotEmpty(t, entry.Risk)
		_, exists := LookupAction(entry.Key)
		require.True(t, exists)
		require.NoError(t, ValidatePermission(entry.Key, "allow"))
		require.EqualError(t, ValidatePermission(entry.Key, "deny"), "invalid_effect")
	}
	require.EqualError(t, ValidatePermission("repo.typo", "allow"), "unknown_action")
	grant, exists := LookupAction(ManageFeatureGrant)
	require.True(t, exists)
	require.True(t, grant.Observed)
	require.True(t, grant.EnforceSupported)
	read, exists := LookupAction(ReadCode)
	require.True(t, exists)
	require.Equal(t, []string{"code"}, read.Units)
	pr, exists := LookupAction(CreatePullRequest)
	require.True(t, exists)
	require.Equal(t, []string{"code", "pull_requests"}, pr.Units)
	pr.Units[0] = "invalid"
	pr, _ = LookupAction(CreatePullRequest)
	require.Equal(t, []string{"code", "pull_requests"}, pr.Units)
	roles := BuiltinRoles()
	require.Len(t, roles, 8)
	require.Len(t, roles["owner"], 20)
	require.Equal(t, roles["owner"], roles["platform-admin"])
	require.NotContains(t, roles["reviewer"], PushBranch)
	require.Contains(t, roles["security-maintainer"], ManageCodeowners)
	require.NotContains(t, roles["security-maintainer"], ManageSecret)
	for _, key := range []string{"owner", "platform-admin"} {
		require.Contains(t, roles[key], Action("repo.manage_access"))
	}
	for _, key := range []string{"guest", "reporter", "developer", "reviewer", "maintainer", "security-maintainer"} {
		require.NotContains(t, roles[key], Action("repo.manage_access"))
	}
	roles["owner"][0] = "repo.typo"
	require.NotContains(t, BuiltinRoles()["owner"], Action("repo.typo"))
}

func TestConditions(t *testing.T) {
	condition, canonical, fingerprint, err := ParseCondition([]byte(`{"branch_pattern":["release/*","main","main"],"path_pattern":["src/**"],"request_sources":["api","web"]}`))
	require.NoError(t, err)
	require.Len(t, fingerprint, 64)
	_, again, hash, err := ParseCondition([]byte(`{"request_sources":["web","api"],"path_pattern":["src/**"],"branch_pattern":["main","release/*"]}`))
	require.NoError(t, err)
	require.Equal(t, canonical, again)
	require.Equal(t, fingerprint, hash)
	base := ConditionContext{Branch: "main", BranchKnown: true, Paths: []string{"src/a.go", "src/sub/b.go"}, PathsComplete: true, Source: "api"}
	for _, tc := range []struct {
		name   string
		change func(*ConditionContext)
		want   MatchResult
	}{
		{"all paths", func(*ConditionContext) {}, Matched},
		{"mixed paths", func(c *ConditionContext) { c.Paths = append(c.Paths, "private/a") }, NotMatched},
		{"wrong branch", func(c *ConditionContext) { c.Branch = "dev" }, NotMatched},
		{"wrong source", func(c *ConditionContext) { c.Source = "ssh" }, NotMatched},
		{"unknown branch", func(c *ConditionContext) { c.BranchKnown = false }, Unresolved},
		{"incomplete paths", func(c *ConditionContext) { c.PathsComplete = false }, Unresolved},
		{"empty paths", func(c *ConditionContext) { c.Paths = nil }, Unresolved},
		{"too many paths", func(c *ConditionContext) { c.Paths = make([]string, MaxContextPaths+1) }, Unresolved},
		{"path traversal", func(c *ConditionContext) { c.Paths = []string{"src/../private/a"} }, Unresolved},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := base
			tc.change(&ctx)
			require.Equal(t, tc.want, condition.Match(ctx))
		})
	}
	for _, input := range []string{
		`{"unknown":[]}`, `{"branch_pattern":[]}`, `{"path_pattern":null}`,
		`{"request_sources":["attacker"]}`, `{"path_pattern":["["]}`,
		`{"branch_pattern":[""]}`, `{"branch_pattern":["` + strings.Repeat("x", 257) + `"]}`,
		`{} {}`, `[]`, `null`, `{"branch_pattern":["main"],"branch_pattern":["dev"]}`,
	} {
		_, _, _, err := ParseCondition([]byte(input))
		require.Error(t, err, input)
		require.NotContains(t, err.Error(), input)
	}
	patterns, err := json.Marshal(map[string]any{"path_pattern": make([]string, 17)})
	require.NoError(t, err)
	_, _, _, err = ParseCondition(patterns)
	require.Error(t, err)
	_, _, _, err = ParseCondition([]byte(strings.Repeat(" ", MaxConditionBytes+1)))
	require.Error(t, err)
	plain, _, _, err := ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	require.Equal(t, Matched, plain.Match(ConditionContext{}))
}

func TestBranchConditionRequiresNonemptyBranch(t *testing.T) {
	condition, _, _, err := ParseCondition([]byte(`{"branch_pattern":["*"]}`))
	require.NoError(t, err)
	require.Equal(t, Unresolved, condition.Match(ConditionContext{BranchKnown: true}))
}

func TestRequestSourceCatalog(t *testing.T) {
	sources := RequestSources()
	require.Len(t, sources, 9)
	for _, source := range sources {
		require.True(t, ValidSource(source))
	}
	sources[0] = "invalid"
	require.True(t, ValidSource("web"))
	require.NotContains(t, RequestSources(), "invalid")
}

func TestEnforceCatalogFixedSet(t *testing.T) {
	want := []string{"repo.merge_pull_request", "repo.push_protected_branch", "repo.manage_branch_protection", "repo.manage_codeowners", "repo.manage_webhook", "repo.manage_ci", "repo.manage_secret", "repo.manage_access", "repo.transfer", "repo.archive", "repo.delete", "repo.manage_feature_grant"}
	var entries []struct {
		Key              string `json:"key"`
		EnforceSupported bool   `json:"enforce_supported"`
	}
	data, err := json.Marshal(Catalog())
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &entries))
	var actual []string
	for _, entry := range entries {
		if entry.EnforceSupported {
			actual = append(actual, entry.Key)
		}
	}
	require.ElementsMatch(t, want, actual)
}
