// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"strconv"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func protectionFeatureContext(t *testing.T, state authz.FeatureState, target string) (context.Context, *repo_model.Repository) {
	t.Helper()
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureRequiredStatusChecks, ScopeType: authz_model.ScopeSystem, State: state, ConfigJSON: `{"check_contexts":["security/gitleaks"]}`, Revision: 1}))
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	intent := authz_service.SettingsIntent(authz.ManageBranchProtection, target)
	var inputs []authz_service.ExecutionInput
	for _, action := range []authz.Action{authz.ManageBranchProtection, authz.ManageCI} {
		inputs = append(inputs, authz_service.ExecutionInput{EvaluateInput: authz_service.EvaluateInput{Actor: actor, Repo: repo, Action: action, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "web"}}, Intent: intent})
	}
	ctx, admission, err := authz_service.BeginExecution(t.Context(), inputs)
	require.NoError(t, err)
	require.NoError(t, admission.Start(ctx))
	t.Cleanup(func() { admission.Finish(ctx, authz_service.NativeFailed, authz_service.StageOperation) })
	return ctx, repo
}

func TestProtectedBranchFeatureChecks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		state  authz.FeatureState
		change string
		denied bool
	}{
		{"disabled-add", authz.FeatureDisabled, "add", true},
		{"disabled-disable", authz.FeatureDisabled, "disable", true},
		{"disabled-delete", authz.FeatureDisabled, "delete", true},
		{"disabled-other-field", authz.FeatureDisabled, "other", false},
		{"disabled-reorder-contexts", authz.FeatureDisabled, "reorder", false},
		{"required-disable", authz.FeatureRequired, "disable", true},
		{"required-delete", authz.FeatureRequired, "delete", true},
		{"required-remove-mandatory", authz.FeatureRequired, "remove", true},
		{"required-add", authz.FeatureRequired, "add", false},
		{"required-other-field", authz.FeatureRequired, "other", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, repo := protectionFeatureContext(t, tc.state, "feature-test")
			old := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "feature-test", EnableStatusCheck: true, StatusCheckContexts: []string{"ci/build", "security/gitleaks"}}
			require.NoError(t, db.Insert(ctx, old))
			next := *old
			switch tc.change {
			case "add":
				next.StatusCheckContexts = []string{"ci/build", "security/gitleaks", "ci/test"}
			case "disable":
				next.EnableStatusCheck = false
			case "remove":
				next.StatusCheckContexts = []string{"ci/build"}
			case "other":
				next.RequiredApprovals = 2
			case "reorder":
				next.StatusCheckContexts = []string{"security/gitleaks", "ci/build"}
			}
			var err error
			if tc.change == "delete" {
				err = DeleteProtectedBranch(ctx, repo, old.ID)
			} else {
				err = UpdateProtectedBranch(ctx, repo, &next, git_model.WhitelistOptions{})
			}
			if tc.denied {
				require.Error(t, err)
				stored := unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: old.ID})
				require.True(t, stored.EnableStatusCheck)
				require.Equal(t, []string{"ci/build", "security/gitleaks"}, stored.StatusCheckContexts)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestProtectedBranchFeaturePriority(t *testing.T) {
	for _, state := range []authz.FeatureState{authz.FeatureDisabled, authz.FeatureRequired} {
		t.Run(string(state), func(t *testing.T) {
			ctx, repo := protectionFeatureContext(t, state, "priority")
			strong := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "release/**", Priority: 1, EnableStatusCheck: true, StatusCheckContexts: []string{"security/gitleaks"}}
			weak := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "release/*", Priority: 2}
			require.NoError(t, db.Insert(ctx, strong, weak))
			require.Error(t, UpdateProtectBranchPriorities(ctx, repo, []int64{weak.ID, strong.ID}))
			require.EqualValues(t, 1, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: strong.ID}).Priority)
		})
	}
}

func TestProtectedBranchFeaturePriorityField(t *testing.T) {
	for _, state := range []authz.FeatureState{authz.FeatureDisabled, authz.FeatureRequired} {
		t.Run(string(state), func(t *testing.T) {
			ctx, repo := protectionFeatureContext(t, state, "release/*")
			strong := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "release/**", Priority: 1, EnableStatusCheck: true, StatusCheckContexts: []string{"security/gitleaks"}}
			weak := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "release/*", Priority: 2}
			require.NoError(t, db.Insert(ctx, strong, weak))
			next := *weak
			next.Priority = 0
			require.Error(t, UpdateProtectedBranch(ctx, repo, &next, git_model.WhitelistOptions{}))
			require.EqualValues(t, 2, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: weak.ID}).Priority)
		})
	}
}

func TestProtectedBranchFeatureNewShadowingRule(t *testing.T) {
	for _, state := range []authz.FeatureState{authz.FeatureDisabled, authz.FeatureRequired} {
		t.Run(string(state), func(t *testing.T) {
			ctx, repo := protectionFeatureContext(t, state, "release/*")
			strong := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "release/**", Priority: 2, EnableStatusCheck: true, StatusCheckContexts: []string{"security/gitleaks"}}
			require.NoError(t, db.Insert(ctx, strong))
			weak := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "release/*", Priority: 1}
			require.Error(t, UpdateProtectedBranch(ctx, repo, weak, git_model.WhitelistOptions{}))
			unittest.AssertNotExistsBean(t, &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "release/*"})
		})
	}
}

func TestProtectedBranchFeatureRequiredPendingAndStrengthening(t *testing.T) {
	ctx, repo := protectionFeatureContext(t, authz.FeatureRequired, "pending")
	empty := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "pending"}
	require.NoError(t, UpdateProtectedBranch(ctx, repo, empty, git_model.WhitelistOptions{}))
	next := *empty
	next.EnableStatusCheck = true
	next.StatusCheckContexts = []string{"ci/build"}
	require.Error(t, UpdateProtectedBranch(ctx, repo, &next, git_model.WhitelistOptions{}))
	next.StatusCheckContexts = []string{"ci/build", "security/gitleaks"}
	require.NoError(t, UpdateProtectedBranch(ctx, repo, &next, git_model.WhitelistOptions{}))
	require.True(t, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: next.ID}).EnableStatusCheck)
}

func TestProtectedBranchFeatureShadowAndDisabled(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(strconv.FormatBool(enabled), func(t *testing.T) {
			ctx, repo := protectionFeatureContext(t, authz.FeatureRequired, "native-checks")
			old := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "native-checks", EnableStatusCheck: true, StatusCheckContexts: []string{"security/gitleaks"}}
			require.NoError(t, db.Insert(ctx, old))
			setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce = enabled, false
			next := *old
			next.EnableStatusCheck = false
			require.NoError(t, UpdateProtectedBranch(ctx, repo, &next, git_model.WhitelistOptions{}))
			require.False(t, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: old.ID}).EnableStatusCheck)
			if enabled {
				var events []audit_model.Event
				require.NoError(t, db.GetEngine(t.Context()).Where("action=? AND metadata LIKE ?", audit_model.EnterpriseFeatureDecision, `%"reason":"feature_status_checks_locked"%`).Find(&events))
				require.Len(t, events, 1)
				require.Contains(t, events[0].Metadata, `"actual_decision":"native"`)
			}
		})
	}
}

func TestProtectedBranchFeatureIndependentRulePriority(t *testing.T) {
	for _, state := range []authz.FeatureState{authz.FeatureDisabled, authz.FeatureRequired} {
		t.Run(string(state), func(t *testing.T) {
			ctx, repo := protectionFeatureContext(t, state, "priority")
			strong := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "main", Priority: 1, EnableStatusCheck: true, StatusCheckContexts: []string{"security/gitleaks"}}
			independent := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "develop", Priority: 2}
			require.NoError(t, db.Insert(ctx, strong, independent))
			require.NoError(t, UpdateProtectBranchPriorities(ctx, repo, []int64{independent.ID, strong.ID}))
		})
	}
}

func TestProtectedBranchFeaturePriorityStrengthening(t *testing.T) {
	ctx, repo := protectionFeatureContext(t, authz.FeatureRequired, "priority")
	current := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "release/**", Priority: 1, EnableStatusCheck: true, StatusCheckContexts: []string{"security/gitleaks"}}
	stronger := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "release/*", Priority: 2, EnableStatusCheck: true, StatusCheckContexts: []string{"security/gitleaks", "ci/build"}}
	require.NoError(t, db.Insert(ctx, current, stronger))
	require.NoError(t, UpdateProtectBranchPriorities(ctx, repo, []int64{stronger.ID, current.ID}))
	require.EqualValues(t, 1, unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{ID: stronger.ID}).Priority)
}
