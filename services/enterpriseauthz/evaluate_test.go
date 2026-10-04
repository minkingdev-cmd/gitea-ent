// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"slices"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/organization"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestEvaluateBuiltinRoleMatrixPreservesNativeActions(t *testing.T) {
	for key, actions := range authz.BuiltinRoles() {
		t.Run(key, func(t *testing.T) {
			enableObservation(t)
			input := observationInput(t)
			input.Action = authz.ViewMetadata
			input.Permission.AccessMode = perm.AccessModeRead
			units := []*repo_model.RepoUnit{{Type: unit.TypeCode}, {Type: unit.TypePullRequests}, {Type: unit.TypeActions}}
			input.Permission.SetUnitsWithDefaultAccessMode(units, perm.AccessModeRead)
			role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeSystem, Name: key, LowerName: key, BuiltinKey: &key, Revision: 1}
			require.NoError(t, db.Insert(t.Context(), role))
			_, normalized, hash, err := authz.ParseCondition([]byte(`{}`))
			require.NoError(t, err)
			for _, action := range actions {
				require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: action, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}))
			}
			binding := &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: input.Actor.ID, ScopeType: authz_model.ScopeSystem, RoleID: role.ID}
			require.NoError(t, db.Insert(t.Context(), binding))
			decision, err := Evaluate(t.Context(), input)
			require.NoError(t, err)
			want := slices.Clone(actions)
			slices.Sort(want)
			require.Equal(t, want, decision.RoleActions)
			require.Equal(t, []authz.Action{authz.Clone, authz.ReadCode, authz.ViewMetadata}, decision.NativeActions)
			require.Equal(t, []int64{role.ID}, decision.MatchedRoleIDs)
			require.Equal(t, []int64{binding.ID}, decision.MatchedBindingIDs)
			require.True(t, decision.CandidateOnly)
			require.False(t, decision.SafetyGuardsEvaluated)
			input.Permission.AccessMode = perm.AccessModeWrite
			input.Permission.SetUnitsWithDefaultAccessMode(units, perm.AccessModeWrite)
			input.Action = authz.PushBranch
			decision, err = Evaluate(t.Context(), input)
			require.NoError(t, err)
			require.Equal(t, "allow", decision.CandidateDecision)
			require.Equal(t, "native_action", decision.Reason)
			input.Credential.Write = false
			decision, err = Evaluate(t.Context(), input)
			require.NoError(t, err)
			require.Equal(t, "native_visibility_denied", decision.Reason)
			input.Credential.Write = true
			input.Permission.AccessMode = perm.AccessModeNone
			input.Permission.SetUnitsWithDefaultAccessMode(nil, perm.AccessModeNone)
			decision, err = Evaluate(t.Context(), input)
			require.NoError(t, err)
			require.Equal(t, "native_visibility_denied", decision.Reason)
			require.Empty(t, decision.MatchedRoleIDs)
			require.Empty(t, decision.Snapshot)
		})
	}
}

func TestEvaluateComposesCurrentSubjectsAndDeduplicatesRoles(t *testing.T) {
	enableObservation(t)
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repository := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	_, normalized, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	for _, subject := range []struct {
		typ    authz_model.SubjectType
		id     int64
		action authz.Action
	}{
		{authz_model.SubjectUser, actor.ID, authz.CreateBranch},
		{authz_model.SubjectTeam, 1, authz.PushBranch},
		{authz_model.SubjectOrg, 3, authz.ReviewPullRequest},
	} {
		role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: repository.ID, Name: string(subject.typ), LowerName: string(subject.typ), Revision: 1}
		require.NoError(t, db.Insert(t.Context(), role))
		require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: subject.action, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}))
		require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{SubjectType: subject.typ, SubjectID: subject.id, ScopeType: authz_model.ScopeRepo, ScopeID: repository.ID, ScopeOwnerID: repository.OwnerID, RoleID: role.ID}))
		if subject.typ == authz_model.SubjectTeam {
			require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: actor.ID, ScopeType: authz_model.ScopeRepo, ScopeID: repository.ID, ScopeOwnerID: repository.OwnerID, RoleID: role.ID}))
		}
	}
	permission := access_model.Permission{AccessMode: perm.AccessModeRead}
	permission.SetUnitsWithDefaultAccessMode([]*repo_model.RepoUnit{{Type: unit.TypeCode}, {Type: unit.TypePullRequests}}, perm.AccessModeRead)
	input := EvaluateInput{Actor: actor, Repo: repository, Permission: &permission, Credential: CredentialCeiling{Read: true, Write: true}, Action: authz.PushBranch, ConditionContext: authz.ConditionContext{Source: "api"}}
	decision, err := Evaluate(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, []authz.Action{authz.CreateBranch, authz.PushBranch, authz.ReviewPullRequest}, decision.RoleActions)
	require.Len(t, decision.MatchedRoleIDs, 1)
	require.Len(t, decision.MatchedBindingIDs, 2)
	_, err = db.GetEngine(t.Context()).Where("uid = ? AND team_id = ?", actor.ID, 1).Delete(new(organization.TeamUser))
	require.NoError(t, err)
	decision, err = Evaluate(t.Context(), input)
	require.NoError(t, err)
	require.Len(t, decision.MatchedRoleIDs, 1)
	require.Len(t, decision.MatchedBindingIDs, 1)
	_, err = db.GetEngine(t.Context()).Where("uid = ? AND org_id = ?", actor.ID, 3).Delete(new(organization.OrgUser))
	require.NoError(t, err)
	decision, err = Evaluate(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, []authz.Action{authz.CreateBranch, authz.PushBranch}, decision.RoleActions)
	for _, credential := range []struct {
		actor      *user_model.User
		nativeOnly bool
	}{
		{nil, false},
		{actor, true},
		{user_model.NewActionsUserWithTaskID(1), true},
		{user_model.NewDeployKeyUserWithKeyID(1), true},
	} {
		input.Actor, input.Credential.NativeOnly = credential.actor, credential.nativeOnly
		decision, err = Evaluate(t.Context(), input)
		require.NoError(t, err)
		require.Equal(t, "missing_action", decision.Reason)
		require.Empty(t, decision.RoleActions)
	}
}

func TestEvaluateCombinesNativeAndRoleActionsWithoutBypassingUnits(t *testing.T) {
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	setting.EnterpriseAuthz.Enabled = true
	require.NoError(t, unittest.PrepareTestDatabase())
	_, normalized, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: 1, Name: "Builder", LowerName: "builder", Revision: 1}
	require.NoError(t, db.Insert(t.Context(), role))
	require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.CreateBranch, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}))
	repository, err := repo_model.GetRepositoryByID(t.Context(), 1)
	require.NoError(t, err)
	actor, err := user_model.GetUserByID(t.Context(), 2)
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: actor.ID, ScopeType: authz_model.ScopeRepo, ScopeID: repository.ID, ScopeOwnerID: repository.OwnerID, RoleID: role.ID}))
	role.ScopeID = repository.ID
	permission := access_model.Permission{AccessMode: perm.AccessModeRead}
	permission.SetUnitsWithDefaultAccessMode([]*repo_model.RepoUnit{{Type: unit.TypeCode}}, perm.AccessModeRead)

	decision, err := Evaluate(t.Context(), EvaluateInput{Actor: actor, Repo: repository, Permission: &permission, Credential: CredentialCeiling{Read: true, Write: true}, Action: authz.CreateBranch, ConditionContext: authz.ConditionContext{Source: "web"}})
	require.NoError(t, err)
	require.Equal(t, "allow", decision.CandidateDecision)
	require.Contains(t, decision.RoleActions, authz.CreateBranch)
	require.NotContains(t, decision.NativeActions, authz.CreateBranch)

	permission.SetUnitsWithDefaultAccessMode([]*repo_model.RepoUnit{{Type: unit.TypeIssues}}, perm.AccessModeRead)
	decision, err = Evaluate(t.Context(), EvaluateInput{Actor: actor, Repo: repository, Permission: &permission, Credential: CredentialCeiling{Read: true, Write: true}, Action: authz.CreateBranch, ConditionContext: authz.ConditionContext{Source: "web"}})
	require.NoError(t, err)
	require.Equal(t, "deny", decision.CandidateDecision)
	require.Equal(t, "native_visibility_denied", decision.Reason)
}

func TestEvaluateResolvesCurrentTeamMembershipAndRepositoryBinding(t *testing.T) {
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	setting.EnterpriseAuthz.Enabled = true
	require.NoError(t, unittest.PrepareTestDatabase())
	_, normalized, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeOrg, ScopeID: 3, Name: "Builder", LowerName: "builder", Revision: 1}
	require.NoError(t, db.Insert(t.Context(), role))
	require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.CreateBranch, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}))
	require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectTeam, SubjectID: 1, ScopeType: authz_model.ScopeOrg, ScopeID: 3, ScopeOwnerID: 3, RoleID: role.ID}))
	repository, err := repo_model.GetRepositoryByID(t.Context(), 3)
	require.NoError(t, err)
	actor, err := user_model.GetUserByID(t.Context(), 2)
	require.NoError(t, err)
	permission := access_model.Permission{AccessMode: perm.AccessModeRead}
	permission.SetUnitsWithDefaultAccessMode([]*repo_model.RepoUnit{{Type: unit.TypeCode}}, perm.AccessModeRead)
	input := EvaluateInput{Actor: actor, Repo: repository, Permission: &permission, Credential: CredentialCeiling{Read: true, Write: true}, Action: authz.CreateBranch, ConditionContext: authz.ConditionContext{Source: "api"}}
	decision, err := Evaluate(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, "role_action", decision.Reason)
	require.NoError(t, organization.RemoveTeamRepo(t.Context(), 1, 3))
	decision, err = Evaluate(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, "deny", decision.CandidateDecision)
	require.Equal(t, "missing_action", decision.Reason)
}

func TestEvaluateSnapshotExplainsUnmatchedPermissionsWithoutPrivateContext(t *testing.T) {
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	setting.EnterpriseAuthz.Enabled = true
	require.NoError(t, unittest.PrepareTestDatabase())
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repository := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: 1, Name: "Conditional", LowerName: "conditional", Revision: 7}
	require.NoError(t, db.Insert(t.Context(), role))
	_, normalized, hash, err := authz.ParseCondition([]byte(`{"branch_pattern":["private-release/*"],"path_pattern":["private-docs/**"],"request_sources":["api"]}`))
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.CreateBranch, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}))
	binding := &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: actor.ID, ScopeType: authz_model.ScopeRepo, ScopeID: 1, ScopeOwnerID: repository.OwnerID, RoleID: role.ID}
	require.NoError(t, db.Insert(t.Context(), binding))
	permission := access_model.Permission{AccessMode: perm.AccessModeRead}
	permission.SetUnitsWithDefaultAccessMode([]*repo_model.RepoUnit{{Type: unit.TypeCode}}, perm.AccessModeRead)
	decision, err := Evaluate(t.Context(), EvaluateInput{Actor: actor, Repo: repository, Permission: &permission, Credential: CredentialCeiling{Read: true, Write: true, Reference: "access-token:42"}, Action: authz.CreateBranch, ConditionContext: authz.ConditionContext{Source: "api", Branch: "private-release/topic", BranchKnown: true, Paths: []string{"private-src/secret.txt"}, PathsComplete: true}})
	require.NoError(t, err)
	require.Equal(t, "condition_not_matched", decision.Reason)
	var snapshot roleSnapshot
	require.NoError(t, json.Unmarshal([]byte(decision.Snapshot), &snapshot))
	require.Equal(t, 2, snapshot.CatalogVersion)
	require.Equal(t, repository.OwnerID, snapshot.OwnerID)
	require.Equal(t, "access-token:42", snapshot.Credential.Reference)
	require.Len(t, snapshot.Roles, 1)
	entry := snapshot.Roles[0]
	require.EqualValues(t, 7, entry.Revision)
	require.Equal(t, "allow", entry.Effect)
	require.Equal(t, "not_matched", entry.Result)
	require.Equal(t, hash, entry.ConditionHash)
	require.NotContains(t, decision.Snapshot, "private-")
	for _, tt := range []struct {
		name, source, branch, reason string
		paths                        []string
		branchKnown, pathsComplete   bool
	}{
		{"all match", "api", "private-release/topic", "role_action", []string{"private-docs/a.md", "private-docs/b.md"}, true, true},
		{"source AND", "web", "private-release/topic", "condition_not_matched", []string{"private-docs/a.md"}, true, true},
		{"branch AND", "api", "other/topic", "condition_not_matched", []string{"private-docs/a.md"}, true, true},
		{"all paths", "api", "private-release/topic", "condition_not_matched", []string{"private-docs/a.md", "private-src/a.go"}, true, true},
		{"unknown branch", "api", "", "condition_unresolved", []string{"private-docs/a.md"}, false, true},
		{"unknown paths", "api", "private-release/topic", "condition_unresolved", []string{"private-docs/a.md"}, true, false},
		{"empty paths", "api", "private-release/topic", "condition_unresolved", nil, true, true},
		{"path overflow", "api", "private-release/topic", "condition_unresolved", make([]string, authz.MaxContextPaths+1), true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := Evaluate(t.Context(), EvaluateInput{Actor: actor, Repo: repository, Permission: &permission, Credential: CredentialCeiling{Read: true, Write: true}, Action: authz.CreateBranch, ConditionContext: authz.ConditionContext{Source: tt.source, Branch: tt.branch, BranchKnown: tt.branchKnown, Paths: tt.paths, PathsComplete: tt.pathsComplete}})
			require.NoError(t, err)
			require.Equal(t, tt.reason, decision.Reason)
			require.NotContains(t, decision.Snapshot, "private-")
		})
	}
}

func TestEvaluateRejectsInvalidBindingScopeAndUnknownPersistedAction(t *testing.T) {
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	setting.EnterpriseAuthz.Enabled = true
	require.NoError(t, unittest.PrepareTestDatabase())
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repository := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: 1, Name: "Local", LowerName: "local", Revision: 1}
	require.NoError(t, db.Insert(t.Context(), role))
	_, normalized, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	permissionRow := &authz_model.RolePermission{RoleID: role.ID, Action: authz.CreateBranch, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}
	require.NoError(t, db.Insert(t.Context(), permissionRow))
	binding := &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: actor.ID, ScopeType: authz_model.ScopeSystem, RoleID: role.ID}
	require.NoError(t, db.Insert(t.Context(), binding))
	permission := access_model.Permission{AccessMode: perm.AccessModeRead}
	permission.SetUnitsWithDefaultAccessMode([]*repo_model.RepoUnit{{Type: unit.TypeCode}}, perm.AccessModeRead)
	input := EvaluateInput{Actor: actor, Repo: repository, Permission: &permission, Credential: CredentialCeiling{Read: true, Write: true}, Action: authz.CreateBranch, ConditionContext: authz.ConditionContext{Source: "api"}}
	decision, err := Evaluate(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, "deny", decision.CandidateDecision)
	require.Equal(t, "missing_action", decision.Reason)
	binding.ScopeType, binding.ScopeID, binding.ScopeOwnerID = authz_model.ScopeRepo, repository.ID, repository.OwnerID
	_, err = db.GetEngine(t.Context()).ID(binding.ID).Cols("scope_type", "scope_id", "scope_owner_id").Update(binding)
	require.NoError(t, err)
	permissionRow.Action = "repo.not_registered"
	_, err = db.GetEngine(t.Context()).ID(permissionRow.ID).Cols("action").Update(permissionRow)
	require.NoError(t, err)
	decision, err = Evaluate(t.Context(), input)
	require.EqualError(t, err, "policy_read_failed")
	require.Equal(t, "error", decision.CandidateDecision)
}

func TestEvaluateProducesStableSnapshotForIdenticalContext(t *testing.T) {
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	setting.EnterpriseAuthz.Enabled = true
	require.NoError(t, unittest.PrepareTestDatabase())
	input := observationInput(t)
	first, err := Evaluate(t.Context(), input)
	require.NoError(t, err)
	for range 10 {
		next, err := Evaluate(t.Context(), input)
		require.NoError(t, err)
		require.Equal(t, first.Snapshot, next.Snapshot)
	}
}

func TestEvaluateMissingReferencedRoleIsPolicyError(t *testing.T) {
	enableObservation(t)
	input := observationInput(t)
	require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: input.Actor.ID, ScopeType: authz_model.ScopeRepo, ScopeID: input.Repo.ID, ScopeOwnerID: input.Repo.OwnerID, RoleID: 99999}))
	decision, err := Evaluate(t.Context(), input)
	require.EqualError(t, err, "policy_read_failed")
	require.Equal(t, "error", decision.CandidateDecision)
	require.Empty(t, decision.MatchedRoleIDs)
}

func TestEvaluateRefreshesActorAndOwnerInPolicySnapshot(t *testing.T) {
	for _, mutation := range []string{"transfer", "inactive", "prohibit", "restricted", "archived"} {
		t.Run(mutation, func(t *testing.T) {
			enableObservation(t)
			input := observationInput(t)
			role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: input.Repo.ID, Name: "Current", LowerName: "current", Revision: 1}
			require.NoError(t, db.Insert(t.Context(), role))
			_, normalized, hash, err := authz.ParseCondition([]byte(`{}`))
			require.NoError(t, err)
			require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.CreateBranch, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}))
			require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: input.Actor.ID, ScopeType: authz_model.ScopeRepo, ScopeID: input.Repo.ID, ScopeOwnerID: input.Repo.OwnerID, RoleID: role.ID}))
			input.Action = authz.CreateBranch
			input.Permission.AccessMode = perm.AccessModeRead
			input.Permission.SetUnitsWithDefaultAccessMode([]*repo_model.RepoUnit{{Type: unit.TypeCode}}, perm.AccessModeRead)
			first, err := Evaluate(t.Context(), input)
			require.NoError(t, err)
			require.Equal(t, "role_action", first.Reason)
			expectedReason := "missing_action"
			switch mutation {
			case "transfer":
				_, err = db.GetEngine(t.Context()).ID(input.Repo.ID).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 4})
			case "inactive":
				_, err = db.GetEngine(t.Context()).ID(input.Actor.ID).Cols("is_active").Update(&user_model.User{IsActive: false})
				expectedReason = "actor_inactive"
			case "prohibit":
				_, err = db.GetEngine(t.Context()).ID(input.Actor.ID).Cols("prohibit_login").Update(&user_model.User{ProhibitLogin: true})
				expectedReason = "actor_inactive"
			case "restricted":
				_, err = db.GetEngine(t.Context()).ID(input.Actor.ID).Cols("is_restricted").Update(&user_model.User{IsRestricted: true})
			case "archived":
				_, err = db.GetEngine(t.Context()).ID(input.Repo.ID).Cols("is_archived").Update(&repo_model.Repository{IsArchived: true})
				expectedReason = "native_visibility_denied"
			}
			require.NoError(t, err)
			current, err := Evaluate(t.Context(), input)
			require.NoError(t, err)
			require.Equal(t, "deny", current.CandidateDecision)
			require.Equal(t, expectedReason, current.Reason)
			require.Empty(t, current.MatchedBindingIDs)
			var snapshot roleSnapshot
			require.NoError(t, json.Unmarshal([]byte(current.Snapshot), &snapshot))
			if mutation == "transfer" {
				require.EqualValues(t, 4, snapshot.OwnerID)
			}
			if mutation == "inactive" || mutation == "prohibit" || mutation == "restricted" {
				require.False(t, snapshot.RoleEligible)
			}
		})
	}
}
