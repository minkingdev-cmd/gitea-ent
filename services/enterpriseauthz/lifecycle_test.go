// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz_test

import (
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/organization"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/audit"
	authz_service "gitea.dev/services/enterpriseauthz"
	org_service "gitea.dev/services/org"
	repo_service "gitea.dev/services/repository"
	user_service "gitea.dev/services/user"

	"github.com/stretchr/testify/require"
)

func TestDisabledPolicyLifecycleCleanup(t *testing.T) {
	testPolicyLifecycleCleanup(t, false)
}

func TestShadowPolicyLifecycleCleanup(t *testing.T) {
	testPolicyLifecycleCleanup(t, true)
}

func testPolicyLifecycleCleanup(t *testing.T, enabled bool) {
	t.Helper()
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	setting.EnterpriseWeCom.Enabled = false
	for _, name := range []string{"repository", "user", "team", "organization"} {
		t.Run(name, func(t *testing.T) {
			unittest.PrepareTestEnv(t)
			setting.EnterpriseAuthz.Enabled = true
			role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeSystem, Name: "test", LowerName: "test", Revision: 1}
			subjectType := authz_model.SubjectUser
			subjectID := int64(24)
			scopeType := authz_model.ScopeSystem
			scopeID := int64(0)
			if name == "repository" {
				role.ScopeType = authz_model.ScopeRepo
				role.ScopeID = 1
				scopeType = authz_model.ScopeRepo
				scopeID = 1
				subjectID = 2
			}
			if name == "team" {
				subjectType = authz_model.SubjectTeam
				subjectID = 2
			}
			if name == "organization" {
				role.ScopeType = authz_model.ScopeOrg
				role.ScopeID = 3
				scopeType = authz_model.ScopeOrg
				scopeID = 3
				subjectType = authz_model.SubjectOrg
				subjectID = 3
			}
			require.NoError(t, db.Insert(t.Context(), role))
			_, normalized, hash, err := authz.ParseCondition([]byte(`{}`))
			require.NoError(t, err)
			require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.Delete, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}))
			ownerID := int64(0)
			if scopeType == authz_model.ScopeRepo {
				ownerID = 2
			}
			if scopeType == authz_model.ScopeOrg {
				ownerID = 3
			}
			binding := &authz_model.SubjectRoleBinding{RoleID: role.ID, SubjectType: subjectType, SubjectID: subjectID, ScopeType: scopeType, ScopeID: scopeID, ScopeOwnerID: ownerID}
			require.NoError(t, db.Insert(t.Context(), binding))
			unrelatedRole := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeSystem, Name: "unrelated", LowerName: "unrelated", Revision: 1}
			require.NoError(t, db.Insert(t.Context(), unrelatedRole))
			unrelatedBinding := &authz_model.SubjectRoleBinding{RoleID: unrelatedRole.ID, SubjectType: authz_model.SubjectUser, SubjectID: 5, ScopeType: authz_model.ScopeSystem}
			require.NoError(t, db.Insert(t.Context(), unrelatedBinding))
			var containedTeamBinding *authz_model.SubjectRoleBinding
			if name == "organization" {
				containedTeamBinding = &authz_model.SubjectRoleBinding{RoleID: unrelatedRole.ID, SubjectType: authz_model.SubjectTeam, SubjectID: 2, ScopeType: authz_model.ScopeSystem}
				require.NoError(t, db.Insert(t.Context(), containedTeamBinding))
			}
			actorID, repoID := int64(24), int64(1)
			if name == "repository" {
				actorID = 2
			}
			if name == "team" || name == "organization" {
				actorID, repoID = 4, 3
			}
			input := lifecycleInput(t, actorID, repoID, authz.Delete)
			decision := lifecycleEvidence(t, input)
			require.Equal(t, "allow", decision.CandidateDecision)
			var snapshot struct {
				Definitions []struct {
					ID       int64 `json:"id"`
					Revision int64 `json:"revision"`
				} `json:"definitions"`
				Bindings []struct {
					ID int64 `json:"id"`
				} `json:"bindings"`
			}
			require.NoError(t, json.Unmarshal([]byte(decision.SnapshotJSON), &snapshot))
			definitionIDs := make([]int64, 0, len(snapshot.Definitions))
			for _, definition := range snapshot.Definitions {
				require.EqualValues(t, 1, definition.Revision)
				definitionIDs = append(definitionIDs, definition.ID)
			}
			require.Contains(t, definitionIDs, role.ID)
			bindingIDs := make([]int64, 0, len(snapshot.Bindings))
			for _, entry := range snapshot.Bindings {
				bindingIDs = append(bindingIDs, entry.ID)
			}
			require.Contains(t, bindingIDs, binding.ID)
			var gateRule *authz_model.ProtectedPathRule
			var gateEvidence *authz_model.MergeGateEvaluation
			if name == "repository" || name == "organization" {
				gateRule = &authz_model.ProtectedPathRule{ScopeType: scopeType, ScopeID: scopeID, OwnerID: ownerID, RequiredRoleID: role.ID, ConfigJSON: "{}", Enabled: true, Revision: 1, CreatedBy: 1, UpdatedBy: 1}
				require.NoError(t, db.Insert(t.Context(), gateRule))
				gateEvidence = &authz_model.MergeGateEvaluation{OperationID: "lifecycle-history", Attempt: 1, Phase: "admission", RepoID: repoID, PullID: 1, IssueID: 1, ActorID: actorID, SnapshotJSON: `{"immutable":true}`, SnapshotVersion: 1}
				require.NoError(t, db.Insert(t.Context(), gateEvidence))
			}
			setting.EnterpriseAuthz.Enabled = enabled
			admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
			ctx := audit.WithDoer(t.Context(), admin)
			switch name {
			case "repository":
				require.NoError(t, repo_service.DeleteRepositoryDirectly(ctx, 1))
			case "user":
				require.NoError(t, user_service.DeleteUser(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 24}), true))
			case "team":
				require.NoError(t, org_service.DeleteTeam(ctx, unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})))
			case "organization":
				require.NoError(t, org_service.DeleteOrganization(ctx, unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 3}), true))
			}
			unittest.AssertNotExistsBean(t, &authz_model.SubjectRoleBinding{ID: binding.ID})
			if gateRule != nil {
				stored := unittest.AssertExistsAndLoadBean(t, &authz_model.ProtectedPathRule{ID: gateRule.ID})
				require.True(t, stored.Deleted)
				require.False(t, stored.Enabled)
				require.EqualValues(t, 2, stored.Revision)
				evidence := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{ID: gateEvidence.ID})
				require.Equal(t, *gateEvidence, *evidence)
			}
			storedDecision := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ID: decision.ID})
			require.Equal(t, *decision, *storedDecision)
			if containedTeamBinding != nil {
				unittest.AssertNotExistsBean(t, &authz_model.SubjectRoleBinding{ID: containedTeamBinding.ID})
			}
			unittest.AssertExistsAndLoadBean(t, &authz_model.RoleDefinition{ID: unrelatedRole.ID})
			unittest.AssertExistsAndLoadBean(t, &authz_model.SubjectRoleBinding{ID: unrelatedBinding.ID})
			if name == "repository" || name == "organization" {
				unittest.AssertNotExistsBean(t, &authz_model.RoleDefinition{ID: role.ID})
				unittest.AssertNotExistsBean(t, &authz_model.RolePermission{RoleID: role.ID})
			} else {
				unittest.AssertExistsAndLoadBean(t, &authz_model.RoleDefinition{ID: role.ID})
				unittest.AssertExistsAndLoadBean(t, &authz_model.RolePermission{RoleID: role.ID})
			}
			setting.EnterpriseAuthz.Enabled = true
			history, err := authz_service.GetDecision(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeSystem}, decision.ID)
			require.NoError(t, err)
			require.Equal(t, *decision, *history)
		})
	}
}

func lifecycleInput(t *testing.T, actorID, repoID int64, action authz.Action) authz_service.EvaluateInput {
	t.Helper()
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: actorID})
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repoID})
	permission, err := access_model.GetDoerRepoPermission(t.Context(), repo, actor)
	require.NoError(t, err)
	return authz_service.EvaluateInput{Actor: actor, Repo: repo, Permission: &permission, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, Action: action, ConditionContext: authz.ConditionContext{Source: "api"}}
}

func lifecycleEvidence(t *testing.T, input authz_service.EvaluateInput) *authz_model.DecisionRecord {
	t.Helper()
	ctx, observation := authz_service.BeginObservation(t.Context(), input)
	require.NotNil(t, observation)
	observation.Finish(ctx, authz_service.NativeDenied, authz_service.StageAuthorization)
	return unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: input.Repo.ID, Action: input.Action})
}

func TestPolicyNativeMembershipChangesInvalidateGrantsWithoutChangingHistory(t *testing.T) {
	defer test.MockVariableValue(&setting.EnterpriseAuthz)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	setting.EnterpriseAuthz.Enabled = true
	setting.EnterpriseWeCom.Enabled = false
	for _, name := range []string{"team member", "org member", "team repository", "transfer"} {
		t.Run(name, func(t *testing.T) {
			unittest.PrepareTestEnv(t)
			input := lifecycleInput(t, 4, 3, authz.Delete)
			admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
			ctx := audit.WithDoer(t.Context(), admin)
			require.NoError(t, repo_service.AddOrUpdateCollaborator(ctx, input.Repo, input.Actor, perm.AccessModeRead))
			role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeSystem, Name: "lifecycle", LowerName: "lifecycle", Revision: 1}
			require.NoError(t, db.Insert(t.Context(), role))
			_, normalized, hash, err := authz.ParseCondition([]byte(`{}`))
			require.NoError(t, err)
			require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.Delete, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}))
			binding := &authz_model.SubjectRoleBinding{RoleID: role.ID, SubjectType: authz_model.SubjectTeam, SubjectID: 2, ScopeType: authz_model.ScopeSystem}
			if name == "org member" {
				binding.SubjectType, binding.SubjectID = authz_model.SubjectOrg, 3
			}
			if name == "transfer" {
				binding.SubjectType, binding.SubjectID = authz_model.SubjectUser, input.Actor.ID
				binding.ScopeType, binding.ScopeID, binding.ScopeOwnerID = authz_model.ScopeRepo, input.Repo.ID, input.Repo.OwnerID
			}
			require.NoError(t, db.Insert(t.Context(), binding))
			before := lifecycleEvidence(t, input)
			require.Equal(t, "allow", before.CandidateDecision)
			require.Equal(t, "role_action", before.Reason)
			switch name {
			case "team member":
				require.NoError(t, org_service.RemoveTeamMember(ctx, unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2}), input.Actor))
				unittest.AssertNotExistsBean(t, &organization.TeamUser{TeamID: 2, UID: input.Actor.ID})
			case "org member":
				require.NoError(t, org_service.RemoveOrgUser(ctx, unittest.AssertExistsAndLoadBean(t, &organization.Organization{ID: 3}), input.Actor))
				unittest.AssertNotExistsBean(t, &organization.OrgUser{OrgID: 3, UID: input.Actor.ID})
			case "team repository":
				require.NoError(t, repo_service.RemoveRepositoryFromTeam(ctx, unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2}), input.Repo.ID))
				unittest.AssertNotExistsBean(t, &organization.TeamRepo{TeamID: 2, RepoID: input.Repo.ID})
			case "transfer":
				require.NoError(t, repo_service.AcceptTransferOwnership(ctx, input.Repo, admin))
				transferred := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: input.Repo.ID})
				require.Equal(t, admin.ID, transferred.OwnerID)
			}
			input = lifecycleInput(t, input.Actor.ID, input.Repo.ID, authz.Delete)
			after, err := authz_service.Evaluate(t.Context(), input)
			require.NoError(t, err)
			require.Equal(t, "deny", after.CandidateDecision)
			require.Equal(t, "missing_action", after.Reason)
			require.Empty(t, after.RoleActions)
			require.Empty(t, after.MatchedBindingIDs)
			unittest.AssertExistsAndLoadBean(t, &authz_model.RoleDefinition{ID: role.ID})
			unittest.AssertExistsAndLoadBean(t, &authz_model.SubjectRoleBinding{ID: binding.ID})
			history := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ID: before.ID})
			require.Equal(t, *before, *history)
		})
	}
}
