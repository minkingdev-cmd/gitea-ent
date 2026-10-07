// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"testing"

	"gitea.dev/models/db"
	"gitea.dev/models/unittest"

	"github.com/stretchr/testify/require"
)

func TestPolicyUniquenessAndCleanup(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	role := &RoleDefinition{ScopeType: ScopeRepo, ScopeID: 1, Name: "Reader", LowerName: "reader", Revision: 1}
	require.NoError(t, db.Insert(ctx, role))
	require.NoError(t, db.Insert(ctx, &RoleDefinition{ScopeType: ScopeRepo, ScopeID: 2, Name: "Reader", LowerName: "reader", Revision: 1}))
	require.Error(t, db.Insert(ctx, &RoleDefinition{ScopeType: ScopeRepo, ScopeID: 1, Name: "Reader", LowerName: "reader", Revision: 1}))
	permission := &RolePermission{RoleID: role.ID, Action: "repo.clone", Effect: "allow", ConditionJSON: "{}", ConditionHash: "hash"}
	require.NoError(t, db.Insert(ctx, permission))
	require.Error(t, db.Insert(ctx, &RolePermission{RoleID: role.ID, Action: permission.Action, Effect: permission.Effect, ConditionJSON: "{}", ConditionHash: permission.ConditionHash}))
	binding := &SubjectRoleBinding{SubjectType: SubjectUser, SubjectID: 2, ScopeType: ScopeRepo, ScopeID: 1, ScopeOwnerID: 2, RoleID: role.ID}
	require.NoError(t, db.Insert(ctx, binding))
	require.Error(t, db.Insert(ctx, &SubjectRoleBinding{SubjectType: SubjectUser, SubjectID: 2, ScopeType: ScopeRepo, ScopeID: 1, ScopeOwnerID: 2, RoleID: role.ID}))
	decision := &DecisionRecord{ObservationID: "observation-1", OperationID: "operation-1", RepoID: 1, OwnerID: 2, ActorID: 2, Action: "repo.clone", RequestSource: "api", CandidateDecision: "allow", NativeOutcome: "unknown", SnapshotJSON: "{}"}
	require.NoError(t, db.Insert(ctx, decision))
	copyDecision := *decision
	copyDecision.ID = 0
	require.Error(t, db.Insert(ctx, &copyDecision))
	rule := &ProtectedPathRule{ScopeType: ScopeRepo, ScopeID: 1, OwnerID: 2, RequiredRoleID: role.ID, ConfigJSON: `{"path_pattern":"**","required_role_id":1,"check_contexts":[],"enabled":true}`, Enabled: true, Revision: 1, CreatedBy: 2, UpdatedBy: 2}
	require.NoError(t, db.Insert(ctx, rule))
	evaluation := &MergeGateEvaluation{OperationID: "history", Attempt: 1, Phase: "admission", RepoID: 1, PullID: 1}
	require.NoError(t, db.Insert(ctx, evaluation))
	require.NoError(t, DeleteScope(ctx, Scope{Type: ScopeRepo, ID: 1}))
	unittest.AssertNotExistsBean(t, &ProtectedPathRule{ScopeType: ScopeRepo, ScopeID: 1}, unittest.Cond("deleted=?", false))
	storedRule := unittest.AssertExistsAndLoadBean(t, &ProtectedPathRule{ID: rule.ID})
	require.True(t, storedRule.Deleted)
	require.False(t, storedRule.Enabled)
	require.EqualValues(t, 2, storedRule.Revision)
	unittest.AssertExistsAndLoadBean(t, &MergeGateEvaluation{ID: evaluation.ID})
	unittest.AssertNotExistsBean(t, &RoleDefinition{ID: role.ID})
	unittest.AssertNotExistsBean(t, &RolePermission{RoleID: role.ID})
	unittest.AssertNotExistsBean(t, &SubjectRoleBinding{ID: binding.ID})
	unittest.AssertExistsAndLoadBean(t, &DecisionRecord{ID: decision.ID})
	unittest.AssertExistsAndLoadBean(t, &RoleDefinition{ScopeID: 2})
}

func TestSubjectCleanupPreservesHistory(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	require.NoError(t, db.Insert(ctx, &SubjectRoleBinding{SubjectType: SubjectTeam, SubjectID: 3, ScopeType: ScopeSystem, RoleID: 1}, &SubjectRoleBinding{SubjectType: SubjectUser, SubjectID: 3, ScopeType: ScopeSystem, RoleID: 1}))
	require.NoError(t, DeleteSubject(ctx, SubjectTeam, 3))
	unittest.AssertNotExistsBean(t, &SubjectRoleBinding{SubjectType: SubjectTeam, SubjectID: 3})
	unittest.AssertExistsAndLoadBean(t, &SubjectRoleBinding{SubjectType: SubjectUser, SubjectID: 3})
}

func TestPolicyInsertIdempotencyPreservesExistingRecords(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	role := &RoleDefinition{ScopeType: ScopeRepo, ScopeID: 1, Name: "Reader", LowerName: "reader", Description: "original", Revision: 1, CreatedBy: 2}
	inserted, err := InsertRoleIfAbsent(ctx, role)
	require.NoError(t, err)
	require.True(t, inserted)
	duplicateRole := &RoleDefinition{ScopeType: ScopeRepo, ScopeID: 1, Name: "Changed", LowerName: "reader", Description: "replacement", Revision: 99, CreatedBy: 4}
	inserted, err = InsertRoleIfAbsent(ctx, duplicateRole)
	require.NoError(t, err)
	require.False(t, inserted)
	storedRole := unittest.AssertExistsAndLoadBean(t, &RoleDefinition{ID: role.ID})
	require.Equal(t, *role, *storedRole)
	binding := &SubjectRoleBinding{SubjectType: SubjectUser, SubjectID: 2, ScopeType: ScopeRepo, ScopeID: 1, ScopeOwnerID: 2, RoleID: role.ID, CreatedBy: 2}
	inserted, err = InsertBindingIfAbsent(ctx, binding)
	require.NoError(t, err)
	require.True(t, inserted)
	duplicateBinding := *binding
	duplicateBinding.ID = 0
	duplicateBinding.CreatedBy = 4
	inserted, err = InsertBindingIfAbsent(ctx, &duplicateBinding)
	require.NoError(t, err)
	require.False(t, inserted)
	require.Equal(t, *binding, duplicateBinding)
	newOwnerBinding := *binding
	newOwnerBinding.ID = 0
	newOwnerBinding.ScopeOwnerID = 4
	inserted, err = InsertBindingIfAbsent(ctx, &newOwnerBinding)
	require.NoError(t, err)
	require.True(t, inserted)
	require.NotEqual(t, binding.ID, newOwnerBinding.ID)
	decision := &DecisionRecord{ObservationID: "history-1", OperationID: "operation-1", ActorID: 2, RepoID: 1, OwnerID: 2, Action: "repo.clone", RequestSource: "api", CandidateDecision: "allow", Reason: "native_action", MissingActions: `[]`, NativeOutcome: "success", NativeStage: "operation", SnapshotJSON: `{"revision":1}`}
	inserted, err = InsertDecisionIfAbsent(ctx, decision)
	require.NoError(t, err)
	require.True(t, inserted)
	admission, err := db.GetEngine(ctx).Query("SELECT decision_mode, authorization_decision, authorization_reason, execution_started FROM enterprise_authz_decision WHERE id = ?", decision.ID)
	require.NoError(t, err)
	require.Len(t, admission, 1)
	require.Equal(t, "shadow", string(admission[0]["decision_mode"]))
	require.Equal(t, "not_enforced", string(admission[0]["authorization_decision"]))
	require.Empty(t, admission[0]["authorization_reason"])
	duplicateDecision := *decision
	duplicateDecision.ID = 0
	duplicateDecision.OperationID = "operation-retry"
	duplicateDecision.CandidateDecision = "deny"
	duplicateDecision.SnapshotJSON = `{"revision":99}`
	inserted, err = InsertDecisionIfAbsent(ctx, &duplicateDecision)
	require.NoError(t, err)
	require.False(t, inserted)
	storedDecision := unittest.AssertExistsAndLoadBean(t, &DecisionRecord{ID: decision.ID})
	require.Equal(t, *decision, *storedDecision)
	distinctDecision := *decision
	distinctDecision.ID = 0
	distinctDecision.ObservationID = "history-2"
	distinctDecision.OperationID = "operation-2"
	inserted, err = InsertDecisionIfAbsent(ctx, &distinctDecision)
	require.NoError(t, err)
	require.True(t, inserted)
	require.NotEqual(t, decision.ID, distinctDecision.ID)
	unittest.AssertCount(t, &RoleDefinition{}, 1)
	unittest.AssertCount(t, &SubjectRoleBinding{}, 2)
	unittest.AssertCount(t, &DecisionRecord{}, 2)
}
