// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"crypto/rand"
	"strings"
	"testing"

	authz_model "gitea.dev/models/enterpriseauthz"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"

	"github.com/stretchr/testify/require"
)

func TestPresentationDecisionDTOWhitelist(t *testing.T) {
	secret := "secret token OAuth code callback URL phone email private/path"
	base := authz_model.DecisionRecord{ID: 1, ObservationID: rand.Text(), OperationID: rand.Text(), ActorID: 2, RepoID: 1, OwnerID: 2, Action: authz.Clone, RequestSource: "api", CandidateDecision: "allow", Reason: "native_action", MissingActions: "[]", NativeOutcome: "success", NativeStage: "operation", SnapshotJSON: `{"catalog_version":1,"native_mode":1,"credential":{"read":true,"write":false,"reference":"` + secret + `"},"native_actions":["repo.clone"],"unknown":"` + secret + `","definitions":[{"id":1,"revision":2,"description":"` + secret + `"}],"roles":[]}`}
	dto, err := DecisionDTO(&base)
	require.NoError(t, err)
	encoded, err := json.Marshal(dto)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), secret)
	require.EqualValues(t, 2, dto.Snapshot.Roles[0].Revision)
	for _, change := range []func(*authz_model.DecisionRecord){
		func(r *authz_model.DecisionRecord) { r.Reason = secret }, func(r *authz_model.DecisionRecord) { r.NativeStage = secret }, func(r *authz_model.DecisionRecord) { r.MissingActions = `["` + secret + `"]` }, func(r *authz_model.DecisionRecord) { r.ObservationID = secret },
		func(r *authz_model.DecisionRecord) {
			r.SnapshotJSON = `{"catalog_version":1,"native_actions":["` + secret + `"]}`
		}, func(r *authz_model.DecisionRecord) {
			r.SnapshotJSON = `{"catalog_version":1,"unit_modes":[{"key":"` + secret + `","mode":1}]}`
		}, func(r *authz_model.DecisionRecord) {
			r.SnapshotJSON = `{"catalog_version":1,"roles":[{"role_id":1,"binding_id":1,"revision":1,"action":"repo.clone","effect":"allow","condition_hash":"` + strings.Repeat("a", 64) + `","result":"` + secret + `"}]}`
		},
	} {
		record := base
		change(&record)
		_, err := DecisionDTO(&record)
		require.ErrorIs(t, err, ErrPolicyStorage)
	}
}

func TestPresentationDecisionDTOProtocolObservationID(t *testing.T) {
	record := authz_model.DecisionRecord{ID: 1, ObservationID: strings.Repeat("ab", 32), OperationID: rand.Text(), ActorID: 2, RepoID: 1, OwnerID: 2, Action: authz.PushBranch, RequestSource: "ssh", CandidateDecision: "allow", Reason: "native_action", MissingActions: "[]", NativeOutcome: "success", NativeStage: "transport", SnapshotJSON: `{"catalog_version":1,"native_mode":1,"native_actions":["repo.push_branch"]}`}
	dto, err := DecisionDTO(&record)
	require.NoError(t, err)
	require.Equal(t, record.ObservationID, dto.ObservationID)
	record.OperationID = strings.Repeat("ab", 32)
	_, err = DecisionDTO(&record)
	require.ErrorIs(t, err, ErrPolicyStorage)
}

func TestPresentationRoleDTORejectsCorruptConditions(t *testing.T) {
	role := &Role{Definition: &authz_model.RoleDefinition{ID: 1, ScopeType: authz_model.ScopeSystem, Name: "<script>unsafe</script>", Revision: 2}}
	dto, err := RoleDTO(role)
	require.NoError(t, err)
	require.Equal(t, "<script>unsafe</script>", dto.Name)
	require.Empty(t, dto.Permissions)
	_, normalized, hash, err := authz.ParseCondition([]byte(`{"branch_pattern":["release/*"]}`))
	require.NoError(t, err)
	role.Permissions = []authz_model.RolePermission{{Action: authz.ReadCode, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}}
	dto, err = RoleDTO(role)
	require.NoError(t, err)
	require.Equal(t, []string{"release/*"}, dto.Permissions[0].Condition.BranchPattern)
	role.Permissions[0].ConditionHash = "bad"
	_, err = RoleDTO(role)
	require.ErrorIs(t, err, ErrPolicyStorage)
}

func TestPresentationExplanationIsCandidateOnly(t *testing.T) {
	dto := ExplanationDTO([]authz.Action{authz.ReadCode}, []authz.Action{authz.CreateBranch}, "role_action", []DiagnosticRole{{ID: 1, Revision: 2}}, []DiagnosticBinding{{ID: 3}}, []DiagnosticCondition{{RoleID: 1, BindingID: 3, Revision: 2, Action: authz.CreateBranch, Effect: "allow", Result: "matched"}})
	require.True(t, dto.CandidateOnly)
	require.Equal(t, []string{"repo.read_code"}, dto.NativeActions)
	require.Equal(t, []string{"repo.create_branch"}, dto.RoleActions)
	require.EqualValues(t, 2, dto.Roles[0].Revision)
	require.Equal(t, "matched", dto.Conditions[0].Result)
	require.Equal(t, []string{}, ActionsDTO(nil))
}
