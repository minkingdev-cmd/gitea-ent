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
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func TestStrictPolicyObject(t *testing.T) {
	for _, input := range []string{`null`, `[]`, `{}`, `{"action":"repo.clone"}`, `{"action":"repo.clone","action":"repo.delete"}`, `{"actor_id":1}`, `{"action":null}`, `{"action":"repo.clone"} {}`, "{\"action\":\"\xff\"}"} {
		t.Run(input, func(t *testing.T) {
			_, err := strictObject([]byte(input), "action")
			valid := input == `{}` || input == `{"action":"repo.clone"}`
			if valid {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, authz_service.ErrInvalidPolicy)
			}
		})
	}
}

func TestDecisionDTOWhitelist(t *testing.T) {
	secret := "secret token OAuth code callback URL phone email private/path"
	base := authz_model.DecisionRecord{ID: 1, ObservationID: rand.Text(), OperationID: rand.Text(), ActorID: 2, RepoID: 1, OwnerID: 2, Action: authz.Clone, RequestSource: "api", CandidateDecision: "allow", Reason: "native_action", MissingActions: "[]", NativeOutcome: "success", NativeStage: "operation", SnapshotJSON: `{"catalog_version":1,"native_mode":1,"credential":{"read":true,"write":false,"reference":"` + secret + `"},"native_actions":["repo.clone"],"unknown":"` + secret + `","definitions":[{"id":1,"revision":2,"description":"` + secret + `"}],"roles":[]}`}
	dto, err := decisionDTO(&base)
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
		_, err := decisionDTO(&record)
		require.ErrorIs(t, err, authz_service.ErrPolicyStorage)
	}
}

func TestDecisionDTOProtocolObservationID(t *testing.T) {
	record := authz_model.DecisionRecord{ID: 1, ObservationID: strings.Repeat("ab", 32), OperationID: rand.Text(), ActorID: 2, RepoID: 1, OwnerID: 2, Action: authz.PushBranch, RequestSource: "ssh", CandidateDecision: "allow", Reason: "native_action", MissingActions: "[]", NativeOutcome: "success", NativeStage: "transport", SnapshotJSON: `{"catalog_version":1,"native_mode":1,"native_actions":["repo.push_branch"]}`}
	dto, err := decisionDTO(&record)
	require.NoError(t, err)
	require.Equal(t, record.ObservationID, dto.ObservationID)
	record.OperationID = strings.Repeat("ab", 32)
	_, err = decisionDTO(&record)
	require.ErrorIs(t, err, authz_service.ErrPolicyStorage)
}
