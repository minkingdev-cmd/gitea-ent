// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"strings"
	"testing"

	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"

	"github.com/stretchr/testify/require"
)

func TestMergeGateFinalSnapshotOverflowPreservesErrorEvidence(t *testing.T) {
	evaluation := mergeGateEvaluation{Snapshot: mergeGateSnapshot{Version: authz.MergeGateSnapshotVersion, RepoID: 1, PullID: 2, IssueID: 3, ActorID: 2, Action: strings.Repeat("private-policy-data", authz.MaxSnapshotBytes), Facts: []authz.MergeGateFact{{Code: "state_changed", Source: "gate", State: "error"}}}}
	require.NoError(t, sealMergeGateEvaluation(&evaluation))
	require.LessOrEqual(t, len(evaluation.JSON), authz.MaxSnapshotBytes)
	require.True(t, json.Valid([]byte(evaluation.JSON)))
	require.NotContains(t, evaluation.JSON, "private-policy-data")
	require.Equal(t, fmt.Sprintf("%x", sha256.Sum256([]byte(evaluation.JSON))), evaluation.Hash)
	require.Equal(t, []authz.MergeGateFact{{Code: "snapshot_too_large", Source: "gate", State: "error"}}, evaluation.Snapshot.Facts)
}

func TestMergeGateUnstableFingerprintPreservesModeAndClearsBypass(t *testing.T) {
	for _, mode := range []string{"shadow", "enforce"} {
		t.Run(mode, func(t *testing.T) {
			reads := 0
			evaluation, err := collectStableMergeGateEvaluation(t.Context(), func(context.Context) (mergeGateEvaluation, error) {
				reads++
				bypass := authz.MergeGateBypass{Requested: true, Authorized: true, NativeAllowed: true, Reason: "approved emergency", Categories: []string{"required_check"}}
				current := mergeGateEvaluation{Snapshot: mergeGateSnapshot{Version: 1, Action: strconv.Itoa(reads), Facts: []authz.MergeGateFact{{Code: "required_check", Source: "feature", State: "failed"}}}, Bypass: bypass}
				current.Result = authz.EvaluateMergeGate(authz.MergeGateInput{Mode: mode, Phase: "admission", Facts: current.Snapshot.Facts, Bypass: bypass})
				err := sealMergeGateEvaluation(&current)
				return current, err
			})
			require.NoError(t, err)
			require.Equal(t, 3, reads)
			require.Equal(t, "error", evaluation.Result.CandidateDecision)
			require.False(t, evaluation.Result.BypassUsed)
			if mode == "shadow" {
				require.Equal(t, "not_enforced", evaluation.Result.AdmissionDecision)
			} else {
				require.Equal(t, "error", evaluation.Result.AdmissionDecision)
			}
		})
	}
}
