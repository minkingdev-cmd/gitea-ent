// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"fmt"
	"testing"
	"time"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/timeutil"

	"github.com/stretchr/testify/require"
)

func TestAuditRetentionCleansShadowDecisionsAndPreservesPermanentEvidence(t *testing.T) {
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, false)()
	require.NoError(t, unittest.PrepareTestDatabase())
	old := timeutil.TimeStamp(time.Now().Add(-48 * time.Hour).Unix())
	recent := timeutil.TimeStampNow()
	decisions := make([]*authz_model.DecisionRecord, 0, 1002)
	events := make([]*audit_model.Event, 0, 1002)
	for i := range 1002 {
		timestamp := old
		if i == 1001 {
			timestamp = recent
		}
		decisions = append(decisions, &authz_model.DecisionRecord{ObservationID: fmt.Sprintf("observation-%d", i), RepoID: 1, CreatedUnix: timestamp})
		events = append(events, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision, ScopeType: audit_model.ScopeRepository, ScopeID: 1, TimestampUnix: timestamp})
	}
	_, err := db.GetEngine(t.Context()).NoAutoTime().Insert(decisions)
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), events))
	require.NoError(t, DeleteOldEvents(t.Context(), 0))
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 1002)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, 1002)
	require.NoError(t, DeleteOldEvents(t.Context(), 24*time.Hour))
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 1)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, 1)
	unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ObservationID: "observation-1001"})
}
