// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"crypto/rand"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"gitea.dev/modelmigration/v28"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzUIBrowser(t *testing.T) {
	if os.Getenv("AUTHZ_UI_BROWSER_TEST") != "true" {
		t.Skip("opt-in browser acceptance against an isolated integration database")
	}
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	require.NoError(t, v28.AddEnterpriseAuthzFoundation(t.Context(), db.GetXORMEngineForTesting()))
	require.NoError(t, v28.AddEnterpriseAuthzEnforcement(t.Context(), db.GetXORMEngineForTesting()))
	require.NoError(t, db.Insert(t.Context(), &authz_model.DecisionRecord{ObservationID: rand.Text(), OperationID: rand.Text(), ActorID: 1, RepoID: 1, OwnerID: 2, Action: authz.ViewMetadata, RequestSource: "web", DecisionMode: "shadow", AuthorizationDecision: "not_enforced", CandidateDecision: "allow", Reason: "native_action", MissingActions: "[]", NativeOutcome: "success", NativeStage: "operation", SnapshotJSON: `{"catalog_version":1}`}))
	for _, evidence := range []struct {
		decision, reason, candidate, outcome string
		started                              bool
	}{
		{"deny", "missing_action", "deny", "unknown", false},
		{"allow", "role_action", "allow", "unknown", false},
		{"fallback", "policy_read_failed", "error", "failed", true},
	} {
		require.NoError(t, db.Insert(t.Context(), &authz_model.DecisionRecord{ObservationID: rand.Text(), OperationID: rand.Text(), ActorID: 4, RepoID: 1, OwnerID: 2, Action: authz.Delete, RequestSource: "api", DecisionMode: "enforce", AuthorizationDecision: evidence.decision, AuthorizationReason: evidence.reason, ExecutionStarted: evidence.started, CandidateDecision: evidence.candidate, Reason: "missing_action", MissingActions: "[]", NativeOutcome: evidence.outcome, NativeStage: "authorization", SnapshotJSON: `{"catalog_version":2}`}))
	}
	server := httptest.NewServer(testWebRoutes)

	defer server.Close()
	defer test.MockVariableValue(&setting.AppURL, server.URL+"/")()
	root := setting.GetGiteaTestSourceRoot()
	cmd := exec.CommandContext(t.Context(), "pnpm", "exec", "playwright", "test", "--config", "playwright.enterprise-authz.config.ts", "--project=chromium", "--workers=1")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GITEA_TEST_E2E_URL="+server.URL, "GITEA_TEST_E2E_USER=user1", "GITEA_TEST_E2E_PASSWORD="+userPassword, "GITEA_TEST_E2E_ENTERPRISE_AUTHZ=true", "GITEA_TEST_E2E_AUTHZ_ENFORCEMENT_HISTORY=true", "GITEA_TEST_E2E_AUTHZ_SUBJECT_ID=4", "GITEA_TEST_E2E_AUTHZ_SUBJECT_NAME=user4", "GITEA_TEST_E2E_AUTHZ_REPO_PATH=/user2/repo1", "TMPDIR="+filepath.Join(root, "tmp/history-ui-browser-temp"))
	output, err := cmd.CombinedOutput()
	require.NoError(t, os.WriteFile(filepath.Join(root, "tmp/authz-enforce-briefs/history-ui-playwright.log"), output, 0o600))
	require.NoError(t, err, "%s", output)
}
