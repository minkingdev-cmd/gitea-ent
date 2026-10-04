// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"gitea.dev/modelmigration/v28"
	"gitea.dev/models/db"
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
	server := httptest.NewServer(testWebRoutes)
	defer server.Close()
	defer test.MockVariableValue(&setting.AppURL, server.URL+"/")()
	root := setting.GetGiteaTestSourceRoot()
	cmd := exec.CommandContext(t.Context(), "pnpm", "exec", "playwright", "test", "--config", "playwright.enterprise-authz.config.ts", "--project=chromium", "--workers=1")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GITEA_TEST_E2E_URL="+server.URL, "GITEA_TEST_E2E_USER=user1", "GITEA_TEST_E2E_PASSWORD="+userPassword, "GITEA_TEST_E2E_ENTERPRISE_AUTHZ=true", "GITEA_TEST_E2E_AUTHZ_SUBJECT_ID=4", "GITEA_TEST_E2E_AUTHZ_SUBJECT_NAME=user4", "GITEA_TEST_E2E_AUTHZ_REPO_PATH=/user2/repo1", "TMPDIR="+filepath.Join(root, "tmp/browser-temp"))
	output, err := cmd.CombinedOutput()
	require.NoError(t, os.WriteFile(filepath.Join(root, "tmp/authz-ui-fixture-browser.log"), output, 0o600))
	require.NoError(t, err, "%s", output)
}
