// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	wecom_service "gitea.dev/services/enterprisewecom"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseWeComPostgreSQLOfflineRecovery(t *testing.T) {
	binary := os.Getenv("GITEA_TEST_RECOVERY_BIN")
	if binary == "" || !setting.Database.Type.IsPostgreSQL() {
		t.Skip("恢复演练需要当前版本 GITEA_TEST_RECOVERY_BIN 与隔离 PostgreSQL")
	}
	host, port, err := net.SplitHostPort(setting.Database.Host)
	require.NoError(t, err)
	require.True(t, host == "127.0.0.1" || host == "localhost")
	require.True(t, strings.HasPrefix(setting.Database.Name, "local_debug_gitea_governance_test_"))
	require.Empty(t, setting.Database.Schema)
	pgDump, err := exec.LookPath("pg_dump")
	require.NoError(t, err)
	pgRestore, err := exec.LookPath("pg_restore")
	require.NoError(t, err)
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "recovery", AgentID: "1000002", ManagedOrgID: 3, SyncDepartments: true})()
	defer test.MockVariableValue(&setting.Service.EnablePasswordSignInForm, true)()
	_, _, err = wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 2, CorpID: "recovery", WeComUserID: "leader", Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	_, err = wecom_service.RunAutomationPipeline(t.Context(), governancePublicationClient{}, wecom_service.AutomationRunOptions{RunID: "recovery-before-backup"})
	require.NoError(t, err)

	dir := t.TempDir()
	config, err := os.ReadFile(setting.CustomConf)
	require.NoError(t, err)
	config = append(config, []byte("\n[enterprise.wecom]\nENABLED=false\nLOGIN_ONLY=false\nADMIN_CALLBACK_ENABLED=false\n[cron]\nENABLED=false\n[log]\nMODE=console\n[log.console]\nLEVEL=Error\n[database]\nLOG_SQL=false\n")...)
	configPath := filepath.Join(dir, "recovery.ini")
	require.NoError(t, os.WriteFile(configPath, config, 0o600))
	cli := func(args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(t.Context(), binary, append([]string{"--work-path", setting.AppWorkPath, "--config", configPath}, args...)...)
		var output bytes.Buffer
		command.Stdout, command.Stderr = &output, &output
		require.NoError(t, command.Run(), "CLI 输出含随机密码，不导出")
		return output.Bytes()
	}
	for _, command := range []string{"create", "change-password", "list", "delete"} {
		help := cli("admin", "user", command, "--help")
		require.True(t, bytes.Contains(help, []byte("USAGE:")))
	}
	pg := func(tool string, args ...string) {
		t.Helper()
		command := exec.CommandContext(t.Context(), tool, args...)
		command.Env = append(os.Environ(), "PGHOST="+host, "PGPORT="+port, "PGUSER="+setting.Database.User, "PGPASSWORD="+setting.Database.Passwd, "PGDATABASE="+setting.Database.Name)
		var output bytes.Buffer
		command.Stdout, command.Stderr = &output, &output
		require.NoError(t, command.Run(), "备份工具输出可能含私密资料，不导出")
	}
	fingerprints := func() map[string]string {
		t.Helper()
		tables, err := db.GetEngine(t.Context()).Query(`SELECT tablename FROM pg_tables WHERE schemaname = 'public' ORDER BY tablename`)
		require.NoError(t, err)
		state := make(map[string]string, len(tables))
		for _, table := range tables {
			name := string(table["tablename"])
			rows, err := db.GetEngine(t.Context()).Query(fmt.Sprintf(`SELECT COALESCE(md5(string_agg(row_to_json(t)::text, E'\n' ORDER BY row_to_json(t)::text)), '') AS digest FROM "%s" t`, strings.ReplaceAll(name, `"`, `""`)))
			require.NoError(t, err)
			state[name] = string(rows[0]["digest"])
		}
		for key, query := range map[string]string{
			"$columns":     `SELECT table_name, column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_schema = 'public' ORDER BY table_name, ordinal_position`,
			"$indexes":     `SELECT tablename, indexname, indexdef FROM pg_indexes WHERE schemaname = 'public' ORDER BY tablename, indexname`,
			"$constraints": `SELECT c.relname, p.conname, pg_get_constraintdef(p.oid) FROM pg_constraint p JOIN pg_class c ON c.oid = p.conrelid JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' ORDER BY c.relname, p.conname`,
			"$sequences":   `SELECT sequencename, start_value, min_value, max_value, increment_by, cycle, cache_size, last_value FROM pg_sequences WHERE schemaname = 'public' ORDER BY sequencename`,
		} {
			rows, err := db.GetEngine(t.Context()).Query(query)
			require.NoError(t, err)
			state[key] = fmt.Sprintf("%x", sha256.Sum256(fmt.Appendf(nil, "%v", rows)))
		}
		return state
	}
	before := fingerprints()
	backup := filepath.Join(dir, "postgresql.dump")
	pg(pgDump, "--format=custom", "--file="+backup)
	require.NoError(t, os.Chmod(backup, 0o600))
	setting.EnterpriseWeCom.Enabled = false
	output := cli("admin", "user", "create", "--username", "recovery-admin", "--email", "recovery-admin@example.invalid", "--admin", "--random-password", "--must-change-password")
	_, remainder, found := strings.Cut(string(output), "generated random password is '")
	require.True(t, found)
	password, _, found := strings.Cut(remainder, "'")
	require.True(t, found)
	recovery := unittest.AssertExistsAndLoadBean(t, &user_model.User{LowerName: "recovery-admin"})
	require.True(t, recovery.IsAdmin)
	require.True(t, recovery.MustChangePassword)
	afterCreate := fingerprints()
	for _, table := range []string{"access_token", "public_key", "wecom_identity", "wecom_admin_authority"} {
		require.Equal(t, before[table], afterCreate[table], "CLI 不得改写 %s", table)
	}
	session := loginUserWithPassword(t, "recovery-admin", password)
	session.MakeRequest(t, NewRequest(t, "GET", "/user/settings/change_password"), http.StatusOK)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user/settings/change_password", map[string]string{"password": password, "retype": password}), http.StatusSeeOther)
	session.MakeRequest(t, NewRequest(t, "GET", "/-/admin"), http.StatusOK)
	setting.EnterpriseWeCom.Enabled = true
	session.MakeRequest(t, NewRequest(t, "GET", "/-/admin"), http.StatusForbidden)
	trusted := loginUser(t, "user2")
	trusted.MakeRequest(t, NewRequest(t, "GET", "/-/admin"), http.StatusOK)
	setting.EnterpriseWeCom.LoginOnly = true
	MakeRequest(t, NewRequestWithValues(t, "POST", "/user/login", map[string]string{"user_name": "recovery-admin", "password": password}), http.StatusForbidden)
	session.MakeRequest(t, NewRequest(t, "GET", "/-/admin"), http.StatusForbidden)
	trusted.MakeRequest(t, NewRequest(t, "GET", "/-/admin"), http.StatusOK)
	_, err = wecom_service.RunAutomationPipeline(t.Context(), governancePublicationClient{}, wecom_service.AutomationRunOptions{RunID: "recovery-strict-publish"})
	require.NoError(t, err)
	MakeRequest(t, NewRequest(t, "GET", "/enterprise/wecom/callback/admin-authority"), http.StatusNotFound)
	cli("admin", "user", "delete", "--username", "recovery-admin")
	unittest.AssertNotExistsBean(t, &user_model.User{LowerName: "recovery-admin"})
	pg(pgRestore, "--clean", "--if-exists", "--single-transaction", "--dbname="+setting.Database.Name, backup)
	require.Equal(t, before, fingerprints(), "完整 PostgreSQL 备份必须恢复全部表、schema 和 sequence，只输出摘要")
	unittest.AssertNotExistsBean(t, &user_model.User{LowerName: "recovery-admin"})
	cli("admin", "user", "list")
	trusted.MakeRequest(t, NewRequest(t, "GET", "/-/admin"), http.StatusOK)
}
