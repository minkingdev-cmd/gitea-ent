// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestLoadEnterpriseWeComDefaults(t *testing.T) {
	defer test.MockVariableValue(&EnterpriseWeCom)()

	cfg, err := NewConfigProviderFromData("")
	require.NoError(t, err)

	loadEnterpriseWeComFrom(cfg)

	require.False(t, EnterpriseWeCom.Enabled)
	require.True(t, EnterpriseWeCom.LoginOnly)
	require.Equal(t, "enterprise-wecom", EnterpriseWeCom.LoginSourceName)
	require.True(t, EnterpriseWeCom.AutoCreateUser)
	require.Equal(t, "{userid}", EnterpriseWeCom.UsernameTemplate)
	require.True(t, EnterpriseWeCom.SyncDepartments)
	require.True(t, EnterpriseWeCom.SyncTags)
	require.False(t, EnterpriseWeCom.ApplyAuthzMappingsOnSync)
	require.Equal(t, "超管", EnterpriseWeCom.SuperAdminTagName)
	require.Equal(t, 15*time.Second, EnterpriseWeCom.HTTPTimeout)
	require.Equal(t, "https://login.work.weixin.qq.com", EnterpriseWeCom.OAuthBaseURL)
	require.Empty(t, EnterpriseWeCom.CorpID)
	require.Empty(t, EnterpriseWeCom.AgentID)
	require.Empty(t, EnterpriseWeCom.CorpSecret)
	require.Equal(t, 10, EnterpriseWeCom.PersonalRepoQuota)
	require.Zero(t, EnterpriseWeCom.ManagedOrgID)
	require.False(t, EnterpriseWeCom.AdminCallbackEnabled)
}

func TestReadEnterpriseWeComGovernanceConfig(t *testing.T) {
	for _, tc := range []struct {
		name, data, wantError string
		quota                 int
		orgID                 int64
	}{
		{name: "default", quota: 10},
		{name: "zero", data: "PERSONAL_REPO_QUOTA = 0"},
		{name: "custom", data: "PERSONAL_REPO_QUOTA = 3\nMANAGED_ORG_ID = 42", quota: 3, orgID: 42},
		{name: "negative quota disabled", data: "PERSONAL_REPO_QUOTA = -1", wantError: "PERSONAL_REPO_QUOTA"},
		{name: "invalid quota disabled", data: "PERSONAL_REPO_QUOTA = sensitive-not-integer", wantError: "PERSONAL_REPO_QUOTA"},
		{name: "overflow quota", data: "PERSONAL_REPO_QUOTA = 9999999999999999999999", wantError: "PERSONAL_REPO_QUOTA"},
		{name: "negative org", data: "MANAGED_ORG_ID = -1", wantError: "MANAGED_ORG_ID"},
		{name: "invalid org", data: "MANAGED_ORG_ID = sensitive-not-integer", wantError: "MANAGED_ORG_ID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, err := NewConfigProviderFromData("[enterprise.wecom]\n" + tc.data)
			require.NoError(t, err)
			cfg, err := readEnterpriseWeComConfig(root)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
				require.NotContains(t, err.Error(), "sensitive-not-integer")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.quota, cfg.PersonalRepoQuota)
			require.Equal(t, tc.orgID, cfg.ManagedOrgID)
		})
	}
}

func TestValidateEnterpriseWeComAdminCallback(t *testing.T) {
	valid := EnterpriseWeComConfig{
		Enabled: true, LoginSourceName: "enterprise-wecom", CorpID: "corp-1", AgentID: "1000002",
		CorpSecret: "secret", HTTPTimeout: time.Second, AdminCallbackEnabled: true,
		AdminCallbackToken: "sensitive-token", AdminCallbackReceiverID: "corp-1",
		AdminCallbackAESKey: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG",
	}
	for _, tc := range []struct {
		name, wantError string
		mutate          func(*EnterpriseWeComConfig)
	}{
		{name: "valid", mutate: func(*EnterpriseWeComConfig) {}},
		{name: "token", wantError: "ADMIN_CALLBACK_TOKEN", mutate: func(c *EnterpriseWeComConfig) { c.AdminCallbackToken = "" }},
		{name: "receiver", wantError: "ADMIN_CALLBACK_RECEIVER_ID", mutate: func(c *EnterpriseWeComConfig) { c.AdminCallbackReceiverID = "" }},
		{name: "aes missing", wantError: "ADMIN_CALLBACK_AES_KEY", mutate: func(c *EnterpriseWeComConfig) { c.AdminCallbackAESKey = "" }},
		{name: "aes short", wantError: "ADMIN_CALLBACK_AES_KEY", mutate: func(c *EnterpriseWeComConfig) { c.AdminCallbackAESKey = strings.Repeat("a", 42) }},
		{name: "aes invalid", wantError: "ADMIN_CALLBACK_AES_KEY", mutate: func(c *EnterpriseWeComConfig) { c.AdminCallbackAESKey = strings.Repeat("!", 43) }},
		{name: "disabled", mutate: func(c *EnterpriseWeComConfig) {
			c.AdminCallbackEnabled = false
			c.AdminCallbackToken = ""
			c.AdminCallbackAESKey = ""
			c.AdminCallbackReceiverID = ""
		}},
		{name: "governance disabled", mutate: func(c *EnterpriseWeComConfig) {
			c.Enabled = false
			c.AdminCallbackToken = ""
			c.AdminCallbackAESKey = ""
			c.AdminCallbackReceiverID = ""
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid
			tc.mutate(&cfg)
			err := validateEnterpriseWeComConfig(cfg)
			if tc.wantError == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantError)
			require.NotContains(t, err.Error(), valid.AdminCallbackToken)
			require.NotContains(t, err.Error(), valid.AdminCallbackAESKey)
		})
	}
}

func TestLoadEnterpriseWeComCallbackSecretURI(t *testing.T) {
	defer test.MockVariableValue(&EnterpriseWeCom)()
	tokenFile, keyFile := filepath.Join(t.TempDir(), "token"), filepath.Join(t.TempDir(), "aes-key")
	require.NoError(t, os.WriteFile(tokenFile, []byte("token-from-file\n"), 0o600))
	require.NoError(t, os.WriteFile(keyFile, []byte("abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG\n"), 0o600))
	root, err := NewConfigProviderFromData(`[enterprise.wecom]
ENABLED = true
CORP_ID = corp-1
AGENT_ID = 1000002
CORP_SECRET = secret
ADMIN_CALLBACK_ENABLED = true
ADMIN_CALLBACK_RECEIVER_ID = corp-1
ADMIN_CALLBACK_TOKEN_URI = file://` + tokenFile + `
ADMIN_CALLBACK_AES_KEY_URI = file://` + keyFile)
	require.NoError(t, err)
	loadEnterpriseWeComFrom(root)
	require.True(t, EnterpriseWeCom.AdminCallbackEnabled)
	require.Equal(t, "corp-1", EnterpriseWeCom.AdminCallbackReceiverID)
	require.Equal(t, "token-from-file", EnterpriseWeCom.AdminCallbackToken)
	require.Equal(t, "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", EnterpriseWeCom.AdminCallbackAESKey)
}

func TestLoadEnterpriseWeComApplyAuthzMappingsOnSync(t *testing.T) {
	defer test.MockVariableValue(&EnterpriseWeCom)()

	cfg, err := NewConfigProviderFromData(`
[enterprise.wecom]
APPLY_AUTHZ_MAPPINGS_ON_SYNC = true
`)
	require.NoError(t, err)

	loadEnterpriseWeComFrom(cfg)

	require.True(t, EnterpriseWeCom.ApplyAuthzMappingsOnSync)
}

func TestLoadEnterpriseWeComSuperAdminTagName(t *testing.T) {
	defer test.MockVariableValue(&EnterpriseWeCom)()

	cfg, err := NewConfigProviderFromData(`
[enterprise.wecom]
SUPER_ADMIN_TAG_NAME = Gitea Admins
`)
	require.NoError(t, err)

	loadEnterpriseWeComFrom(cfg)

	require.Equal(t, "Gitea Admins", EnterpriseWeCom.SuperAdminTagName)
}

func TestLoadEnterpriseWeComSecretURI(t *testing.T) {
	defer test.MockVariableValue(&EnterpriseWeCom)()

	secretFile := filepath.Join(t.TempDir(), "wecom-secret")
	require.NoError(t, os.WriteFile(secretFile, []byte("super-secret\n"), 0o600))
	cfg, err := NewConfigProviderFromData(`
[enterprise.wecom]
ENABLED = true
LOGIN_ONLY = true
CORP_ID = corp-1
AGENT_ID = 1000002
CORP_SECRET_URI = file://` + secretFile + `
ADMIN_CALLBACK_ENABLED = true
ADMIN_CALLBACK_RECEIVER_ID = corp-1
ADMIN_CALLBACK_TOKEN = inline-token
ADMIN_CALLBACK_AES_KEY = abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG
`)
	require.NoError(t, err)

	loadEnterpriseWeComFrom(cfg)

	require.Equal(t, "super-secret", EnterpriseWeCom.CorpSecret)
	require.Equal(t, "file://"+secretFile, EnterpriseWeCom.CorpSecretURI)
	require.Equal(t, "inline-token", EnterpriseWeCom.AdminCallbackToken)
	require.Equal(t, "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG", EnterpriseWeCom.AdminCallbackAESKey)
}

func TestValidateEnterpriseWeComLoginOnlyRequiresBoundaryAndSecret(t *testing.T) {
	cfg := EnterpriseWeComConfig{Enabled: true, LoginOnly: true}
	err := validateEnterpriseWeComConfig(cfg)
	require.ErrorContains(t, err, "CORP_ID")
	require.ErrorContains(t, err, "AGENT_ID")
	require.ErrorContains(t, err, "CORP_SECRET")

	cfg.CorpID = "corp-1"
	cfg.AgentID = "1000002"
	cfg.CorpSecret = "secret"
	cfg.LoginSourceName = "enterprise-wecom"
	cfg.HTTPTimeout = 15 * time.Second
	require.NoError(t, validateEnterpriseWeComConfig(cfg))
}

func TestValidateEnterpriseWeComRejectsInvalidHTTPTimeout(t *testing.T) {
	cfg := EnterpriseWeComConfig{
		Enabled:         true,
		LoginSourceName: "enterprise-wecom",
		CorpID:          "corp-1",
		AgentID:         "1000002",
		CorpSecret:      "secret",
	}
	require.ErrorContains(t, validateEnterpriseWeComConfig(cfg), "HTTP_TIMEOUT")
}
