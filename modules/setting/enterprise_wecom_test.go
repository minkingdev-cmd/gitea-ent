// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"os"
	"path/filepath"
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
	require.Equal(t, 15*time.Second, EnterpriseWeCom.HTTPTimeout)
	require.Empty(t, EnterpriseWeCom.CorpID)
	require.Empty(t, EnterpriseWeCom.AgentID)
	require.Empty(t, EnterpriseWeCom.CorpSecret)
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
`)
	require.NoError(t, err)

	loadEnterpriseWeComFrom(cfg)

	require.Equal(t, "super-secret", EnterpriseWeCom.CorpSecret)
	require.Equal(t, "file://"+secretFile, EnterpriseWeCom.CorpSecretURI)
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
