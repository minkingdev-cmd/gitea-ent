// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package oauth2

import (
	"testing"
	"time"

	"gitea.dev/models/auth"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func mockWeComPreflightSettings(t *testing.T) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:         true,
		LoginOnly:       true,
		LoginSourceName: "enterprise-wecom",
		CorpID:          "corp-1",
		AgentID:         "1000002",
		CorpSecret:      "secret",
		HTTPTimeout:     15 * time.Second,
	}))
}

func TestValidateEnterpriseWeComSource(t *testing.T) {
	mockWeComPreflightSettings(t)

	t.Run("missing", func(t *testing.T) {
		require.ErrorContains(t, validateEnterpriseWeComSource(nil), "does not exist")
	})

	t.Run("inactive", func(t *testing.T) {
		sources := []*auth.Source{{
			Name: "enterprise-wecom", Type: auth.OAuth2, IsActive: false,
			Cfg: &Source{Provider: ProviderNameWeCom},
		}}
		require.ErrorContains(t, validateEnterpriseWeComSource(sources), "inactive")
	})

	t.Run("wrong provider", func(t *testing.T) {
		sources := []*auth.Source{{
			Name: "enterprise-wecom", Type: auth.OAuth2, IsActive: true,
			Cfg: &Source{Provider: "github"},
		}}
		require.ErrorContains(t, validateEnterpriseWeComSource(sources), "not a WeCom")
	})

	t.Run("valid", func(t *testing.T) {
		sources := []*auth.Source{{
			Name: "enterprise-wecom", Type: auth.OAuth2, IsActive: true,
			Cfg: &Source{Provider: ProviderNameWeCom},
		}}
		require.NoError(t, validateEnterpriseWeComSource(sources))
	})
}

func TestIsConfiguredWeComSource(t *testing.T) {
	mockWeComPreflightSettings(t)
	require.True(t, IsConfiguredWeComSource(&auth.Source{
		Name: "enterprise-wecom", Type: auth.OAuth2,
		Cfg: &Source{Provider: ProviderNameWeCom},
	}))
	require.False(t, IsConfiguredWeComSource(&auth.Source{
		Name: "other", Type: auth.OAuth2,
		Cfg: &Source{Provider: ProviderNameWeCom},
	}))
}
