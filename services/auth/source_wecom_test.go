// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"testing"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

type testOAuth2ProviderConfig struct {
	auth_model.ConfigBase
	provider string
}

func (c *testOAuth2ProviderConfig) FromDB([]byte) error        { return nil }
func (c *testOAuth2ProviderConfig) ToDB() ([]byte, error)      { return nil, nil }
func (c *testOAuth2ProviderConfig) OAuth2ProviderName() string { return c.provider }

func TestValidateConfiguredWeComSourceMutation(t *testing.T) {
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled: true, LoginOnly: true, LoginSourceName: "enterprise-wecom",
	}))
	original := &auth_model.Source{
		ID: 1, Name: "enterprise-wecom", Type: auth_model.OAuth2, IsActive: true,
		Cfg: &testOAuth2ProviderConfig{provider: "wecom"},
	}

	t.Run("unchanged", func(t *testing.T) {
		updated := *original
		require.NoError(t, validateConfiguredWeComSourceMutation(original, &updated))
	})
	t.Run("disabled", func(t *testing.T) {
		updated := *original
		updated.IsActive = false
		require.ErrorIs(t, validateConfiguredWeComSourceMutation(original, &updated), ErrConfiguredWeComSourceProtected)
	})
	t.Run("renamed", func(t *testing.T) {
		updated := *original
		updated.Name = "renamed"
		require.ErrorIs(t, validateConfiguredWeComSourceMutation(original, &updated), ErrConfiguredWeComSourceProtected)
	})
	t.Run("provider changed", func(t *testing.T) {
		updated := *original
		updated.Cfg = &testOAuth2ProviderConfig{provider: "github"}
		require.ErrorIs(t, validateConfiguredWeComSourceMutation(original, &updated), ErrConfiguredWeComSourceProtected)
	})
	t.Run("deleted", func(t *testing.T) {
		require.ErrorIs(t, validateConfiguredWeComSourceMutation(original, nil), ErrConfiguredWeComSourceProtected)
	})
}
