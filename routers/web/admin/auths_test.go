// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package admin

import (
	"testing"

	"gitea.dev/services/auth/source/oauth2"
	"gitea.dev/services/forms"

	"github.com/stretchr/testify/require"
)

func TestParseOAuth2ConfigDoesNotPersistWeComCredentials(t *testing.T) {
	cfg := parseOAuth2Config(forms.AuthenticationForm{
		Oauth2Provider: oauth2.ProviderNameWeCom,
		Oauth2Key:      "corp-sensitive",
		Oauth2Secret:   "secret-sensitive",
	})
	require.Empty(t, cfg.ClientID)
	require.Empty(t, cfg.ClientSecret)

	cfg = parseOAuth2Config(forms.AuthenticationForm{
		Oauth2Provider: "github",
		Oauth2Key:      "client-id",
		Oauth2Secret:   "client-secret",
	})
	require.Equal(t, "client-id", cfg.ClientID)
	require.Equal(t, "client-secret", cfg.ClientSecret)
}
