// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package routing

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizedRequestURIHidesSensitiveQueryValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/user/oauth2/enterprise-wecom/callback?code=oauth-code&state=state-1&access_token=token-1&corpsecret=secret-1", nil)

	uri := sanitizedRequestURI(req)

	require.Equal(t, "/user/oauth2/enterprise-wecom/callback?access_token=redacted&code=redacted&corpsecret=redacted&state=state-1", uri)
	require.NotContains(t, uri, "oauth-code")
	require.NotContains(t, uri, "token-1")
	require.NotContains(t, uri, "secret-1")
}
