// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestAdminCallbackHandlerDisabledMalformedAndOversized(t *testing.T) {
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	req := httptest.NewRequest(http.MethodPost, "/enterprise/wecom/callback/admin-authority", strings.NewReader("secret"))
	rec := httptest.NewRecorder()
	AdminAuthorityCallback(rec, req)
	require.Equal(t, http.StatusNotFound, rec.Code)
	require.Empty(t, rec.Header().Values("Set-Cookie"))
	setting.EnterpriseWeCom.Enabled = true
	setting.EnterpriseWeCom.AdminCallbackEnabled = true
	req = httptest.NewRequest(http.MethodPost, "/enterprise/wecom/callback/admin-authority?msg_signature=secret", strings.NewReader("<xml/>"))
	rec = httptest.NewRecorder()
	AdminAuthorityCallback(rec, req)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.NotContains(t, rec.Body.String(), "secret")
	require.Empty(t, rec.Header().Values("Set-Cookie"))
	req = httptest.NewRequest(http.MethodPost, "/enterprise/wecom/callback/admin-authority", strings.NewReader(strings.Repeat("x", 1<<20+1)))
	rec = httptest.NewRecorder()
	AdminAuthorityCallback(rec, req)
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
}
