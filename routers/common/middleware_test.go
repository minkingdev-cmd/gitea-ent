// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package common

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"gitea.dev/modules/process"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
)

func TestCallbackRequestProcessDescriptionHidesQuery(t *testing.T) {
	for _, path := range []string{"/enterprise/wecom/callback/admin-authority", "/gitea/enterprise/wecom/callback/admin-authority"} {
		req := httptest.NewRequest(http.MethodPost, path+"?msg_signature=private-signature&echostr=private-ciphertext", nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, chi.NewRouteContext()))
		seen := false
		handler := RequestContextHandler()(http.HandlerFunc(func(_ http.ResponseWriter, req *http.Request) {
			processes, _ := process.GetManager().Processes(true, false)
			for _, p := range processes {
				if p.PID == process.GetPID(req.Context()) {
					require.Equal(t, "HTTP: POST "+path, p.Description)
					seen = true
				}
			}
		}))
		handler.ServeHTTP(httptest.NewRecorder(), req)
		require.True(t, seen)
	}
}
