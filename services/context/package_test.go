// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package context

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gitea.dev/models/perm"
	"gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/structs"
	"gitea.dev/modules/test"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
)

func TestDeterminePackageAccessModeForLimitedOwner(t *testing.T) {
	owner := &user.User{ID: 1, Visibility: structs.VisibleTypeLimited}

	accessMode, err := determineAccessMode(&Base{}, owner, &user.User{ID: 2, IsActive: true})
	assert.NoError(t, err)
	assert.Equal(t, perm.AccessModeRead, accessMode)

	accessMode, err = determineAccessMode(&Base{}, owner, &user.User{ID: 3, IsActive: true, IsRestricted: true})
	assert.NoError(t, err)
	assert.Equal(t, perm.AccessModeNone, accessMode)
}

func TestPackageAssignmentFeatureUnavailableStatus(t *testing.T) {
	defer test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: true})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDisabled)()
	for _, version := range []string{"", "1.0"} {
		t.Run(version, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/owner/-/packages/generic/pkg", nil)
			req.Header.Set("X-Gitea-Fetch-Action", "1")
			resp := httptest.NewRecorder()
			base := NewBaseContextForTest(t, resp, req)
			base.SetContextValue(chi.RouteCtxKey, chi.NewRouteContext())
			base.SetPathParam("type", "generic")
			base.SetPathParam("name", "pkg")
			base.SetPathParam("version", version)
			ctx := NewWebContext(base, nil, nil)
			ctx.ContextUser = &user.User{ID: 1, Visibility: structs.VisibleTypePublic}
			PackageAssignment()(ctx)
			assert.Equal(t, http.StatusServiceUnavailable, resp.Code)
			assert.Contains(t, resp.Body.String(), "feature_policy_unavailable")
		})
	}
}
