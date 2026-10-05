// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package helper

import (
	"fmt"
	"net/http"
	"testing"

	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func TestPackageErrorStatusFeatureDenial(t *testing.T) {
	require.Equal(t, http.StatusForbidden, PackageErrorStatus(fmt.Errorf("wrapped: %w", &authz_service.ExecutionError{Reason: "feature_disabled", Status: http.StatusForbidden})))
	require.Equal(t, http.StatusServiceUnavailable, PackageErrorStatus(&authz_service.ExecutionError{Reason: "feature_policy_unavailable", Status: http.StatusServiceUnavailable}))
}
