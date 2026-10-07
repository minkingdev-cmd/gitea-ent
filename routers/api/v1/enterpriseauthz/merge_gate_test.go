// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"testing"

	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func TestProtectedPathRuleBody(t *testing.T) {
	for _, raw := range []string{
		`{"config":{"path_pattern":"k8s/**","required_role_id":1},"expected_revision":0}`,
		`{}`, `{"config":{"path_pattern":"k8s/**","required_role_id":1}}`,
		`{"config":{"path_pattern":"k8s/**","required_role_id":1},"expected_revision":-1}`,
		`{"config":{"path_pattern":"k8s/**","required_role_id":1},"expected_revision":0,"scope":"global"}`,
		`{"config":{"path_pattern":"k8s/**","required_role_id":1},"expected_revision":0,"expected_revision":1}`,
	} {
		fields, err := strictObject([]byte(raw), "config", "expected_revision")
		if err == nil {
			_, err = parseProtectedPathInput(fields)
		}
		if raw == `{"config":{"path_pattern":"k8s/**","required_role_id":1},"expected_revision":0}` {
			require.NoError(t, err)
		} else {
			require.ErrorIs(t, err, authz_service.ErrInvalidPolicy)
		}
	}
}
