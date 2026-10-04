// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"testing"

	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzConfiguration(t *testing.T) {
	defer test.MockVariableValue(&Audit)()
	defer test.MockVariableValue(&EnterpriseWeCom)()
	for _, wecom := range []bool{false, true} {
		EnterpriseWeCom.Enabled = wecom
		for _, tc := range []struct {
			name, data, reason  string
			audit               AuditRecordOutput
			enabled, failClosed bool
		}{
			{name: "defaults", failClosed: true},
			{name: "shadow", data: "ENABLED=true", audit: AuditRecordOutputDatabase, enabled: true, failClosed: true},
			{name: "reserved fail open", data: "ENABLED=true\nFAIL_CLOSED_ON_ERROR=false", audit: AuditRecordOutputDatabase, enabled: true},
			{name: "disabled enforce", data: "ENFORCE=true", reason: "enforce_not_supported"},
			{name: "enabled enforce", data: "ENABLED=true\nENFORCE=true", audit: AuditRecordOutputDatabase, reason: "enforce_not_supported"},
			{name: "missing audit", data: "ENABLED=true", reason: "database_audit_required"},
			{name: "invalid enabled", data: "ENABLED=sensitive-invalid", reason: "invalid_enabled"},
			{name: "invalid enforce", data: "ENFORCE=sensitive-invalid", reason: "invalid_enforce"},
			{name: "invalid fail closed", data: "FAIL_CLOSED_ON_ERROR=sensitive-invalid", reason: "invalid_fail_closed_on_error"},
			{name: "empty value", data: "ENABLED=", reason: "invalid_enabled"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				Audit.RecordOutput = tc.audit
				root, err := NewConfigProviderFromData("[enterprise.authz]\n" + tc.data)
				require.NoError(t, err)
				cfg, err := readEnterpriseAuthzConfig(root)
				if tc.reason != "" {
					require.EqualError(t, err, tc.reason)
					return
				}
				require.NoError(t, err)
				require.Equal(t, tc.enabled, cfg.Enabled)
				require.False(t, cfg.Enforce)
				require.Equal(t, tc.failClosed, cfg.FailClosedOnError)
			})
		}
	}
}

func TestLoadEnterpriseAuthz(t *testing.T) {
	defer test.MockVariableValue(&EnterpriseAuthz)()
	defer test.MockVariableValue(&Audit)()
	Audit.RecordOutput = AuditRecordOutputDatabase
	root, err := NewConfigProviderFromData("[enterprise.authz]\nENABLED=true\nFAIL_CLOSED_ON_ERROR=false")
	require.NoError(t, err)
	loadEnterpriseAuthzFrom(root)
	require.True(t, EnterpriseAuthz.Enabled)
	require.False(t, EnterpriseAuthz.Enforce)
	require.False(t, EnterpriseAuthz.FailClosedOnError)
}
