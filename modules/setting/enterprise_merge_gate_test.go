// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"testing"

	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseMergeGateConfiguration(t *testing.T) {
	defer test.MockVariableValue(&EnterpriseAuthz)()
	defer test.MockVariableValue(&Audit)()
	for _, tc := range []struct {
		data, reason     string
		authz            EnterpriseAuthzConfig
		audit            AuditRecordOutput
		enabled, enforce bool
	}{
		{},
		{data: "ENFORCE=true", reason: "enforce_requires_enabled"},
		{data: "ENABLED=true", reason: "authz_enabled_required"},
		{data: "ENABLED=true", authz: EnterpriseAuthzConfig{Enabled: true}, reason: "database_audit_required"},
		{data: "ENABLED=true", authz: EnterpriseAuthzConfig{Enabled: true}, audit: AuditRecordOutputDatabase, enabled: true},
		{data: "ENABLED=true\nENFORCE=true", authz: EnterpriseAuthzConfig{Enabled: true}, audit: AuditRecordOutputDatabase, reason: "authz_enforce_required"},
		{data: "ENABLED=true\nENFORCE=true", authz: EnterpriseAuthzConfig{Enabled: true, Enforce: true, FailClosedOnError: false}, audit: AuditRecordOutputDatabase, enabled: true, enforce: true},
		{data: "ENABLED=invalid", reason: "invalid_enabled"},
		{data: "ENFORCE=", reason: "invalid_enforce"},
	} {
		t.Run(tc.data+tc.reason, func(t *testing.T) {
			EnterpriseAuthz, Audit.RecordOutput = tc.authz, tc.audit
			root, err := NewConfigProviderFromData("[enterprise.merge_gate]\n" + tc.data)
			require.NoError(t, err)
			cfg, err := readEnterpriseMergeGateConfig(root)
			if tc.reason != "" {
				require.EqualError(t, err, tc.reason)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.enabled, cfg.Enabled)
			require.Equal(t, tc.enforce, cfg.Enforce)
		})
	}
}
