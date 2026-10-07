// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"testing"

	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
)

func TestEnterpriseMergeGateAuthenticationCompatibility(t *testing.T) {
	for _, mode := range []struct {
		name             string
		enabled, enforce bool
	}{{"disabled", false, false}, {"shadow", true, false}, {"enforce", true, true}} {
		t.Run(mode.name, func(t *testing.T) {
			featureTestMode(t)
			setting.EnterpriseAuthz.Enforce = true
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: mode.enabled, Enforce: mode.enforce}))
			for _, check := range []struct {
				name string
				run  func(*testing.T)
			}{
				{"legal_MFA_and_forbidden_login", TestEnterpriseWeComLoginOnlyIntegration},
				{"live_HTTP_and_SSH", TestEnterpriseWeComLoginOnlySmoke},
				{"callback_closed", authzCallbackAndForbiddenAuthClosed},
				{"full_directory_publication", TestEnterpriseWeComPublicationCoordinationPortable},
				{"token_metadata", TestAPIGetCurrentToken},
				{"token_revocation", TestAPITokenSelfService},
				{"token_scope", TestAPIRepositoryCreationTokenScopes},
				{"SSH_key_lifecycle", TestEnterpriseWeComNativeSSHAccountStateParity},
				{"PAT_and_Git_HTTP", authzProtocolCredentialStateParity},
				{"actual_clone_fetch_and_push", mergeGateNativeProtocolCompatibility},
			} {
				t.Run(check.name, check.run)
			}
		})
	}
}
