// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package web

import (
	"testing"

	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestAllowAutomaticWebSignIn(t *testing.T) {
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled: true, LoginOnly: true,
	}))
	require.False(t, allowAutomaticWebSignIn())

	setting.EnterpriseWeCom.LoginOnly = false
	require.True(t, allowAutomaticWebSignIn())

	setting.EnterpriseWeCom.Enabled = false
	setting.EnterpriseWeCom.LoginOnly = true
	require.True(t, allowAutomaticWebSignIn())
}
