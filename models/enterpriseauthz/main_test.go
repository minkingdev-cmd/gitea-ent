// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"testing"

	"gitea.dev/models/unittest"

	_ "gitea.dev/models/organization"
	_ "gitea.dev/models/repo"
	_ "gitea.dev/models/webhook"
)

func TestMain(m *testing.M) { unittest.MainTest(m) }
