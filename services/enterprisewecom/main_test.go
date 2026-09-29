// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"testing"

	"gitea.dev/models/unittest"

	_ "gitea.dev/models"
	_ "gitea.dev/models/actions"
	_ "gitea.dev/models/activities"
	_ "gitea.dev/models/auth"
	_ "gitea.dev/models/enterprisewecom"
	_ "gitea.dev/models/user"
)

func TestMain(m *testing.M) {
	unittest.MainTest(m)
}
