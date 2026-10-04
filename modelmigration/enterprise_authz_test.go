// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package modelmigration

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzEnforceMigrationRegistered(t *testing.T) {
	migrations := prepareMigrationTasks()
	require.EqualValues(t, 362, migrations[len(migrations)-1].idNumber)
	require.EqualValues(t, 363, ExpectedDBVersion())
}
