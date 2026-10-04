// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package models

import (
	"context"

	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/unit"

	_ "gitea.dev/models/enterprisewecom" // register Enterprise WeCom models
)

// Init initialize model
func Init(ctx context.Context) error {
	if err := unit.LoadUnitConfig(); err != nil {
		return err
	}
	return authz_model.CheckReady(ctx)
}
