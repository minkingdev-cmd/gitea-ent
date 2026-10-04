// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"fmt"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/services/audit"
)

func ArchiveIntent(archived bool) string { return fmt.Sprintf("archive:%t", archived) }

func ExecutionSource(ctx context.Context) string {
	switch audit.OriginFromContext(ctx) {
	case audit_model.OriginUI:
		return "web"
	case audit_model.OriginAPI:
		return "api"
	default:
		return "system"
	}
}
