// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"fmt"
	"strings"

	"gitea.dev/modules/setting"
)

const WeComChangeAppAdminEvent = "change_app_admin"

type AdminAuthorityCallback struct {
	Validated bool
	verified  bool
	dedupKey  string
	CorpID    string
	AgentID   string
	Event     string
	InfoType  string
	TriggerID string
}

func HandleAdminAuthorityCallback(ctx context.Context, client AdminAuthorityClient, callback AdminAuthorityCallback) (*AdminAuthorityRefreshResult, error) {
	if !AdminCallbackEnabled() {
		return nil, ErrWeComDisabled
	}
	if !callback.verified {
		return nil, fmt.Errorf("%w: unvalidated callback", ErrWeComDenied)
	}
	event := strings.TrimSpace(firstNonEmpty(callback.Event, callback.InfoType))
	if event != WeComChangeAppAdminEvent {
		return nil, fmt.Errorf("%w: unsupported callback event", ErrWeComDenied)
	}
	if callback.CorpID == "" || callback.CorpID != setting.EnterpriseWeCom.CorpID {
		return nil, fmt.Errorf("%w: callback corp mismatch", ErrWeComDenied)
	}
	if callback.AgentID == "" || callback.AgentID != setting.EnterpriseWeCom.AgentID {
		return nil, fmt.Errorf("%w: callback agent mismatch", ErrWeComDenied)
	}
	return RefreshAdminAuthoritySnapshot(ctx, client, AdminAuthorityRefreshOptions{
		CorpID:  setting.EnterpriseWeCom.CorpID,
		AgentID: setting.EnterpriseWeCom.AgentID,
		Trigger: "callback",
		RunID:   strings.TrimSpace(callback.TriggerID),
	})
}
