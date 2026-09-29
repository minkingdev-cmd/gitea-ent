// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"strings"

	"gitea.dev/models/db"
)

func IsActiveManagementAuthorityBoundUser(ctx context.Context, corpID, agentID string, userID int64) (bool, error) {
	corpID = strings.TrimSpace(corpID)
	agentID = strings.TrimSpace(agentID)
	if corpID == "" || agentID == "" || userID == 0 {
		return false, nil
	}

	var identities []Identity
	if err := db.GetEngine(ctx).
		Where("corp_id = ? AND user_id = ? AND status = ?", corpID, userID, IdentityStatusActive).
		Find(&identities); err != nil {
		return false, err
	}
	for _, identity := range identities {
		has, err := db.GetEngine(ctx).
			Where("corp_id = ? AND agent_id = ? AND wecom_userid = ? AND is_active = ? AND is_management = ?", corpID, agentID, identity.WeComUserID, true, true).
			Exist(new(AdminAuthority))
		if err != nil || has {
			return has, err
		}
	}
	return false, nil
}
