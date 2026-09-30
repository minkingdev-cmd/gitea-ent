// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"cmp"
	"context"
	"slices"
	"strings"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/services/audit"
)

type ProtectedAdminResolveOptions struct {
	CorpID  string
	AgentID string
}

func ResolveProtectedAdminUsers(ctx context.Context, opts ProtectedAdminResolveOptions) ([]*user_model.User, error) {
	opts.CorpID = strings.TrimSpace(firstNonEmpty(opts.CorpID, setting.EnterpriseWeCom.CorpID))
	opts.AgentID = strings.TrimSpace(firstNonEmpty(opts.AgentID, setting.EnterpriseWeCom.AgentID))
	if !setting.EnterpriseWeCom.Enabled {
		return nil, nil
	}
	if opts.CorpID == "" || opts.AgentID == "" {
		return nil, nil
	}
	var authorities []wecom_model.AdminAuthority
	if err := db.GetEngine(ctx).Where("corp_id = ? AND agent_id = ? AND is_active = ? AND is_management = ?", opts.CorpID, opts.AgentID, true, true).OrderBy("wecom_userid").Find(&authorities); err != nil {
		return nil, err
	}
	users := make([]*user_model.User, 0, len(authorities))
	seen := map[int64]struct{}{}
	for _, authority := range authorities {
		identity, has, err := wecom_model.GetIdentityByCorpAndUserID(ctx, opts.CorpID, authority.WeComUserID)
		if err != nil {
			return nil, err
		}
		if !has || identity.UserID == 0 || identity.Status != wecom_model.IdentityStatusActive {
			continue
		}
		if _, ok := seen[identity.UserID]; ok {
			continue
		}
		u, err := user_model.GetUserByID(ctx, identity.UserID)
		if err != nil {
			return nil, err
		}
		if !u.IsIndividual() {
			continue
		}
		seen[u.ID] = struct{}{}
		users = append(users, u)
	}
	slices.SortFunc(users, func(a, b *user_model.User) int { return cmp.Compare(a.ID, b.ID) })
	return users, nil
}

func PromoteProtectedAdmins(ctx context.Context, opts ProtectedAdminResolveOptions) (int, error) {
	if !setting.EnterpriseWeCom.Enabled {
		return 0, nil
	}
	opts.CorpID = strings.TrimSpace(firstNonEmpty(opts.CorpID, setting.EnterpriseWeCom.CorpID))
	opts.AgentID = strings.TrimSpace(firstNonEmpty(opts.AgentID, setting.EnterpriseWeCom.AgentID))
	if err := configuredGovernanceScope(opts.CorpID, opts.AgentID); err != nil {
		return 0, err
	}
	if lease, ok := ctx.Value(governanceLeaseKey{}).(*governanceLease); ok && db.InTransaction(ctx) {
		if lease.row.CorpID != opts.CorpID || lease.row.AgentID != opts.AgentID {
			return 0, governanceError("preflight", "scope_mismatch")
		}
		return persistProtectedAdminPromotion(ctx, opts)
	}
	promoted := 0
	err := withGovernanceLease(ctx, opts.CorpID, opts.AgentID, newGovernanceID("promotion"), func(ctx context.Context) error {
		return publishGovernance(ctx, 0, func(ctx context.Context, _ int64) error {
			var err error
			promoted, err = persistProtectedAdminPromotion(ctx, opts)
			return err
		})
	})
	if err != nil {
		return 0, safeGovernanceError("promotion", err)
	}
	return promoted, nil
}

func persistProtectedAdminPromotion(ctx context.Context, opts ProtectedAdminResolveOptions) (int, error) {
	users, err := ResolveProtectedAdminUsers(ctx, opts)
	if err != nil {
		return 0, err
	}
	promoted := 0
	for _, u := range users {
		if u.IsAdmin {
			continue
		}
		u.IsAdmin = true
		if _, err := db.GetEngine(ctx).ID(u.ID).Cols("is_admin").Update(u); err != nil {
			return promoted, err
		}
		audit.RecordAs(ctx, user_model.NewAuthSourceUser(), audit_model.EnterpriseWeComProtectedAdminPromote, u,
			"outcome", "promoted",
			"reason", "active_management_authority",
		)
		promoted++
	}
	return promoted, nil
}
