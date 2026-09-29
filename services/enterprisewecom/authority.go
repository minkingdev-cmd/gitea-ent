// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/timeutil"
	"gitea.dev/services/audit"

	"xorm.io/builder"
)

type AdminAuthorityClient interface {
	ListAppAdmins(ctx context.Context) ([]AppAdminInfo, error)
}

type AdminAuthorityRefreshOptions struct {
	CorpID  string
	AgentID string
	Trigger string
	RunID   string
	Now     timeutil.TimeStamp
}

type AdminAuthorityRefreshResult struct {
	RefreshID          string
	Total              int
	ManagementCount    int
	MessageOnlyCount   int
	DeactivatedMissing int64
}

func RefreshAdminAuthoritySnapshot(ctx context.Context, client AdminAuthorityClient, opts AdminAuthorityRefreshOptions) (*AdminAuthorityRefreshResult, error) {
	if !setting.EnterpriseWeCom.Enabled {
		return nil, ErrWeComDisabled
	}
	opts = normalizeAdminAuthorityRefreshOptions(opts)
	if opts.CorpID == "" || opts.AgentID == "" {
		recordAuthorityRefreshAudit(ctx, opts, nil, "error", "missing_configuration")
		return nil, fmt.Errorf("%w: missing corp or agent id", ErrWeComDenied)
	}
	if client == nil {
		recordAuthorityRefreshAudit(ctx, opts, nil, "unsupported", "unsupported_authority_source")
		return nil, ErrWeComAuthorityUnsupported
	}

	admins, err := client.ListAppAdmins(ctx)
	if err != nil {
		recordAuthorityRefreshAudit(ctx, opts, nil, "error", "provider_error")
		return nil, err
	}

	result := &AdminAuthorityRefreshResult{RefreshID: opts.RunID, Total: len(admins)}
	activeUsers := make([]string, 0, len(admins))
	seen := map[string]struct{}{}

	err = db.WithTx(ctx, func(ctx context.Context) error {
		for _, admin := range admins {
			userID := strings.TrimSpace(admin.UserID)
			if userID == "" {
				continue
			}
			if _, ok := seen[userID]; ok {
				continue
			}
			seen[userID] = struct{}{}
			activeUsers = append(activeUsers, userID)

			authType := wecom_model.AdminAuthorityAuthType(admin.AuthType)
			isManagement := authType == wecom_model.AdminAuthorityAuthTypeManagement
			if isManagement {
				result.ManagementCount++
			} else {
				result.MessageOnlyCount++
			}
			if err := upsertAdminAuthority(ctx, opts, userID, admin.OpenUserID, authType, isManagement); err != nil {
				return err
			}
		}
		affected, err := deactivateMissingAdminAuthorities(ctx, opts, activeUsers)
		if err != nil {
			return err
		}
		result.DeactivatedMissing = affected
		return nil
	})
	if err != nil {
		recordAuthorityRefreshAudit(ctx, opts, result, "error", "snapshot_persist_failed")
		return nil, err
	}
	if _, err := PromoteProtectedAdmins(ctx, ProtectedAdminResolveOptions{CorpID: opts.CorpID, AgentID: opts.AgentID}); err != nil {
		recordAuthorityRefreshAudit(ctx, opts, result, "error", "promotion_failed")
		return nil, err
	}
	recordAuthorityRefreshAudit(ctx, opts, result, "success", "")
	return result, nil
}

func normalizeAdminAuthorityRefreshOptions(opts AdminAuthorityRefreshOptions) AdminAuthorityRefreshOptions {
	opts.CorpID = strings.TrimSpace(firstNonEmpty(opts.CorpID, setting.EnterpriseWeCom.CorpID))
	opts.AgentID = strings.TrimSpace(firstNonEmpty(opts.AgentID, setting.EnterpriseWeCom.AgentID))
	opts.Trigger = strings.TrimSpace(opts.Trigger)
	if opts.Trigger == "" {
		opts.Trigger = "scheduled"
	}
	opts.RunID = strings.TrimSpace(opts.RunID)
	if opts.RunID == "" {
		opts.RunID = fmt.Sprintf("authority-%d", timeutil.TimeStampNow())
	}
	if opts.Now == 0 {
		opts.Now = timeutil.TimeStamp(time.Now().Unix())
	}
	return opts
}

func upsertAdminAuthority(ctx context.Context, opts AdminAuthorityRefreshOptions, userID, openUserID string, authType wecom_model.AdminAuthorityAuthType, isManagement bool) error {
	authority := &wecom_model.AdminAuthority{CorpID: opts.CorpID, AgentID: opts.AgentID, WeComUserID: userID}
	has, err := db.GetEngine(ctx).Get(authority)
	if err != nil {
		return err
	}
	if has {
		authority.OpenUserID = openUserID
		authority.AuthType = authType
		authority.IsManagement = isManagement
		authority.IsActive = true
		authority.RefreshID = opts.RunID
		authority.RefreshTrigger = opts.Trigger
		authority.LastRefreshUnix = opts.Now
		authority.LastSeenUnix = opts.Now
		authority.LastError = ""
		_, err = db.GetEngine(ctx).ID(authority.ID).Cols(
			"open_user_id", "auth_type", "is_management", "is_active", "refresh_id", "refresh_trigger", "last_refresh_unix", "last_seen_unix", "last_error",
		).Update(authority)
		return err
	}
	return db.Insert(ctx, &wecom_model.AdminAuthority{
		CorpID:          opts.CorpID,
		AgentID:         opts.AgentID,
		WeComUserID:     userID,
		OpenUserID:      openUserID,
		AuthType:        authType,
		IsManagement:    isManagement,
		IsActive:        true,
		RefreshID:       opts.RunID,
		RefreshTrigger:  opts.Trigger,
		LastRefreshUnix: opts.Now,
		LastSeenUnix:    opts.Now,
	})
}

func deactivateMissingAdminAuthorities(ctx context.Context, opts AdminAuthorityRefreshOptions, activeUsers []string) (int64, error) {
	update := &wecom_model.AdminAuthority{
		IsActive:        false,
		RefreshID:       opts.RunID,
		RefreshTrigger:  opts.Trigger,
		LastRefreshUnix: opts.Now,
	}
	sess := db.GetEngine(ctx).
		Where("corp_id = ? AND agent_id = ? AND is_active = ?", opts.CorpID, opts.AgentID, true)
	if len(activeUsers) > 0 {
		sess = sess.And(builder.NotIn("wecom_userid", stringSliceToAny(activeUsers)...))
	}
	return sess.Cols("is_active", "refresh_id", "refresh_trigger", "last_refresh_unix").Update(update)
}

func stringSliceToAny(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func IsManagementAuthType(authType int) bool {
	return wecom_model.AdminAuthorityAuthType(authType) == wecom_model.AdminAuthorityAuthTypeManagement
}

func IsUnsupportedAuthorityError(err error) bool {
	return errors.Is(err, ErrWeComAuthorityUnsupported)
}

func recordAuthorityRefreshAudit(ctx context.Context, opts AdminAuthorityRefreshOptions, result *AdminAuthorityRefreshResult, outcome, reason string) {
	metadata := []any{
		"corp_id", opts.CorpID,
		"agent_id", opts.AgentID,
		"trigger", opts.Trigger,
		"refresh_id", opts.RunID,
		"outcome", outcome,
	}
	if reason != "" {
		metadata = append(metadata, "reason", reason)
	}
	if result != nil {
		metadata = append(metadata,
			"total", result.Total,
			"management_count", result.ManagementCount,
			"message_only_count", result.MessageOnlyCount,
			"deactivated_missing", result.DeactivatedMissing,
		)
	}
	audit.RecordAs(ctx, user_model.NewAuthSourceUser(), audit_model.EnterpriseWeComAuthorityRefresh, nil, metadata...)
}
