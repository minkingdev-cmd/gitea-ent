// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"cmp"
	"context"
	"errors"
	"slices"
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
	OnPublished func(context.Context) error
	CorpID      string
	AgentID     string
	Trigger     string
	RunID       string
	Now         timeutil.TimeStamp
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
	if db.InTransaction(ctx) {
		return nil, governanceError("preflight", "invalid_publish_context")
	}
	opts = normalizeAdminAuthorityRefreshOptions(opts)
	run := &wecom_model.ReconcileRun{RunID: opts.RunID, CorpID: opts.CorpID, AgentID: opts.AgentID, Trigger: opts.Trigger, Stage: "authority", Status: wecom_model.ReconcileRunStatusRunning, StartedUnix: timeutil.TimeStampNow()}
	if err := db.Insert(ctx, run); err != nil {
		return nil, safeGovernanceError("evidence", err)
	}
	var result *AdminAuthorityRefreshResult
	err := withGovernanceLease(ctx, opts.CorpID, opts.AgentID, opts.RunID, func(ctx context.Context) error {
		admins, err := fetchAdminAuthority(ctx, client)
		if err != nil {
			return err
		}
		return publishGovernance(ctx, 0, func(ctx context.Context, revision int64) error {
			result, err = persistAdminAuthority(ctx, admins, opts)
			if err != nil {
				return err
			}
			run.ProtectedCount = result.ManagementCount
			run.PublishedRevision = revision
			run.Stage = "published"
			if _, err := finishAutomationRun(ctx, run, wecom_model.ReconcileRunStatusSuccess, "not_requested", "success", nil); err != nil {
				return err
			}
			if opts.OnPublished != nil {
				return opts.OnPublished(ctx)
			}
			return nil
		})
	})
	if err != nil {
		err = safeGovernanceError("authority", err)
		var safe *GovernanceError
		errors.As(err, &safe)
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		run.ProtectedCount, run.PublishedRevision = 0, 0
		_, persistErr := finishAutomationRun(cleanup, run, wecom_model.ReconcileRunStatusFailed, "not_requested", "failed", err)
		recordAuthorityRefreshAudit(cleanup, opts, nil, "error", safe.Reason)
		return nil, persistErr
	}
	return result, nil
}

func fetchAdminAuthority(ctx context.Context, client AdminAuthorityClient) ([]AppAdminInfo, error) {
	if client == nil {
		return nil, ErrWeComAuthorityUnsupported
	}
	admins, err := client.ListAppAdmins(ctx)
	if err != nil {
		return nil, safeProviderError("authority", err)
	}
	seen := map[string]bool{}
	for _, admin := range admins {
		if strings.TrimSpace(admin.UserID) == "" || (admin.AuthType != 0 && admin.AuthType != 1) || seen[admin.UserID] {
			return nil, governanceError("authority", "incomplete_authority_source")
		}
		seen[admin.UserID] = true
	}
	admins = slices.Clone(admins)
	slices.SortFunc(admins, func(a, b AppAdminInfo) int { return cmp.Compare(a.UserID, b.UserID) })
	return admins, nil
}

func persistAdminAuthority(ctx context.Context, admins []AppAdminInfo, opts AdminAuthorityRefreshOptions) (*AdminAuthorityRefreshResult, error) {
	result := &AdminAuthorityRefreshResult{RefreshID: opts.RunID, Total: len(admins)}
	activeUsers := make([]string, 0, len(admins))
	for _, admin := range admins {
		userID := strings.TrimSpace(admin.UserID)
		activeUsers = append(activeUsers, userID)
		authType := wecom_model.AdminAuthorityAuthType(admin.AuthType)
		isManagement := authType == wecom_model.AdminAuthorityAuthTypeManagement
		if isManagement {
			result.ManagementCount++
		} else {
			result.MessageOnlyCount++
		}
		if err := upsertAdminAuthority(ctx, opts, userID, admin.OpenUserID, authType, isManagement); err != nil {
			return nil, err
		}
	}
	affected, err := deactivateMissingAdminAuthorities(ctx, opts, activeUsers)
	if err != nil {
		return nil, err
	}
	result.DeactivatedMissing = affected
	if _, err := PromoteProtectedAdmins(ctx, ProtectedAdminResolveOptions{CorpID: opts.CorpID, AgentID: opts.AgentID}); err != nil {
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
		opts.RunID = newGovernanceID("authority")
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
