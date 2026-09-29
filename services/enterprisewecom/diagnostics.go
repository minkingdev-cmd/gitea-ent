// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/timeutil"
)

type AdminAuthorityDiagnosticStatus string

const (
	AdminAuthorityDiagnosticStatusDisabled    AdminAuthorityDiagnosticStatus = "disabled"
	AdminAuthorityDiagnosticStatusOK          AdminAuthorityDiagnosticStatus = "ok"
	AdminAuthorityDiagnosticStatusWarning     AdminAuthorityDiagnosticStatus = "warning"
	AdminAuthorityDiagnosticStatusUnsupported AdminAuthorityDiagnosticStatus = "unsupported"
)

type AdminAuthorityWarningCode string

const (
	AdminAuthorityWarningUnsupported              AdminAuthorityWarningCode = "unsupported_authority_source"
	AdminAuthorityWarningStaleRefresh             AdminAuthorityWarningCode = "stale_authority_refresh"
	AdminAuthorityWarningUnboundIdentity          AdminAuthorityWarningCode = "unbound_authority_identity"
	AdminAuthorityWarningInactiveIdentity         AdminAuthorityWarningCode = "inactive_or_out_of_scope_identity"
	AdminAuthorityWarningMultipleManagementAdmins AdminAuthorityWarningCode = "multiple_management_admins"
	AdminAuthorityWarningGeneratedMappingFailure  AdminAuthorityWarningCode = "generated_mapping_failure"
)

type AdminAuthorityWarning struct {
	Code    AdminAuthorityWarningCode
	Message string
	Count   int
}

type AdminAuthorityDiagnostics struct {
	Status           AdminAuthorityDiagnosticStatus
	Warnings         []AdminAuthorityWarning
	ProtectedUserIDs []int64
}

func (d AdminAuthorityDiagnostics) HasWarning(code AdminAuthorityWarningCode) bool {
	return slices.ContainsFunc(d.Warnings, func(w AdminAuthorityWarning) bool {
		return w.Code == code
	})
}

type AdminAuthorityDiagnosticsOptions struct {
	CorpID     string
	AgentID    string
	Now        timeutil.TimeStamp
	StaleAfter time.Duration
}

func BuildAdminAuthorityDiagnostics(ctx context.Context, opts AdminAuthorityDiagnosticsOptions) (*AdminAuthorityDiagnostics, error) {
	if !setting.EnterpriseWeCom.Enabled {
		return &AdminAuthorityDiagnostics{Status: AdminAuthorityDiagnosticStatusDisabled}, nil
	}
	opts = normalizeAdminAuthorityDiagnosticsOptions(opts)
	diag := &AdminAuthorityDiagnostics{Status: AdminAuthorityDiagnosticStatusOK}
	if opts.CorpID == "" || opts.AgentID == "" {
		diag.Status = AdminAuthorityDiagnosticStatusWarning
		diag.Warnings = append(diag.Warnings, AdminAuthorityWarning{
			Code:    AdminAuthorityWarningUnsupported,
			Message: "Enterprise WeCom authority source is not configured.",
			Count:   1,
		})
		return diag, nil
	}

	if unsupported, err := latestAuthorityRefreshUnsupported(ctx, opts); err != nil {
		return nil, err
	} else if unsupported {
		diag.Status = AdminAuthorityDiagnosticStatusUnsupported
		diag.Warnings = append(diag.Warnings, AdminAuthorityWarning{
			Code:    AdminAuthorityWarningUnsupported,
			Message: "Enterprise WeCom authority refresh is unsupported for the configured app mode.",
			Count:   1,
		})
	}

	authorities := make([]wecom_model.AdminAuthority, 0)
	if err := db.GetEngine(ctx).Where("corp_id = ? AND agent_id = ? AND is_management = ? AND is_active = ?", opts.CorpID, opts.AgentID, true, true).Find(&authorities); err != nil {
		return nil, err
	}
	if len(authorities) > 1 {
		diag.Warnings = append(diag.Warnings, AdminAuthorityWarning{
			Code:    AdminAuthorityWarningMultipleManagementAdmins,
			Message: fmt.Sprintf("Enterprise WeCom reports %d active management administrators.", len(authorities)),
			Count:   len(authorities),
		})
	}

	staleCount, unboundCount, inactiveCount := 0, 0, 0
	staleBefore := opts.Now - timeutil.TimeStamp(opts.StaleAfter/time.Second)
	for _, authority := range authorities {
		if authority.LastRefreshUnix == 0 || authority.LastRefreshUnix < staleBefore {
			staleCount++
		}
		identity, has, err := wecom_model.GetIdentityByCorpAndUserID(ctx, opts.CorpID, authority.WeComUserID)
		if err != nil {
			return nil, err
		}
		switch {
		case !has || identity.UserID == 0:
			unboundCount++
		case identity.Status != wecom_model.IdentityStatusActive:
			inactiveCount++
		default:
			diag.ProtectedUserIDs = append(diag.ProtectedUserIDs, identity.UserID)
		}
	}
	slices.Sort(diag.ProtectedUserIDs)
	diag.ProtectedUserIDs = slices.Compact(diag.ProtectedUserIDs)
	appendCountWarning := func(code AdminAuthorityWarningCode, message string, count int) {
		if count > 0 {
			diag.Warnings = append(diag.Warnings, AdminAuthorityWarning{Code: code, Message: message, Count: count})
		}
	}
	appendCountWarning(AdminAuthorityWarningStaleRefresh, "Enterprise WeCom administrator authority refresh is stale.", staleCount)
	appendCountWarning(AdminAuthorityWarningUnboundIdentity, "Enterprise WeCom management administrator identity is not bound to a Gitea user.", unboundCount)
	appendCountWarning(AdminAuthorityWarningInactiveIdentity, "Enterprise WeCom management administrator identity is inactive or out of scope.", inactiveCount)

	generatedFailures, err := countGeneratedMappingFailures(ctx, opts)
	if err != nil {
		return nil, err
	}
	appendCountWarning(AdminAuthorityWarningGeneratedMappingFailure, "Enterprise WeCom generated authorization state contains skipped, unresolved, or failed items.", generatedFailures)

	if diag.Status == AdminAuthorityDiagnosticStatusOK && len(diag.Warnings) > 0 {
		diag.Status = AdminAuthorityDiagnosticStatusWarning
	}
	return diag, nil
}

func normalizeAdminAuthorityDiagnosticsOptions(opts AdminAuthorityDiagnosticsOptions) AdminAuthorityDiagnosticsOptions {
	opts.CorpID = strings.TrimSpace(firstNonEmpty(opts.CorpID, setting.EnterpriseWeCom.CorpID))
	opts.AgentID = strings.TrimSpace(firstNonEmpty(opts.AgentID, setting.EnterpriseWeCom.AgentID))
	if opts.Now == 0 {
		opts.Now = timeutil.TimeStampNow()
	}
	if opts.StaleAfter == 0 {
		opts.StaleAfter = 24 * time.Hour
	}
	return opts
}

func latestAuthorityRefreshUnsupported(ctx context.Context, opts AdminAuthorityDiagnosticsOptions) (bool, error) {
	run := &wecom_model.ReconcileRun{}
	has, err := db.GetEngine(ctx).
		Where("corp_id = ? AND agent_id = ?", opts.CorpID, opts.AgentID).
		Desc("id").
		Get(run)
	if err != nil || !has {
		return false, err
	}
	return run.AuthorityRefreshStatus == "unsupported", nil
}

func countGeneratedMappingFailures(ctx context.Context, opts AdminAuthorityDiagnosticsOptions) (int, error) {
	statuses := []wecom_model.GeneratedState{wecom_model.GeneratedStateError, wecom_model.GeneratedStateSkipped, wecom_model.GeneratedStateUnresolved}
	mappings, err := db.GetEngine(ctx).Where("corp_id = ? AND agent_id = ?", opts.CorpID, opts.AgentID).In("status", statuses).Count(new(wecom_model.GeneratedMapping))
	if err != nil {
		return 0, err
	}
	teams, err := db.GetEngine(ctx).Where("corp_id = ? AND agent_id = ?", opts.CorpID, opts.AgentID).In("status", statuses).Count(new(wecom_model.GeneratedTeam))
	if err != nil {
		return 0, err
	}
	admins, err := db.GetEngine(ctx).Where("corp_id = ? AND agent_id = ?", opts.CorpID, opts.AgentID).In("status", statuses).Count(new(wecom_model.GeneratedTeamAdmin))
	if err != nil {
		return 0, err
	}
	return int(mappings + teams + admins), nil
}
