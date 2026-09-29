// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"fmt"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/timeutil"
	"gitea.dev/services/audit"
)

type AutomationClient interface {
	DirectoryClient
	AdminAuthorityClient
}

type AutomationRunOptions struct {
	Trigger string
	RunID   string
	OrgID   int64
}

func RunScheduledAutomation(ctx context.Context, client AutomationClient) (*wecom_model.ReconcileRun, error) {
	return RunAutomationPipeline(ctx, client, AutomationRunOptions{Trigger: "cron"})
}

func RunAutomationPipeline(ctx context.Context, client AutomationClient, opts AutomationRunOptions) (*wecom_model.ReconcileRun, error) {
	if !setting.EnterpriseWeCom.Enabled {
		return nil, ErrWeComDisabled
	}
	opts = normalizeAutomationRunOptions(opts)
	run := &wecom_model.ReconcileRun{
		RunID:       opts.RunID,
		CorpID:      setting.EnterpriseWeCom.CorpID,
		AgentID:     setting.EnterpriseWeCom.AgentID,
		Trigger:     opts.Trigger,
		Status:      wecom_model.ReconcileRunStatusRunning,
		StartedUnix: timeutil.TimeStampNow(),
	}
	if err := db.Insert(ctx, run); err != nil {
		return nil, err
	}

	if err := syncDirectory(ctx, client, setting.EnterpriseWeCom.CorpID); err != nil {
		return finishAutomationRun(ctx, run, wecom_model.ReconcileRunStatusFailed, "failed", "", err)
	}
	run.DirectorySyncStatus = "success"

	authorityResult, err := RefreshAdminAuthoritySnapshot(ctx, client, AdminAuthorityRefreshOptions{
		CorpID:  setting.EnterpriseWeCom.CorpID,
		AgentID: setting.EnterpriseWeCom.AgentID,
		Trigger: opts.Trigger,
		RunID:   opts.RunID,
	})
	if err != nil {
		if !IsUnsupportedAuthorityError(err) {
			return finishAutomationRun(ctx, run, wecom_model.ReconcileRunStatusFailed, "success", "failed", err)
		}
		run.AuthorityRefreshStatus = "unsupported"
	} else {
		run.AuthorityRefreshStatus = "success"
		run.ProtectedCount = authorityResult.ManagementCount
	}

	generatedResult, err := DeriveGeneratedAuthorizationState(ctx, GeneratedDerivationOptions{
		CorpID:  setting.EnterpriseWeCom.CorpID,
		AgentID: setting.EnterpriseWeCom.AgentID,
		OrgID:   opts.OrgID,
		RunID:   opts.RunID,
	})
	if err != nil {
		return finishAutomationRun(ctx, run, wecom_model.ReconcileRunStatusFailed, "success", run.AuthorityRefreshStatus, err)
	}
	run.GeneratedMappings = generatedResult.GeneratedMappings
	run.GeneratedTeams = generatedResult.GeneratedTeams
	run.SkippedCount = generatedResult.Skipped + generatedResult.UnresolvedAdmins

	teamResult, err := ReconcileGeneratedTeams(ctx, GeneratedTeamReconcileOptions{
		CorpID:  setting.EnterpriseWeCom.CorpID,
		AgentID: setting.EnterpriseWeCom.AgentID,
		OrgID:   opts.OrgID,
		RunID:   opts.RunID,
		ApplyID: opts.RunID,
	})
	if err != nil {
		return finishAutomationRun(ctx, run, wecom_model.ReconcileRunStatusFailed, "success", run.AuthorityRefreshStatus, err)
	}
	run.AddedMemberships = teamResult.AddedMemberships
	run.RemovedMemberships = teamResult.RemovedMemberships
	run.AddedTeamAdmins = teamResult.GeneratedTeamAdmins
	run.SkippedCount += teamResult.Skipped + teamResult.UnresolvedAdmins
	run.ErrorCount = len(teamResult.Errors)
	if run.ErrorCount > 0 {
		return finishAutomationRun(ctx, run, wecom_model.ReconcileRunStatusFailed, "success", run.AuthorityRefreshStatus, ErrInvalidAuthzMapping)
	}
	return finishAutomationRun(ctx, run, wecom_model.ReconcileRunStatusSuccess, "success", run.AuthorityRefreshStatus, nil)
}

func normalizeAutomationRunOptions(opts AutomationRunOptions) AutomationRunOptions {
	if opts.Trigger == "" {
		opts.Trigger = "cron"
	}
	if opts.RunID == "" {
		opts.RunID = fmt.Sprintf("%s-%d", opts.Trigger, timeutil.TimeStampNow())
	}
	return opts
}

func finishAutomationRun(ctx context.Context, run *wecom_model.ReconcileRun, status wecom_model.ReconcileRunStatus, directoryStatus, authorityStatus string, runErr error) (*wecom_model.ReconcileRun, error) {
	run.Status = status
	if directoryStatus != "" {
		run.DirectorySyncStatus = directoryStatus
	}
	if authorityStatus != "" {
		run.AuthorityRefreshStatus = authorityStatus
	}
	run.FinishedUnix = timeutil.TimeStampNow()
	if runErr != nil {
		run.ErrorCount++
		run.ErrorMessage = runErr.Error()
	}
	if _, err := db.GetEngine(ctx).ID(run.ID).Cols(
		"status", "directory_sync_status", "authority_refresh_status", "generated_mappings", "generated_teams", "added_memberships", "removed_memberships", "added_team_admins", "removed_team_admins", "skipped_count", "error_count", "protected_count", "error_message", "finished_unix",
	).Update(run); err != nil {
		return run, err
	}
	recordAutomationRunAudit(ctx, run)
	return run, runErr
}

func recordAutomationRunAudit(ctx context.Context, run *wecom_model.ReconcileRun) {
	audit.RecordAs(ctx, user_model.NewAuthSourceUser(), audit_model.EnterpriseWeComAutomationFinish, nil,
		"run_id", run.RunID,
		"trigger", run.Trigger,
		"outcome", run.Status,
		"directory_status", run.DirectorySyncStatus,
		"authority_status", run.AuthorityRefreshStatus,
		"generated_mappings", run.GeneratedMappings,
		"generated_teams", run.GeneratedTeams,
		"added_memberships", run.AddedMemberships,
		"removed_memberships", run.RemovedMemberships,
		"added_team_admins", run.AddedTeamAdmins,
		"removed_team_admins", run.RemovedTeamAdmins,
		"skipped", run.SkippedCount,
		"errors", run.ErrorCount,
		"protected", run.ProtectedCount,
	)
}
