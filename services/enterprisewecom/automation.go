// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"errors"
	"time"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/log"
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
	if db.InTransaction(ctx) {
		return nil, governanceError("preflight", "invalid_publish_context")
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
		return nil, safeGovernanceError("evidence", err)
	}

	run.Stage = "preflight"
	orgID, err := resolveGeneratedTargetOrg(ctx, opts.OrgID)
	if err == nil {
		err = withGovernanceLease(ctx, run.CorpID, run.AgentID, run.RunID, func(ctx context.Context) error {
			run.Stage = "directory"
			snapshot, err := fetchDirectorySnapshot(ctx, client, setting.EnterpriseWeCom.SyncDepartments, setting.EnterpriseWeCom.SyncTags)
			if err != nil {
				run.DirectorySyncStatus = "failed"
				return safeGovernanceError(run.Stage, err)
			}
			run.DirectorySyncStatus = "fetched"
			run.Stage = "authority"
			admins, err := fetchAdminAuthority(ctx, client)
			if err != nil {
				run.AuthorityRefreshStatus = "failed"
				return err
			}
			run.AuthorityRefreshStatus = "fetched"
			return publishGovernance(ctx, orgID, func(ctx context.Context, revision int64) error {
				run.Stage = "directory"
				if err := persistDirectorySnapshot(ctx, snapshot, run.CorpID, setting.EnterpriseWeCom.SyncDepartments, setting.EnterpriseWeCom.SyncTags); err != nil {
					return safeGovernanceError(run.Stage, err)
				}
				run.Stage = "authority"
				authority, err := persistAdminAuthority(ctx, admins, normalizeAdminAuthorityRefreshOptions(AdminAuthorityRefreshOptions{CorpID: run.CorpID, AgentID: run.AgentID, Trigger: opts.Trigger, RunID: opts.RunID}))
				if err != nil {
					return safeGovernanceError(run.Stage, err)
				}
				run.ProtectedCount = authority.ManagementCount
				run.Stage = "derive"
				generated, err := DeriveGeneratedAuthorizationState(ctx, GeneratedDerivationOptions{CorpID: run.CorpID, AgentID: run.AgentID, OrgID: orgID, RunID: opts.RunID})
				if err != nil {
					return safeGovernanceError(run.Stage, err)
				}
				run.GeneratedMappings = generated.GeneratedMappings
				run.GeneratedTeams = generated.GeneratedTeams
				run.SkippedCount = generated.Skipped + generated.UnresolvedAdmins
				run.Stage = "memberships"
				teams, err := ReconcileGeneratedTeams(ctx, GeneratedTeamReconcileOptions{CorpID: run.CorpID, AgentID: run.AgentID, OrgID: orgID, RunID: opts.RunID, ApplyID: opts.RunID})
				if err != nil {
					return safeGovernanceError(run.Stage, err)
				}
				run.AddedMemberships = teams.AddedMemberships
				run.RemovedMemberships = teams.RemovedMemberships
				run.AddedTeamAdmins = teams.GeneratedTeamAdmins
				run.SkippedCount += teams.Skipped + teams.UnresolvedAdmins
				run.PublishedRevision = revision
				run.Stage = "published"
				_, err = finishAutomationRun(ctx, run, wecom_model.ReconcileRunStatusSuccess, "success", "success", nil)
				return err
			})
		})
	}
	if err != nil {
		err = safeGovernanceError(run.Stage, err)
		run.GeneratedMappings, run.GeneratedTeams, run.AddedMemberships, run.RemovedMemberships, run.AddedTeamAdmins, run.RemovedTeamAdmins, run.ProtectedCount, run.PublishedRevision = 0, 0, 0, 0, 0, 0, 0, 0
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		return finishAutomationRun(cleanup, run, wecom_model.ReconcileRunStatusFailed, "", "", err)
	}
	return run, nil
}

func normalizeAutomationRunOptions(opts AutomationRunOptions) AutomationRunOptions {
	if opts.Trigger == "" {
		opts.Trigger = "cron"
	}
	if opts.RunID == "" {
		opts.RunID = newGovernanceID(opts.Trigger)
	}
	return opts
}

func finishAutomationRun(ctx context.Context, run *wecom_model.ReconcileRun, status wecom_model.ReconcileRunStatus, directoryStatus, authorityStatus string, runErr error) (*wecom_model.ReconcileRun, error) {
	ctx, auditError := audit.WithRequiredPersistence(ctx)
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
		var safe *GovernanceError
		errors.As(safeGovernanceError(run.Stage, runErr), &safe)
		run.Stage, run.Reason = safe.Stage, safe.Reason
		run.ErrorMessage = safe.Error()
	}
	if _, err := db.GetEngine(ctx).ID(run.ID).Cols(
		"stage", "reason", "published_revision", "status", "directory_sync_status", "authority_refresh_status", "generated_mappings", "generated_teams", "added_memberships", "removed_memberships", "added_team_admins", "removed_team_admins", "skipped_count", "error_count", "protected_count", "error_message", "finished_unix",
	).Update(run); err != nil {
		log.Error("WeCom governance run evidence unavailable: evidence_persist_failed")
		return run, safeGovernanceError("evidence", err)
	}
	recordAutomationRunAudit(ctx, run)
	if auditError() != nil {
		return run, governanceError("evidence", "evidence_persist_failed")
	}
	return run, runErr
}

func recordAutomationRunAudit(ctx context.Context, run *wecom_model.ReconcileRun) {
	audit.RecordAs(ctx, user_model.NewAuthSourceUser(), audit_model.EnterpriseWeComAutomationFinish, nil,
		"run_id", run.RunID,
		"trigger", run.Trigger,
		"outcome", run.Status,
		"stage", run.Stage,
		"reason", run.Reason,
		"published_revision", run.PublishedRevision,
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
