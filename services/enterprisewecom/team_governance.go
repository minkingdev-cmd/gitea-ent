// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"fmt"
	"strings"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	"gitea.dev/models/perm"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/structs"
	"gitea.dev/modules/timeutil"
	"gitea.dev/modules/util"
	"gitea.dev/services/audit"
	org_service "gitea.dev/services/org"
)

type TeamLocalMaintenanceOperation string

const (
	TeamLocalMaintenanceCreate     TeamLocalMaintenanceOperation = "create"
	TeamLocalMaintenanceEdit       TeamLocalMaintenanceOperation = "edit"
	TeamLocalMaintenanceDelete     TeamLocalMaintenanceOperation = "delete"
	TeamLocalMaintenanceMembership TeamLocalMaintenanceOperation = "membership"
)

var ErrManagedTeamLocalMaintenanceDenied = util.NewPermissionDeniedErrorf("Enterprise WeCom managed teams are maintained by scheduled directory reconciliation")

type GeneratedTeamReconcileOptions struct {
	CorpID  string
	AgentID string
	RunID   string
	OrgID   int64
	ActorID int64
	ApplyID string
}

func CanLocallyMaintainTeam(ctx context.Context, teamID int64, operation TeamLocalMaintenanceOperation) error {
	if !setting.EnterpriseWeCom.Enabled {
		return nil
	}
	if operation == TeamLocalMaintenanceCreate {
		recordTeamMaintenanceDenyAudit(ctx, 0, operation)
		return ErrManagedTeamLocalMaintenanceDenied
	}
	if teamID == 0 {
		return nil
	}
	managed, err := db.GetEngine(ctx).Where("team_id = ?", teamID).Exist(new(wecom_model.GeneratedTeam))
	if err != nil || !managed {
		return err
	}
	recordTeamMaintenanceDenyAudit(ctx, teamID, operation)
	return ErrManagedTeamLocalMaintenanceDenied
}

type GeneratedTeamReconcileResult struct {
	CreatedTeams        int
	UpdatedTeams        int
	GeneratedTeamAdmins int
	UnresolvedAdmins    int
	AddedMemberships    int
	RemovedMemberships  int
	Skipped             int
	Errors              []string
}

func ReconcileGeneratedTeams(ctx context.Context, opts GeneratedTeamReconcileOptions) (*GeneratedTeamReconcileResult, error) {
	if !setting.EnterpriseWeCom.Enabled {
		return nil, ErrWeComDisabled
	}
	opts = normalizeGeneratedTeamReconcileOptions(opts)
	result := &GeneratedTeamReconcileResult{}

	var generatedTeams []wecom_model.GeneratedTeam
	sess := db.GetEngine(ctx).Where("corp_id = ? AND agent_id = ?", opts.CorpID, opts.AgentID).OrderBy("id ASC")
	if opts.RunID != "" {
		sess = sess.And("run_id = ?", opts.RunID)
	}
	if err := sess.Find(&generatedTeams); err != nil {
		return nil, err
	}

	for _, generatedTeam := range generatedTeams {
		team, created, skipped, err := ensureGeneratedGiteaTeam(ctx, opts, &generatedTeam)
		if err != nil {
			result.Errors = append(result.Errors, err.Error())
			continue
		}
		if skipped {
			result.Skipped++
			continue
		}
		if created {
			result.CreatedTeams++
		}
		if err := markGeneratedTeamApplied(ctx, opts, &generatedTeam, team.ID); err != nil {
			return nil, err
		}
		if err := upsertGeneratedTeamAuthzMapping(ctx, opts, &generatedTeam, team.ID); err != nil {
			return nil, err
		}
		adminCount, unresolved, err := updateGeneratedTeamAdminsTarget(ctx, opts, &generatedTeam, team.ID)
		if err != nil {
			return nil, err
		}
		result.GeneratedTeamAdmins += adminCount
		if unresolved {
			result.UnresolvedAdmins++
		}
	}
	if len(result.Errors) > 0 {
		recordGeneratedTeamReconcileAudit(ctx, opts, result, "error", "generated_team_errors")
		return result, fmt.Errorf("%w: generated team reconciliation has errors", ErrInvalidAuthzMapping)
	}

	applyID := strings.TrimSpace(opts.ApplyID)
	if applyID == "" {
		applyID = firstNonEmpty(opts.RunID, fmt.Sprintf("generated-team-%d", timeutil.TimeStampNow()))
	}
	applyResult, err := ApplyAuthzMappings(ctx, AuthzReconcileOptions{CorpID: opts.CorpID, ActorID: opts.ActorID, ApplyID: applyID})
	if err != nil {
		recordGeneratedTeamReconcileAudit(ctx, opts, result, "error", "membership_apply_failed")
		return result, err
	}
	result.AddedMemberships = len(applyResult.Additions)
	result.RemovedMemberships = len(applyResult.Removals)
	result.Skipped += len(applyResult.Skipped)
	recordGeneratedTeamReconcileAudit(ctx, opts, result, "success", "")
	return result, nil
}

func normalizeGeneratedTeamReconcileOptions(opts GeneratedTeamReconcileOptions) GeneratedTeamReconcileOptions {
	opts.CorpID = strings.TrimSpace(firstNonEmpty(opts.CorpID, setting.EnterpriseWeCom.CorpID))
	opts.AgentID = strings.TrimSpace(firstNonEmpty(opts.AgentID, setting.EnterpriseWeCom.AgentID))
	return opts
}

func ensureGeneratedGiteaTeam(ctx context.Context, opts GeneratedTeamReconcileOptions, generatedTeam *wecom_model.GeneratedTeam) (*organization.Team, bool, bool, error) {
	if generatedTeam.Status == wecom_model.GeneratedStateSkipped {
		skipReason, err := generatedTeamTargetSkipReason(ctx, opts, generatedTeam)
		if err != nil {
			return nil, false, false, err
		}
		if skipReason == "source_missing" || skipReason == "ambiguous_team" {
			return nil, false, true, nil
		}
	}
	if generatedTeam.TeamID > 0 {
		team, err := organization.GetTeamByID(ctx, generatedTeam.TeamID)
		if err != nil {
			return nil, false, false, err
		}
		if generatedTeam.TeamName != "" && team.Name != generatedTeam.TeamName {
			team.Name = generatedTeam.TeamName
			team.Description = "Managed by Enterprise WeCom directory automation."
			if err := org_service.UpdateTeam(ctx, team, false, false); err != nil {
				return nil, false, false, err
			}
		}
		return team, false, false, nil
	}
	skipReason, err := generatedTeamTargetSkipReason(ctx, opts, generatedTeam)
	if err != nil {
		return nil, false, false, err
	}
	if skipReason == "ambiguous_team" {
		return nil, false, true, nil
	}
	orgID := generatedTeam.OrgID
	if opts.OrgID > 0 {
		orgID = opts.OrgID
	}
	if orgID == 0 {
		return nil, false, false, fmt.Errorf("%w: generated team has no target organization", ErrInvalidAuthzMapping)
	}
	if generatedTeam.TeamName == "" {
		return nil, false, false, fmt.Errorf("%w: generated team has no team name", ErrInvalidAuthzMapping)
	}
	team := &organization.Team{
		OrgID:       orgID,
		Name:        generatedTeam.TeamName,
		Description: "Managed by Enterprise WeCom directory automation.",
		AccessMode:  perm.AccessModeRead,
		Visibility:  structs.VisibleTypePrivate,
	}
	if err := org_service.NewTeam(ctx, team); err != nil {
		if organization.IsErrTeamAlreadyExist(err) {
			existing, getErr := organization.GetTeam(ctx, orgID, generatedTeam.TeamName)
			return existing, false, false, getErr
		}
		return nil, false, false, err
	}
	return team, true, false, nil
}

func generatedTeamTargetSkipReason(ctx context.Context, opts GeneratedTeamReconcileOptions, generatedTeam *wecom_model.GeneratedTeam) (string, error) {
	mapping := &wecom_model.GeneratedMapping{
		CorpID:     opts.CorpID,
		AgentID:    opts.AgentID,
		SourceType: generatedTeam.SourceType,
		SourceID:   generatedTeam.SourceID,
		TargetType: wecom_model.AuthzTargetTeam,
	}
	sess := db.GetEngine(ctx)
	if opts.RunID != "" {
		sess = sess.Where("run_id = ?", opts.RunID)
	}
	has, err := sess.Get(mapping)
	if err != nil || !has {
		return "", err
	}
	return mapping.SkipReason, nil
}

func markGeneratedTeamApplied(ctx context.Context, opts GeneratedTeamReconcileOptions, generatedTeam *wecom_model.GeneratedTeam, teamID int64) error {
	now := timeutil.TimeStampNow()
	if _, err := db.GetEngine(ctx).
		Where("corp_id = ? AND agent_id = ? AND source_type = ? AND source_id = ?", opts.CorpID, opts.AgentID, generatedTeam.SourceType, generatedTeam.SourceID).
		Cols("team_id", "status", "last_apply_unix").
		Update(&wecom_model.GeneratedTeam{TeamID: teamID, Status: wecom_model.GeneratedStateApplied, LastApplyUnix: now}); err != nil {
		return err
	}
	_, err := db.GetEngine(ctx).
		Where("corp_id = ? AND agent_id = ? AND source_type = ? AND source_id = ? AND target_type = ?", opts.CorpID, opts.AgentID, generatedTeam.SourceType, generatedTeam.SourceID, wecom_model.AuthzTargetTeam).
		Cols("team_id", "status", "skip_reason", "last_apply_unix").
		Update(&wecom_model.GeneratedMapping{TeamID: teamID, Status: wecom_model.GeneratedStateApplied, SkipReason: "", LastApplyUnix: now})
	return err
}

func upsertGeneratedTeamAuthzMapping(ctx context.Context, opts GeneratedTeamReconcileOptions, generatedTeam *wecom_model.GeneratedTeam, teamID int64) error {
	mapping := &wecom_model.AuthzMapping{}
	has, err := db.GetEngine(ctx).
		Where("corp_id = ? AND source_type = ? AND source_id = ? AND target_type = ?", opts.CorpID, generatedTeam.SourceType, generatedTeam.SourceID, wecom_model.AuthzTargetTeam).
		Get(mapping)
	if err != nil {
		return err
	}
	if has {
		mapping.OrgID = generatedTeam.OrgID
		mapping.TeamID = teamID
		mapping.IsActive = true
		_, err = db.GetEngine(ctx).ID(mapping.ID).Cols("org_id", "team_id", "is_active").Update(mapping)
		return err
	}
	return db.Insert(ctx, &wecom_model.AuthzMapping{
		CorpID:     opts.CorpID,
		SourceType: generatedTeam.SourceType,
		SourceID:   generatedTeam.SourceID,
		TargetType: wecom_model.AuthzTargetTeam,
		OrgID:      generatedTeam.OrgID,
		TeamID:     teamID,
		IsActive:   true,
		CreatedBy:  opts.ActorID,
	})
}

func updateGeneratedTeamAdminsTarget(ctx context.Context, opts GeneratedTeamReconcileOptions, generatedTeam *wecom_model.GeneratedTeam, teamID int64) (int, bool, error) {
	if generatedTeam.AdminStatus == wecom_model.GeneratedStateUnresolved {
		return 0, true, nil
	}
	if _, err := db.GetEngine(ctx).
		Where("corp_id = ? AND agent_id = ? AND source_type = ? AND source_id = ? AND team_id = ?", opts.CorpID, opts.AgentID, generatedTeam.SourceType, generatedTeam.SourceID, 0).
		Cols("team_id").
		Update(&wecom_model.GeneratedTeamAdmin{TeamID: teamID}); err != nil {
		return 0, false, err
	}
	count, err := db.GetEngine(ctx).
		Where("corp_id = ? AND agent_id = ? AND source_type = ? AND source_id = ? AND team_id = ? AND status = ?", opts.CorpID, opts.AgentID, generatedTeam.SourceType, generatedTeam.SourceID, teamID, wecom_model.GeneratedStateApplied).
		Count(new(wecom_model.GeneratedTeamAdmin))
	return int(count), false, err
}

func recordGeneratedTeamReconcileAudit(ctx context.Context, opts GeneratedTeamReconcileOptions, result *GeneratedTeamReconcileResult, outcome, reason string) {
	metadata := []any{
		"run_id", opts.RunID,
		"outcome", outcome,
		"created_teams", result.CreatedTeams,
		"updated_teams", result.UpdatedTeams,
		"generated_team_admins", result.GeneratedTeamAdmins,
		"unresolved_admins", result.UnresolvedAdmins,
		"added_memberships", result.AddedMemberships,
		"removed_memberships", result.RemovedMemberships,
		"skipped", result.Skipped,
		"errors", len(result.Errors),
	}
	if reason != "" {
		metadata = append(metadata, "reason", reason)
	}
	audit.Record(ctx, audit_model.EnterpriseWeComTeamReconcile, nil, metadata...)
}

func recordTeamMaintenanceDenyAudit(ctx context.Context, teamID int64, operation TeamLocalMaintenanceOperation) {
	audit.Record(ctx, audit_model.EnterpriseWeComTeamMaintenanceDeny, nil,
		"team_id", teamID,
		"operation", operation,
		"reason", "managed_by_enterprise_wecom",
		"outcome", "denied",
	)
}
