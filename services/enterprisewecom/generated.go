// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/timeutil"
	"gitea.dev/services/audit"
)

type GeneratedDerivationOptions struct {
	CorpID  string
	AgentID string
	OrgID   int64
	RunID   string
	Now     timeutil.TimeStamp
}

type GeneratedDerivationResult struct {
	RunID               string
	GeneratedMappings   int
	GeneratedTeams      int
	GeneratedTeamAdmins int
	Skipped             int
	UnresolvedAdmins    int
}

type generatedTeamCandidate struct {
	SourceType        wecom_model.AuthzSourceType
	SourceID          string
	SourceName        string
	TeamName          string
	TeamID            int64
	MemberCount       int
	AdminUserIDs      []int64
	AdminWeComUserIDs []string
	AdminStatus       wecom_model.GeneratedState
	UnresolvedReason  string
	AdminSource       string
	DerivationRule    string
	TargetSkipReason  string
}

type generatedSourceKey struct {
	SourceType wecom_model.AuthzSourceType
	SourceID   string
}

func DeriveGeneratedAuthorizationState(ctx context.Context, opts GeneratedDerivationOptions) (*GeneratedDerivationResult, error) {
	var result *GeneratedDerivationResult
	err := withGeneratedMutation(ctx, func(ctx context.Context) error {
		var err error
		result, err = deriveGeneratedAuthorizationState(ctx, opts)
		return err
	})
	return result, safeGovernanceError("derive", err)
}

func deriveGeneratedAuthorizationState(ctx context.Context, opts GeneratedDerivationOptions) (*GeneratedDerivationResult, error) {
	if !setting.EnterpriseWeCom.Enabled {
		return nil, ErrWeComDisabled
	}
	opts = normalizeGeneratedDerivationOptions(opts)
	if err := configuredGovernanceScope(opts.CorpID, opts.AgentID); err != nil {
		return nil, err
	}
	if opts.CorpID == "" || opts.AgentID == "" {
		return nil, fmt.Errorf("%w: missing corp or agent id", ErrWeComDenied)
	}
	orgID, err := resolveGeneratedTargetOrg(ctx, opts.OrgID)
	if err != nil {
		return nil, err
	}
	opts.OrgID = orgID

	teams, err := organization.FindOrgTeams(ctx, orgID)
	if err != nil {
		return nil, err
	}
	teamsByName := map[string][]*organization.Team{}
	for _, team := range teams {
		teamsByName[strings.ToLower(team.Name)] = append(teamsByName[strings.ToLower(team.Name)], team)
	}

	candidates, err := loadGeneratedTeamCandidates(ctx, opts, teamsByName)
	if err != nil {
		return nil, err
	}
	result := &GeneratedDerivationResult{RunID: opts.RunID}
	err = db.WithTx(ctx, func(ctx context.Context) error {
		currentSources := make(map[generatedSourceKey]struct{}, len(candidates))
		for _, candidate := range candidates {
			currentSources[generatedSourceKey{SourceType: candidate.SourceType, SourceID: candidate.SourceID}] = struct{}{}
			if err := persistGeneratedCandidate(ctx, opts, candidate, result); err != nil {
				return err
			}
		}
		return deactivateStaleGeneratedSources(ctx, opts, currentSources, result)
	})
	recordGeneratedDerivationAudit(ctx, opts, result, err)
	return result, err
}

func normalizeGeneratedDerivationOptions(opts GeneratedDerivationOptions) GeneratedDerivationOptions {
	opts.CorpID = strings.TrimSpace(firstNonEmpty(opts.CorpID, setting.EnterpriseWeCom.CorpID))
	opts.AgentID = strings.TrimSpace(firstNonEmpty(opts.AgentID, setting.EnterpriseWeCom.AgentID))
	opts.RunID = strings.TrimSpace(opts.RunID)
	if opts.RunID == "" {
		opts.RunID = newGovernanceID("generated")
	}
	if opts.Now == 0 {
		opts.Now = timeutil.TimeStamp(time.Now().Unix())
	}
	return opts
}

func resolveGeneratedTargetOrg(ctx context.Context, orgID int64) (int64, error) {
	configured := setting.EnterpriseWeCom.ManagedOrgID
	if configured <= 0 {
		return 0, governanceError("preflight", "managed_org_unconfigured")
	}
	if orgID != 0 && orgID != configured {
		return 0, governanceError("preflight", "managed_org_override")
	}
	if org, err := organization.GetOrgByID(ctx, configured); err != nil || org.Type != user_model.UserTypeOrganization {
		return 0, governanceError("preflight", "managed_org_invalid")
	}
	conflicting, err := db.GetEngine(ctx).Where("corp_id = ? AND agent_id = ? AND org_id <> ?", setting.EnterpriseWeCom.CorpID, setting.EnterpriseWeCom.AgentID, configured).Exist(new(wecom_model.GeneratedTeam))
	if err != nil {
		return 0, safeGovernanceError("preflight", err)
	}
	if conflicting {
		return 0, governanceError("preflight", "managed_org_conflict")
	}
	conflicting, err = db.GetEngine(ctx).Where("corp_id = ? AND agent_id = ? AND origin = ? AND org_id <> ?", setting.EnterpriseWeCom.CorpID, setting.EnterpriseWeCom.AgentID, wecom_model.AuthzMappingOriginGenerated, configured).Exist(new(wecom_model.AuthzMapping))
	if err != nil {
		return 0, safeGovernanceError("preflight", err)
	}
	if conflicting {
		return 0, governanceError("preflight", "managed_org_conflict")
	}
	var legacy []wecom_model.AuthzMapping
	if err := db.GetEngine(ctx).Where("corp_id = ? AND origin = ?", setting.EnterpriseWeCom.CorpID, wecom_model.AuthzMappingOriginLegacy).Find(&legacy); err != nil {
		return 0, safeGovernanceError("preflight", err)
	}
	for _, mapping := range legacy {
		if mapping.TargetType != wecom_model.AuthzTargetTeam {
			continue
		}
		count, err := db.GetEngine(ctx).Where("corp_id = ? AND agent_id = ? AND source_type = ? AND source_id = ? AND org_id = ? AND team_id = ?", mapping.CorpID, setting.EnterpriseWeCom.AgentID, mapping.SourceType, mapping.SourceID, mapping.OrgID, mapping.TeamID).Count(new(wecom_model.GeneratedTeam))
		if err != nil {
			return 0, safeGovernanceError("preflight", err)
		}
		if count > 0 {
			return 0, governanceError("preflight", "mapping_origin_conflict")
		}
	}
	return configured, nil
}

func loadGeneratedTeamCandidates(ctx context.Context, opts GeneratedDerivationOptions, teamsByName map[string][]*organization.Team) ([]generatedTeamCandidate, error) {
	var departments []wecom_model.Department
	if err := db.GetEngine(ctx).Where("corp_id = ?", opts.CorpID).OrderBy("department_id").Find(&departments); err != nil {
		return nil, err
	}
	var tags []wecom_model.Tag
	if err := db.GetEngine(ctx).Where("corp_id = ?", opts.CorpID).OrderBy("tag_id").Find(&tags); err != nil {
		return nil, err
	}

	candidates := make([]generatedTeamCandidate, 0, len(departments)+len(tags))
	for _, dept := range departments {
		teamName := generatedTeamName("dept", dept.Name, dept.DepartmentID)
		candidate := generatedTeamCandidate{
			SourceType:     wecom_model.AuthzSourceDepartment,
			SourceID:       strconv.FormatInt(dept.DepartmentID, 10),
			SourceName:     dept.Name,
			TeamName:       teamName,
			DerivationRule: "department_to_team",
			AdminSource:    "department_leader",
		}
		candidate.TeamID, candidate.TargetSkipReason = resolveGeneratedTeamTarget(teamsByName, teamName)
		memberCount, adminUserIDs, adminWeComUserIDs, adminStatus, unresolvedReason, err := departmentGeneratedAdmins(ctx, opts.CorpID, dept)
		if err != nil {
			return nil, err
		}
		candidate.MemberCount = memberCount
		candidate.AdminUserIDs = adminUserIDs
		candidate.AdminWeComUserIDs = adminWeComUserIDs
		candidate.AdminStatus = adminStatus
		candidate.UnresolvedReason = unresolvedReason
		candidates = append(candidates, candidate)
	}
	for _, tag := range tags {
		teamName := generatedTeamName("tag", tag.Name, tag.TagID)
		memberCount, err := countMemberships(ctx, opts.CorpID, wecom_model.MembershipTag, tag.TagID)
		if err != nil {
			return nil, err
		}
		candidate := generatedTeamCandidate{
			SourceType:       wecom_model.AuthzSourceTag,
			SourceID:         strconv.FormatInt(tag.TagID, 10),
			SourceName:       tag.Name,
			TeamName:         teamName,
			MemberCount:      memberCount,
			AdminStatus:      wecom_model.GeneratedStateUnresolved,
			UnresolvedReason: "tag_has_no_admin_metadata",
			DerivationRule:   "tag_to_team",
			AdminSource:      "unsupported_tag_metadata",
		}
		candidate.TeamID, candidate.TargetSkipReason = resolveGeneratedTeamTarget(teamsByName, teamName)
		candidates = append(candidates, candidate)
	}
	return candidates, nil
}

func resolveGeneratedTeamTarget(teamsByName map[string][]*organization.Team, teamName string) (int64, string) {
	teams := teamsByName[strings.ToLower(teamName)]
	switch len(teams) {
	case 0:
		return 0, "missing_team"
	case 1:
		return teams[0].ID, ""
	default:
		return 0, "ambiguous_team"
	}
}

func generatedTeamName(prefix, name string, sourceID int64) string {
	slug, _ := user_model.NormalizeUserName(name)
	slug = strings.Trim(strings.ToLower(slug), "-.")
	if slug == "" {
		slug = strconv.FormatInt(sourceID, 10)
	}
	teamName := fmt.Sprintf("%s-%d-%s", prefix, sourceID, slug)
	if len(teamName) > 255 {
		teamName = teamName[:255]
	}
	if err := organization.IsUsableTeamName(teamName); err != nil {
		return fmt.Sprintf("%s-%d", prefix, sourceID)
	}
	return teamName
}

func departmentGeneratedAdmins(ctx context.Context, corpID string, dept wecom_model.Department) (int, []int64, []string, wecom_model.GeneratedState, string, error) {
	memberships := make([]wecom_model.Membership, 0)
	if err := db.GetEngine(ctx).Where("corp_id = ? AND kind = ? AND target_id = ?", corpID, wecom_model.MembershipDepartment, dept.DepartmentID).Find(&memberships); err != nil {
		return 0, nil, nil, "", "", err
	}
	leaderIDs := append([]string{}, wecom_model.DecodeLeaderUserIDs(dept.LeaderUserIDs)...)
	for _, membership := range memberships {
		if membership.IsLeader && !slices.Contains(leaderIDs, membership.WeComUserID) {
			leaderIDs = append(leaderIDs, membership.WeComUserID)
		}
	}
	if len(leaderIDs) == 0 {
		return len(memberships), nil, nil, wecom_model.GeneratedStateUnresolved, "no_admin_metadata", nil
	}
	adminUserIDs := make([]int64, 0, len(leaderIDs))
	adminWeComUserIDs := make([]string, 0, len(leaderIDs))
	for _, wecomUserID := range leaderIDs {
		identity, has, err := wecom_model.GetIdentityByCorpAndUserID(ctx, corpID, wecomUserID)
		if err != nil {
			return 0, nil, nil, "", "", err
		}
		if !has || identity.UserID == 0 || identity.Status != wecom_model.IdentityStatusActive {
			continue
		}
		adminUserIDs = append(adminUserIDs, identity.UserID)
		adminWeComUserIDs = append(adminWeComUserIDs, wecomUserID)
	}
	if len(adminUserIDs) == 0 {
		return len(memberships), nil, nil, wecom_model.GeneratedStateUnresolved, "admin_identity_unbound_or_inactive", nil
	}
	return len(memberships), adminUserIDs, adminWeComUserIDs, wecom_model.GeneratedStateApplied, "", nil
}

func countMemberships(ctx context.Context, corpID string, kind wecom_model.MembershipKind, targetID int64) (int, error) {
	count, err := db.GetEngine(ctx).Where("corp_id = ? AND kind = ? AND target_id = ?", corpID, kind, targetID).Count(new(wecom_model.Membership))
	return int(count), err
}

func persistGeneratedCandidate(ctx context.Context, opts GeneratedDerivationOptions, candidate generatedTeamCandidate, result *GeneratedDerivationResult) error {
	teamStatus := wecom_model.GeneratedStateApplied
	mappingStatus := wecom_model.GeneratedStateApplied
	skipReason := ""
	if candidate.TeamID == 0 {
		teamStatus = wecom_model.GeneratedStateSkipped
		mappingStatus = wecom_model.GeneratedStateSkipped
		skipReason = firstNonEmpty(candidate.TargetSkipReason, "missing_team")
		result.Skipped++
	}
	if candidate.AdminStatus == wecom_model.GeneratedStateUnresolved {
		result.UnresolvedAdmins++
	}
	if err := upsertGeneratedTeam(ctx, opts, candidate, teamStatus); err != nil {
		return err
	}
	if err := db.Insert(ctx, &wecom_model.GeneratedMapping{
		RunID:          opts.RunID,
		CorpID:         opts.CorpID,
		AgentID:        opts.AgentID,
		SourceType:     candidate.SourceType,
		SourceID:       candidate.SourceID,
		SourceName:     candidate.SourceName,
		TargetType:     wecom_model.AuthzTargetTeam,
		OrgID:          opts.OrgID,
		TeamID:         candidate.TeamID,
		DerivationRule: candidate.DerivationRule,
		Status:         mappingStatus,
		SkipReason:     skipReason,
		MemberCount:    candidate.MemberCount,
		AdminCount:     len(candidate.AdminUserIDs),
		LastApplyUnix:  opts.Now,
	}); err != nil {
		return err
	}
	result.GeneratedMappings++
	result.GeneratedTeams++
	for idx, adminUserID := range candidate.AdminUserIDs {
		adminWeComUserID := ""
		if idx < len(candidate.AdminWeComUserIDs) {
			adminWeComUserID = candidate.AdminWeComUserIDs[idx]
		}
		if err := upsertGeneratedTeamAdmin(ctx, opts, candidate, adminUserID, adminWeComUserID); err != nil {
			return err
		}
		result.GeneratedTeamAdmins++
	}
	return markStaleGeneratedTeamAdmins(ctx, opts, candidate)
}

func upsertGeneratedTeam(ctx context.Context, opts GeneratedDerivationOptions, candidate generatedTeamCandidate, status wecom_model.GeneratedState) error {
	row := &wecom_model.GeneratedTeam{
		CorpID:     opts.CorpID,
		AgentID:    opts.AgentID,
		SourceType: candidate.SourceType,
		SourceID:   candidate.SourceID,
	}
	has, err := db.GetEngine(ctx).Get(row)
	if err != nil {
		return err
	}
	row.RunID = opts.RunID
	row.SourceName = candidate.SourceName
	row.OrgID = opts.OrgID
	row.TeamID = candidate.TeamID
	row.TeamName = candidate.TeamName
	row.DerivationRule = candidate.DerivationRule
	row.Status = status
	row.AdminStatus = candidate.AdminStatus
	row.UnresolvedReason = candidate.UnresolvedReason
	row.MemberCount = candidate.MemberCount
	row.AdminCount = len(candidate.AdminUserIDs)
	row.LastApplyUnix = opts.Now
	if has {
		_, err = db.GetEngine(ctx).ID(row.ID).Cols(
			"run_id", "source_name", "org_id", "team_id", "team_name", "derivation_rule", "status", "admin_status", "unresolved_reason", "member_count", "admin_count", "last_apply_unix",
		).Update(row)
		return err
	}
	return db.Insert(ctx, row)
}

func upsertGeneratedTeamAdmin(ctx context.Context, opts GeneratedDerivationOptions, candidate generatedTeamCandidate, adminUserID int64, adminWeComUserID string) error {
	row := &wecom_model.GeneratedTeamAdmin{
		CorpID:      opts.CorpID,
		AgentID:     opts.AgentID,
		SourceType:  candidate.SourceType,
		SourceID:    candidate.SourceID,
		TeamID:      candidate.TeamID,
		UserID:      adminUserID,
		WeComUserID: adminWeComUserID,
	}
	has, err := db.GetEngine(ctx).Get(row)
	if err != nil {
		return err
	}
	row.RunID = opts.RunID
	row.AdminSource = candidate.AdminSource
	row.Status = wecom_model.GeneratedStateApplied
	row.Reason = ""
	row.LastApplyUnix = opts.Now
	if has {
		_, err = db.GetEngine(ctx).ID(row.ID).Cols("run_id", "admin_source", "status", "reason", "last_apply_unix").Update(row)
		return err
	}
	return db.Insert(ctx, row)
}

func markStaleGeneratedTeamAdmins(ctx context.Context, opts GeneratedDerivationOptions, candidate generatedTeamCandidate) error {
	var admins []wecom_model.GeneratedTeamAdmin
	if err := db.GetEngine(ctx).
		Where("corp_id = ? AND agent_id = ? AND source_type = ? AND source_id = ?", opts.CorpID, opts.AgentID, candidate.SourceType, candidate.SourceID).
		Find(&admins); err != nil {
		return err
	}
	current := make(map[int64]bool, len(candidate.AdminUserIDs))
	for _, adminUserID := range candidate.AdminUserIDs {
		current[adminUserID] = true
	}
	for _, admin := range admins {
		if current[admin.UserID] {
			continue
		}
		if _, err := db.GetEngine(ctx).ID(admin.ID).Cols("run_id", "status", "reason", "last_apply_unix").Update(&wecom_model.GeneratedTeamAdmin{
			RunID:         opts.RunID,
			Status:        wecom_model.GeneratedStateSkipped,
			Reason:        "admin_metadata_removed",
			LastApplyUnix: opts.Now,
		}); err != nil {
			return err
		}
	}
	return nil
}

func deactivateStaleGeneratedSources(ctx context.Context, opts GeneratedDerivationOptions, currentSources map[generatedSourceKey]struct{}, result *GeneratedDerivationResult) error {
	var staleTeams []wecom_model.GeneratedTeam
	if err := db.GetEngine(ctx).Where("corp_id = ? AND agent_id = ?", opts.CorpID, opts.AgentID).OrderBy("team_id, id").Find(&staleTeams); err != nil {
		return err
	}
	for _, generatedTeam := range staleTeams {
		if _, ok := currentSources[generatedSourceKey{SourceType: generatedTeam.SourceType, SourceID: generatedTeam.SourceID}]; ok {
			continue
		}
		if err := markGeneratedSourceMissing(ctx, opts, &generatedTeam); err != nil {
			return err
		}
		if result != nil {
			result.Skipped++
		}
	}
	return nil
}

func markGeneratedSourceMissing(ctx context.Context, opts GeneratedDerivationOptions, generatedTeam *wecom_model.GeneratedTeam) error {
	_, err := db.GetEngine(ctx).ID(generatedTeam.ID).Cols(
		"run_id", "status", "admin_status", "unresolved_reason", "member_count", "admin_count", "last_apply_unix",
	).Update(&wecom_model.GeneratedTeam{
		RunID:            opts.RunID,
		Status:           wecom_model.GeneratedStateSkipped,
		AdminStatus:      wecom_model.GeneratedStateUnresolved,
		UnresolvedReason: "source_missing",
		MemberCount:      0,
		AdminCount:       0,
		LastApplyUnix:    opts.Now,
	})
	if err != nil {
		return err
	}
	if _, err := db.GetEngine(ctx).
		Where("corp_id = ? AND agent_id = ? AND source_type = ? AND source_id = ?", opts.CorpID, opts.AgentID, generatedTeam.SourceType, generatedTeam.SourceID).
		Cols("run_id", "status", "reason", "last_apply_unix").
		Update(&wecom_model.GeneratedTeamAdmin{RunID: opts.RunID, Status: wecom_model.GeneratedStateSkipped, Reason: "source_missing", LastApplyUnix: opts.Now}); err != nil {
		return err
	}
	if _, err := db.GetEngine(ctx).
		Where("corp_id = ? AND agent_id = ? AND origin = ? AND org_id = ? AND source_type = ? AND source_id = ? AND target_type = ?", opts.CorpID, opts.AgentID, wecom_model.AuthzMappingOriginGenerated, opts.OrgID, generatedTeam.SourceType, generatedTeam.SourceID, wecom_model.AuthzTargetTeam).
		Cols("is_active").
		Update(&wecom_model.AuthzMapping{IsActive: false}); err != nil {
		return err
	}
	return db.Insert(ctx, &wecom_model.GeneratedMapping{
		RunID:          opts.RunID,
		CorpID:         opts.CorpID,
		AgentID:        opts.AgentID,
		SourceType:     generatedTeam.SourceType,
		SourceID:       generatedTeam.SourceID,
		SourceName:     generatedTeam.SourceName,
		TargetType:     wecom_model.AuthzTargetTeam,
		OrgID:          generatedTeam.OrgID,
		TeamID:         generatedTeam.TeamID,
		DerivationRule: generatedTeam.DerivationRule,
		Status:         wecom_model.GeneratedStateSkipped,
		SkipReason:     "source_missing",
		LastApplyUnix:  opts.Now,
	})
}

func recordGeneratedDerivationAudit(ctx context.Context, opts GeneratedDerivationOptions, result *GeneratedDerivationResult, err error) {
	outcome := "success"
	reason := ""
	if err != nil {
		outcome = "error"
		reason = "derive_failed"
	}
	metadata := []any{
		"run_id", opts.RunID,
		"corp_id", opts.CorpID,
		"agent_id", opts.AgentID,
		"outcome", outcome,
	}
	if reason != "" {
		metadata = append(metadata, "reason", reason)
	}
	if result != nil {
		metadata = append(metadata,
			"generated_mappings", result.GeneratedMappings,
			"generated_teams", result.GeneratedTeams,
			"generated_team_admins", result.GeneratedTeamAdmins,
			"skipped", result.Skipped,
			"unresolved_admins", result.UnresolvedAdmins,
		)
	}
	audit.RecordAs(ctx, user_model.NewAuthSourceUser(), audit_model.EnterpriseWeComGeneratedDerive, nil, metadata...)
}
