// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/timeutil"
	"gitea.dev/services/audit"
	org_service "gitea.dev/services/org"
)

type AuthzReconcileOptions struct {
	AgentID string
	OrgID   int64
	CorpID  string
	ActorID int64
	ApplyID string
}

type AuthzMembershipChange struct {
	MappingID  int64
	UserID     int64
	TargetType wecom_model.AuthzTargetType
	OrgID      int64
	TeamID     int64
}

type AuthzSkippedIdentity struct {
	MappingID    int64
	WeComUserID  string
	Reason       string
	Status       wecom_model.IdentityStatus
	BoundUserID  int64
	SourceType   wecom_model.AuthzSourceType
	SourceID     string
	TargetType   wecom_model.AuthzTargetType
	TargetOrgID  int64
	TargetTeamID int64
}

type AuthzReconcileResult struct {
	Additions         []AuthzMembershipChange
	Removals          []AuthzMembershipChange
	ProtectedRemovals []AuthzMembershipChange
	Skipped           []AuthzSkippedIdentity
	Errors            []string

	desiredChanges      []AuthzMembershipChange
	staleManagedChanges []AuthzMembershipChange
	nativeMemberBefore  map[authzTargetUserKey]bool
	managedMemberBefore map[authzTargetUserKey]bool
}

type authzManagedKey struct {
	MappingID int64
	authzTargetUserKey
}

type authzTargetUserKey struct {
	UserID     int64
	TargetType wecom_model.AuthzTargetType
	OrgID      int64
	TeamID     int64
}

func compareTargetUserKeys(a, b authzTargetUserKey) int {
	return cmp.Or(cmp.Compare(a.OrgID, b.OrgID), cmp.Compare(a.TeamID, b.TeamID), cmp.Compare(a.TargetType, b.TargetType), cmp.Compare(a.UserID, b.UserID))
}

func orderedTargetUserKeys(changes map[authzTargetUserKey][]AuthzMembershipChange) []authzTargetUserKey {
	return slices.SortedFunc(maps.Keys(changes), compareTargetUserKeys)
}

func PlanAuthzMappings(ctx context.Context, opts AuthzReconcileOptions) (*AuthzReconcileResult, error) {
	corpID := normalizeReconcileCorpID(opts.CorpID)
	result := &AuthzReconcileResult{
		nativeMemberBefore:  make(map[authzTargetUserKey]bool),
		managedMemberBefore: make(map[authzTargetUserKey]bool),
	}
	if corpID == "" {
		result.Errors = append(result.Errors, "missing corp id")
		return result, nil
	}

	if err := configuredGovernanceScope(corpID, firstNonEmpty(opts.AgentID, setting.EnterpriseWeCom.AgentID)); err != nil {
		return nil, err
	}
	orgID, err := resolveGeneratedTargetOrg(ctx, opts.OrgID)
	if err != nil {
		return nil, err
	}
	var allMappings []*wecom_model.AuthzMapping
	err = db.GetEngine(ctx).Where("corp_id = ? AND agent_id = ? AND origin = ? AND org_id = ?", corpID, setting.EnterpriseWeCom.AgentID, wecom_model.AuthzMappingOriginGenerated, orgID).OrderBy("id ASC").Find(&allMappings)
	if err != nil {
		return nil, err
	}
	activeMappings := make([]*wecom_model.AuthzMapping, 0, len(allMappings))
	mappingIDs := make([]int64, 0, len(allMappings))
	for _, mapping := range allMappings {
		mappingIDs = append(mappingIDs, mapping.ID)
		if mapping.IsActive {
			activeMappings = append(activeMappings, mapping)
		}
	}

	desiredByManagedKey := make(map[authzManagedKey]AuthzMembershipChange)
	desiredByTargetUser := make(map[authzTargetUserKey][]AuthzMembershipChange)
	for _, mapping := range activeMappings {
		if err := validateExistingMappingTarget(ctx, mapping); err != nil {
			return nil, safeGovernanceError("plan", err)
		}
		changes, skipped, err := resolveMappingUsers(ctx, mapping)
		if err != nil {
			return nil, safeGovernanceError("plan", err)
		}
		result.Skipped = append(result.Skipped, skipped...)
		for _, change := range changes {
			managedKey := makeManagedKey(change)
			if _, ok := desiredByManagedKey[managedKey]; ok {
				continue
			}
			targetKey := makeTargetUserKey(change)
			desiredByManagedKey[managedKey] = change
			desiredByTargetUser[targetKey] = append(desiredByTargetUser[targetKey], change)
			result.desiredChanges = append(result.desiredChanges, change)
		}
	}

	managedRows, err := listManagedMembershipsForMappings(ctx, mappingIDs)
	if err != nil {
		return nil, err
	}
	currentManagedByTargetUser := make(map[authzTargetUserKey][]AuthzMembershipChange)
	for _, managed := range managedRows {
		change := changeFromManagedMembership(managed)
		targetKey := makeTargetUserKey(change)
		result.managedMemberBefore[targetKey] = true
		currentManagedByTargetUser[targetKey] = append(currentManagedByTargetUser[targetKey], change)
		if _, ok := desiredByManagedKey[makeManagedKey(change)]; !ok {
			result.staleManagedChanges = append(result.staleManagedChanges, change)
		}
	}

	for _, targetKey := range orderedTargetUserKeys(desiredByTargetUser) {
		changes := desiredByTargetUser[targetKey]
		hasMembership, err := hasNativeMembership(ctx, targetKey)
		if err != nil {
			return nil, err
		}
		result.nativeMemberBefore[targetKey] = hasMembership
		if !hasMembership {
			result.Additions = append(result.Additions, changes[0])
		}
	}

	seenRemoval := make(map[authzTargetUserKey]bool)
	for _, targetKey := range orderedTargetUserKeys(currentManagedByTargetUser) {
		changes := currentManagedByTargetUser[targetKey]
		if _, stillDesired := desiredByTargetUser[targetKey]; stillDesired {
			continue
		}
		if seenRemoval[targetKey] {
			continue
		}
		hasMembership, err := hasNativeMembership(ctx, targetKey)
		if err != nil {
			return nil, err
		}
		result.nativeMemberBefore[targetKey] = hasMembership
		shared, err := db.GetEngine(ctx).Where("user_id = ? AND target_type = ? AND org_id = ? AND team_id = ?", targetKey.UserID, targetKey.TargetType, targetKey.OrgID, targetKey.TeamID).NotIn("mapping_id", mappingIDs).Exist(new(wecom_model.ManagedMembership))
		if err != nil {
			return nil, err
		}
		if hasMembership && !shared {
			result.Removals = append(result.Removals, changes[0])
		}
		seenRemoval[targetKey] = true
	}

	return result, nil
}

func ApplyAuthzMappings(ctx context.Context, opts AuthzReconcileOptions) (*AuthzReconcileResult, error) {
	var result *AuthzReconcileResult
	err := withGeneratedMutation(ctx, func(ctx context.Context) error {
		var err error
		result, err = applyAuthzMappings(ctx, opts)
		return err
	})
	return result, safeGovernanceError("memberships", err)
}

func applyAuthzMappings(ctx context.Context, opts AuthzReconcileOptions) (*AuthzReconcileResult, error) {
	result, err := PlanAuthzMappings(ctx, opts)
	if err != nil {
		recordMappingApplyAudit(ctx, opts.ActorID, result, "error", "plan_failed")
		return result, err
	}
	if len(result.Errors) > 0 {
		recordMappingApplyAudit(ctx, opts.ActorID, result, "error", "invalid_plan")
		return result, fmt.Errorf("%w: reconciliation plan has errors", ErrInvalidAuthzMapping)
	}

	applyID := strings.TrimSpace(opts.ApplyID)
	if applyID == "" {
		applyID = newGovernanceID("apply")
	}
	sortChanges := func(a, b AuthzMembershipChange) int {
		return cmp.Or(compareTargetUserKeys(makeTargetUserKey(a), makeTargetUserKey(b)), cmp.Compare(a.MappingID, b.MappingID))
	}
	slices.SortFunc(result.Removals, sortChanges)
	slices.SortFunc(result.staleManagedChanges, sortChanges)
	err = db.WithTx(ctx, func(ctx context.Context) error {
		protectedKeys := make(map[authzTargetUserKey]bool)
		for _, removal := range result.Removals {
			protected, err := removeAuthzMembership(ctx, removal)
			if err != nil {
				return err
			}
			if protected {
				result.ProtectedRemovals = append(result.ProtectedRemovals, removal)
				protectedKeys[makeTargetUserKey(removal)] = true
			}
		}

		for _, stale := range result.staleManagedChanges {
			if protectedKeys[makeTargetUserKey(stale)] {
				continue
			}
			if err := deleteManagedMembership(ctx, stale); err != nil {
				return err
			}
		}

		desiredByTargetUser := groupChangesByTargetUser(result.desiredChanges)
		for _, targetKey := range orderedTargetUserKeys(desiredByTargetUser) {
			changes := desiredByTargetUser[targetKey]
			hasMembership, err := hasNativeMembership(ctx, targetKey)
			if err != nil {
				return err
			}
			managedBefore := result.managedMemberBefore[targetKey]
			if !managedBefore && hasMembership {
				managedBefore, err = db.GetEngine(ctx).Where("user_id = ? AND target_type = ? AND org_id = ? AND team_id = ?", targetKey.UserID, targetKey.TargetType, targetKey.OrgID, targetKey.TeamID).Exist(new(wecom_model.ManagedMembership))
				if err != nil {
					return err
				}
			}
			if !hasMembership {
				if err := addAuthzMembership(ctx, changes[0]); err != nil {
					return err
				}
				managedBefore = true
			}
			if !managedBefore {
				continue
			}
			for _, change := range changes {
				if err := upsertManagedMembership(ctx, change, applyID); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		recordMappingApplyAudit(ctx, opts.ActorID, result, "error", "apply_failed")
		return result, err
	}
	recordMappingApplyAudit(ctx, opts.ActorID, result, "applied", "")
	return result, nil
}

func normalizeReconcileCorpID(corpID string) string {
	corpID = strings.TrimSpace(corpID)
	if corpID == "" {
		corpID = setting.EnterpriseWeCom.CorpID
	}
	return corpID
}

func validateExistingMappingTarget(ctx context.Context, mapping *wecom_model.AuthzMapping) error {
	orgID, teamID, err := validateMappingTarget(ctx, mapping.TargetType, mapping.OrgID, mapping.TeamID)
	if err != nil {
		return fmt.Errorf("mapping %d: %w", mapping.ID, err)
	}
	if orgID != mapping.OrgID || teamID != mapping.TeamID {
		return fmt.Errorf("mapping %d: %w: target changed", mapping.ID, ErrInvalidAuthzMapping)
	}
	return nil
}

func resolveMappingUsers(ctx context.Context, mapping *wecom_model.AuthzMapping) ([]AuthzMembershipChange, []AuthzSkippedIdentity, error) {
	switch mapping.SourceType {
	case wecom_model.AuthzSourceUser:
		identity, has, err := wecom_model.GetIdentityByCorpAndUserID(ctx, mapping.CorpID, mapping.SourceID)
		if err != nil {
			return nil, nil, err
		}
		if !has {
			return nil, []AuthzSkippedIdentity{skippedIdentity(mapping, mapping.SourceID, "identity_not_found", nil)}, nil
		}
		return changesForIdentities(ctx, mapping, []*wecom_model.Identity{identity})
	case wecom_model.AuthzSourceDepartment:
		return resolveMembershipSource(ctx, mapping, wecom_model.MembershipDepartment)
	case wecom_model.AuthzSourceTag:
		return resolveMembershipSource(ctx, mapping, wecom_model.MembershipTag)
	default:
		return nil, nil, fmt.Errorf("mapping %d: %w: unsupported source type", mapping.ID, ErrInvalidAuthzMapping)
	}
}

func resolveMembershipSource(ctx context.Context, mapping *wecom_model.AuthzMapping, kind wecom_model.MembershipKind) ([]AuthzMembershipChange, []AuthzSkippedIdentity, error) {
	targetID, err := strconv.ParseInt(mapping.SourceID, 10, 64)
	if err != nil {
		return nil, nil, fmt.Errorf("mapping %d: %w: source id must be numeric", mapping.ID, ErrInvalidAuthzMapping)
	}
	var memberships []*wecom_model.Membership
	if err := db.GetEngine(ctx).
		Where("corp_id = ? AND kind = ? AND target_id = ?", mapping.CorpID, kind, targetID).
		OrderBy("wecom_userid ASC").
		Find(&memberships); err != nil {
		return nil, nil, err
	}
	identities := make([]*wecom_model.Identity, 0, len(memberships))
	skipped := make([]AuthzSkippedIdentity, 0)
	for _, membership := range memberships {
		identity, has, err := wecom_model.GetIdentityByCorpAndUserID(ctx, mapping.CorpID, membership.WeComUserID)
		if err != nil {
			return nil, nil, err
		}
		if !has {
			skipped = append(skipped, skippedIdentity(mapping, membership.WeComUserID, "identity_not_found", nil))
			continue
		}
		identities = append(identities, identity)
	}
	changes, identitySkips, err := changesForIdentities(ctx, mapping, identities)
	if err != nil {
		return nil, nil, err
	}
	skipped = append(skipped, identitySkips...)
	changes, adminSkips, err := appendGeneratedTeamAdminChanges(ctx, mapping, changes)
	if err != nil {
		return nil, nil, err
	}
	skipped = append(skipped, adminSkips...)
	return changes, skipped, nil
}

func changesForIdentities(ctx context.Context, mapping *wecom_model.AuthzMapping, identities []*wecom_model.Identity) ([]AuthzMembershipChange, []AuthzSkippedIdentity, error) {
	changes := make([]AuthzMembershipChange, 0, len(identities))
	skipped := make([]AuthzSkippedIdentity, 0)
	seenUsers := make(map[int64]bool)
	for _, identity := range identities {
		if identity == nil {
			continue
		}
		if !identity.ActiveForLogin() {
			skipped = append(skipped, skippedIdentity(mapping, identity.WeComUserID, "identity_inactive", identity))
			continue
		}
		if identity.UserID == 0 {
			skipped = append(skipped, skippedIdentity(mapping, identity.WeComUserID, "identity_unbound", identity))
			continue
		}
		if seenUsers[identity.UserID] {
			continue
		}
		if _, err := user_model.GetUserByID(ctx, identity.UserID); err != nil {
			if !user_model.IsErrUserNotExist(err) {
				return nil, nil, err
			}
			skipped = append(skipped, skippedIdentity(mapping, identity.WeComUserID, "gitea_user_not_found", identity))
			continue
		}
		seenUsers[identity.UserID] = true
		changes = append(changes, AuthzMembershipChange{
			MappingID:  mapping.ID,
			UserID:     identity.UserID,
			TargetType: mapping.TargetType,
			OrgID:      mapping.OrgID,
			TeamID:     mapping.TeamID,
		})
	}
	return changes, skipped, nil
}

func appendGeneratedTeamAdminChanges(ctx context.Context, mapping *wecom_model.AuthzMapping, changes []AuthzMembershipChange) ([]AuthzMembershipChange, []AuthzSkippedIdentity, error) {
	if mapping.TargetType != wecom_model.AuthzTargetTeam || mapping.TeamID == 0 {
		return changes, nil, nil
	}
	var admins []wecom_model.GeneratedTeamAdmin
	if err := db.GetEngine(ctx).
		Where("corp_id = ? AND agent_id = ? AND source_type = ? AND source_id = ? AND team_id = ? AND status = ? AND user_id > 0", mapping.CorpID, mapping.AgentID, mapping.SourceType, mapping.SourceID, mapping.TeamID, wecom_model.GeneratedStateApplied).
		Find(&admins); err != nil {
		return nil, nil, err
	}
	if len(admins) == 0 {
		return changes, nil, nil
	}
	seenUsers := make(map[int64]bool, len(changes)+len(admins))
	for _, change := range changes {
		seenUsers[change.UserID] = true
	}
	skipped := make([]AuthzSkippedIdentity, 0)
	for _, admin := range admins {
		if seenUsers[admin.UserID] {
			continue
		}
		if _, err := user_model.GetUserByID(ctx, admin.UserID); err != nil {
			if !user_model.IsErrUserNotExist(err) {
				return nil, nil, err
			}
			skipped = append(skipped, skippedIdentity(mapping, admin.WeComUserID, "generated_admin_user_not_found", nil))
			continue
		}
		seenUsers[admin.UserID] = true
		changes = append(changes, AuthzMembershipChange{
			MappingID:  mapping.ID,
			UserID:     admin.UserID,
			TargetType: mapping.TargetType,
			OrgID:      mapping.OrgID,
			TeamID:     mapping.TeamID,
		})
	}
	return changes, skipped, nil
}

func skippedIdentity(mapping *wecom_model.AuthzMapping, wecomUserID, reason string, identity *wecom_model.Identity) AuthzSkippedIdentity {
	skipped := AuthzSkippedIdentity{
		MappingID:    mapping.ID,
		WeComUserID:  wecomUserID,
		Reason:       reason,
		SourceType:   mapping.SourceType,
		SourceID:     mapping.SourceID,
		TargetType:   mapping.TargetType,
		TargetOrgID:  mapping.OrgID,
		TargetTeamID: mapping.TeamID,
	}
	if identity != nil {
		skipped.Status = identity.Status
		skipped.BoundUserID = identity.UserID
	}
	return skipped
}

func listManagedMembershipsForMappings(ctx context.Context, mappingIDs []int64) ([]*wecom_model.ManagedMembership, error) {
	if len(mappingIDs) == 0 {
		return nil, nil
	}
	var managed []*wecom_model.ManagedMembership
	err := db.GetEngine(ctx).In("mapping_id", mappingIDs).OrderBy("id ASC").Find(&managed)
	return managed, err
}

func hasNativeMembership(ctx context.Context, key authzTargetUserKey) (bool, error) {
	switch key.TargetType {
	case wecom_model.AuthzTargetOrg:
		return organization.IsOrganizationMember(ctx, key.OrgID, key.UserID)
	case wecom_model.AuthzTargetTeam:
		return organization.IsTeamMember(ctx, key.OrgID, key.TeamID, key.UserID)
	default:
		return false, fmt.Errorf("%w: unsupported target type", ErrInvalidAuthzMapping)
	}
}

func addAuthzMembership(ctx context.Context, change AuthzMembershipChange) error {
	user, err := user_model.GetUserByID(ctx, change.UserID)
	if err != nil {
		return err
	}
	switch change.TargetType {
	case wecom_model.AuthzTargetOrg:
		return organization.AddOrgUser(ctx, change.OrgID, change.UserID)
	case wecom_model.AuthzTargetTeam:
		team, err := organization.GetTeamByID(ctx, change.TeamID)
		if err != nil {
			return err
		}
		return org_service.AddTeamMember(ctx, team, user)
	default:
		return fmt.Errorf("%w: unsupported target type", ErrInvalidAuthzMapping)
	}
}

func removeAuthzMembership(ctx context.Context, change AuthzMembershipChange) (bool, error) {
	user, err := user_model.GetUserByID(ctx, change.UserID)
	if err != nil {
		return false, err
	}
	protected, err := wecom_model.IsActiveManagementAuthorityBoundUser(ctx, setting.EnterpriseWeCom.CorpID, setting.EnterpriseWeCom.AgentID, change.UserID)
	if err != nil || protected {
		return protected, err
	}
	switch change.TargetType {
	case wecom_model.AuthzTargetOrg:
		if hasTeamMembership, err := hasAnyTeamMembershipInOrg(ctx, change.OrgID, change.UserID); err != nil || hasTeamMembership {
			return false, err
		}
		org, err := organization.GetOrgByID(ctx, change.OrgID)
		if err != nil {
			return false, err
		}
		if err := org_service.RemoveOrgUser(ctx, org, user); err != nil {
			if organization.IsErrLastOrgOwner(err) {
				return true, nil
			}
			return false, err
		}
		return false, nil
	case wecom_model.AuthzTargetTeam:
		team, err := organization.GetTeamByID(ctx, change.TeamID)
		if err != nil {
			return false, err
		}
		if team.IsOwnerTeam() && team.NumMembers <= 1 {
			member, err := organization.IsTeamMember(ctx, team.OrgID, team.ID, user.ID)
			if err != nil || member {
				return member, err
			}
		}
		if err := org_service.RemoveTeamMember(ctx, team, user); err != nil {
			return false, err
		}
		return false, nil
	default:
		return false, fmt.Errorf("%w: unsupported target type", ErrInvalidAuthzMapping)
	}
}

func hasAnyTeamMembershipInOrg(ctx context.Context, orgID, userID int64) (bool, error) {
	return db.GetEngine(ctx).
		Where("org_id = ? AND uid = ?", orgID, userID).
		Table("team_user").
		Exist()
}

func upsertManagedMembership(ctx context.Context, change AuthzMembershipChange, applyID string) error {
	now := timeutil.TimeStampNow()
	existing := &wecom_model.ManagedMembership{}
	has, err := db.GetEngine(ctx).
		Where("mapping_id = ? AND user_id = ? AND target_type = ? AND org_id = ? AND team_id = ?", change.MappingID, change.UserID, change.TargetType, change.OrgID, change.TeamID).
		Get(existing)
	if err != nil {
		return err
	}
	if has {
		existing.LastApplyUnix = now
		existing.LastSeenApplyID = applyID
		_, err = db.GetEngine(ctx).ID(existing.ID).Cols("last_apply_unix", "last_seen_apply_id").Update(existing)
		return err
	}
	return db.Insert(ctx, &wecom_model.ManagedMembership{
		MappingID:       change.MappingID,
		UserID:          change.UserID,
		TargetType:      change.TargetType,
		OrgID:           change.OrgID,
		TeamID:          change.TeamID,
		LastApplyUnix:   now,
		LastSeenApplyID: applyID,
	})
}

func deleteManagedMembership(ctx context.Context, change AuthzMembershipChange) error {
	_, err := db.GetEngine(ctx).
		Where("mapping_id = ? AND user_id = ? AND target_type = ? AND org_id = ? AND team_id = ?", change.MappingID, change.UserID, change.TargetType, change.OrgID, change.TeamID).
		Delete(new(wecom_model.ManagedMembership))
	return err
}

func changeFromManagedMembership(managed *wecom_model.ManagedMembership) AuthzMembershipChange {
	return AuthzMembershipChange{
		MappingID:  managed.MappingID,
		UserID:     managed.UserID,
		TargetType: managed.TargetType,
		OrgID:      managed.OrgID,
		TeamID:     managed.TeamID,
	}
}

func makeManagedKey(change AuthzMembershipChange) authzManagedKey {
	return authzManagedKey{MappingID: change.MappingID, authzTargetUserKey: makeTargetUserKey(change)}
}

func makeTargetUserKey(change AuthzMembershipChange) authzTargetUserKey {
	return authzTargetUserKey{UserID: change.UserID, TargetType: change.TargetType, OrgID: change.OrgID, TeamID: change.TeamID}
}

func groupChangesByTargetUser(changes []AuthzMembershipChange) map[authzTargetUserKey][]AuthzMembershipChange {
	grouped := make(map[authzTargetUserKey][]AuthzMembershipChange)
	for _, change := range changes {
		grouped[makeTargetUserKey(change)] = append(grouped[makeTargetUserKey(change)], change)
	}
	return grouped
}

func recordMappingApplyAudit(ctx context.Context, actorID int64, result *AuthzReconcileResult, outcome, reason string) {
	metadata := []any{"outcome", outcome}
	if reason != "" {
		metadata = append(metadata, "reason", reason)
	}
	if result != nil {
		metadata = append(metadata,
			"additions", len(result.Additions),
			"removals", len(result.Removals),
			"protected_removals", len(result.ProtectedRemovals),
			"skipped", len(result.Skipped),
			"errors", len(result.Errors),
		)
	}
	audit.RecordAs(ctx, mappingAuditActor(ctx, actorID), audit_model.EnterpriseWeComMappingApply, nil, metadata...)
}
