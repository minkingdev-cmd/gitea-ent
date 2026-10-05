// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"
	"slices"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/organization"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"

	"xorm.io/builder"
)

type EvaluateInput struct {
	Actor             *user_model.User
	Repo              *repo_model.Repository
	Permission        *access_model.Permission
	Credential        CredentialCeiling
	Action            authz.Action
	TargetOwnerID     int64
	observationTarget string
	ConditionContext  authz.ConditionContext
}

type Decision struct {
	CandidateDecision     string         `json:"candidate_decision"`
	Reason                string         `json:"reason"`
	Action                authz.Action   `json:"action"`
	NativeActions         []authz.Action `json:"native_actions"`
	RoleActions           []authz.Action `json:"role_actions"`
	MatchedRoleIDs        []int64        `json:"matched_role_ids"`
	MatchedBindingIDs     []int64        `json:"matched_binding_ids"`
	MissingActions        []authz.Action `json:"missing_actions"`
	CandidateOnly         bool           `json:"candidate_only"`
	SafetyGuardsEvaluated bool           `json:"safety_guards_evaluated"`
	Snapshot              string         `json:"snapshot"`
	ownerID               int64
}

type roleSnapshot struct {
	Features       []api.EnterpriseFeatureSnapshot `json:"features,omitempty"`
	CatalogVersion int                             `json:"catalog_version"`
	ActorID        int64                           `json:"actor_id"`
	RepoID         int64                           `json:"repo_id"`
	OwnerID        int64                           `json:"owner_id"`
	TargetOwnerID  int64                           `json:"target_owner_id,omitzero"`
	IntentHash     string                          `json:"intent_hash,omitempty"`
	Archived       bool                            `json:"archived"`
	NativeMode     int                             `json:"native_mode"`
	UnitModes      []unitSnapshot                  `json:"unit_modes"`
	Credential     CredentialCeiling               `json:"credential"`
	RoleEligible   bool                            `json:"role_eligible"`
	BranchKnown    bool                            `json:"branch_known"`
	PathsComplete  bool                            `json:"paths_complete"`
	PathCount      int                             `json:"path_count"`
	NativeActions  []authz.Action                  `json:"native_actions"`
	Definitions    []definitionSnapshot            `json:"definitions"`
	Bindings       []bindingSnapshot               `json:"bindings"`
	Roles          []roleResult                    `json:"roles"`
}

type unitSnapshot struct {
	Key  string `json:"key"`
	Mode int    `json:"mode"`
}

type definitionSnapshot struct {
	ID       int64             `json:"id"`
	Revision int64             `json:"revision"`
	Scope    authz_model.Scope `json:"scope"`
}

type bindingSnapshot struct {
	ID          int64                   `json:"id"`
	SubjectType authz_model.SubjectType `json:"subject_type"`
	SubjectID   int64                   `json:"subject_id"`
	Scope       authz_model.Scope       `json:"scope"`
	OwnerID     int64                   `json:"owner_id"`
}

type roleResult struct {
	RoleID          int64  `json:"role_id"`
	BindingID       int64  `json:"binding_id"`
	Revision        int64  `json:"revision"`
	Action          string `json:"action"`
	Effect          string `json:"effect"`
	ConditionHash   string `json:"condition_hash"`
	Result          string `json:"result"`
	RequestedAction bool   `json:"requested_action"`
}

func baseSnapshot(input EvaluateInput, native []authz.Action) roleSnapshot {
	snapshot := roleSnapshot{
		CatalogVersion: authz.CatalogVersion, NativeActions: native, TargetOwnerID: max(0, input.TargetOwnerID),
		Credential: input.Credential, RoleEligible: roleEligible(input.Actor) && !input.Credential.NativeOnly,
		BranchKnown:   input.ConditionContext.BranchKnown,
		PathsComplete: input.ConditionContext.PathsComplete && len(input.ConditionContext.Paths) <= authz.MaxContextPaths,
		PathCount:     len(input.ConditionContext.Paths), UnitModes: nil,
	}
	snapshot.Credential.Reference = safeCredentialReference(input.Credential.Reference)
	if input.Actor != nil {
		snapshot.ActorID = input.Actor.ID
	}
	if input.Repo != nil {
		snapshot.RepoID, snapshot.OwnerID = input.Repo.ID, input.Repo.OwnerID
		snapshot.Archived = input.Repo.IsArchived
	}
	if input.Permission != nil {
		snapshot.NativeMode = int(input.Permission.AccessMode)
		for _, typ := range unit.AllRepoUnitTypes {
			snapshot.UnitModes = append(snapshot.UnitModes, unitSnapshot{Key: unit.Units[typ].NameKey, Mode: int(input.Permission.UnitAccessMode(typ))})
		}
	}
	return snapshot
}

func Evaluate(ctx context.Context, input EvaluateInput) (Decision, error) {
	return evaluate(ctx, input, false)
}

func evaluate(ctx context.Context, input EvaluateInput, inSnapshot bool) (Decision, error) {
	decision := Decision{
		CandidateDecision: "error", Reason: "invalid_evaluation_context", Action: input.Action,
		CandidateOnly: true, SafetyGuardsEvaluated: false,
	}
	if !setting.EnterpriseAuthz.Enabled {
		decision.Reason = "authz_disabled"
		return decision, errors.New("authz_disabled")
	}
	if _, ok := authz.LookupAction(input.Action); !ok {
		decision.Reason = "unknown_action"
		return decision, errors.New("unknown_action")
	}
	if input.Repo == nil || input.Repo.ID <= 0 || input.Permission == nil || !authz.ValidSource(input.ConditionContext.Source) {
		return decision, errors.New(decision.Reason)
	}
	decision.ownerID = input.Repo.OwnerID
	if input.Credential.organizationID > 0 && input.Repo.OwnerID != input.Credential.organizationID || !input.Credential.Read || !input.Permission.HasAnyUnitAccessOrPublicAccess() {
		decision.CandidateDecision, decision.Reason = "deny", "native_visibility_denied"
		decision.MissingActions = []authz.Action{input.Action}
		return decision, nil
	}

	var policyErr error
	var native []authz.Action
	read := func(snapshotCtx context.Context) (readErr error) {
		defer func() {
			key := featureForAction(input.Action)
			if readErr != nil || decision.Snapshot == "" || key == "" {
				return
			}
			policy, err := featurePolicy(snapshotCtx, key, authz_model.Scope{Type: authz_model.ScopeRepo, ID: input.Repo.ID})
			if err != nil {
				policyErr = errors.New("policy_read_failed")
				readErr = policyErr
				return
			}
			var snapshot roleSnapshot
			if json.Unmarshal([]byte(decision.Snapshot), &snapshot) != nil {
				policyErr = errors.New("policy_read_failed")
				readErr = policyErr
				return
			}
			snapshot.Features = []api.EnterpriseFeatureSnapshot{featureSnapshot(policy)}
			data, err := json.Marshal(snapshot)
			if err != nil || len(data) > authz.MaxSnapshotBytes {
				policyErr = errors.New("snapshot_limit_exceeded")
				readErr = policyErr
				return
			}
			decision.Snapshot = string(data)
		}()

		currentRepo, exists, err := db.GetByID[repo_model.Repository](snapshotCtx, input.Repo.ID)
		if err != nil || !exists {
			policyErr = errors.New("policy_read_failed")
			return policyErr
		}
		input.Repo = currentRepo
		decision.ownerID = currentRepo.OwnerID
		if input.Actor != nil && input.Actor.ID > 0 {
			currentActor, exists, err := db.GetByID[user_model.User](snapshotCtx, input.Actor.ID)
			if err != nil {
				policyErr = errors.New("policy_read_failed")
				return policyErr
			}
			if !exists {
				currentActor = &user_model.User{ID: input.Actor.ID}
			}
			currentActor.ExtDoerData = input.Actor.ExtDoerData
			if inSnapshot {
				currentActor.IsAdmin = input.Actor.IsAdmin
			}
			input.Actor = currentActor
		}
		if input.Actor != nil && (!input.Actor.IsActive || input.Actor.ProhibitLogin) {
			decision.CandidateDecision, decision.Reason = "deny", "actor_inactive"
			decision.MissingActions = []authz.Action{input.Action}
			data, _ := json.Marshal(baseSnapshot(input, nil))
			decision.Snapshot = string(data)
			return nil
		}
		if !visibleAction(input.Action, input.Permission, input.Credential, input.Repo.IsArchived) {
			decision.CandidateDecision, decision.Reason = "deny", "native_visibility_denied"
			decision.MissingActions = []authz.Action{input.Action}
			data, _ := json.Marshal(baseSnapshot(input, nil))
			decision.Snapshot = string(data)
			return nil
		}
		native = NativeActions(input.Repo, input.Permission, input.Credential)
		decision.NativeActions = native
		if input.Credential.NativeOnly || !roleEligible(input.Actor) {
			if slices.Contains(native, input.Action) {
				decision.CandidateDecision, decision.Reason = "allow", "native_action"
			} else {
				decision.CandidateDecision, decision.Reason = "deny", "missing_action"
				decision.MissingActions = []authz.Action{input.Action}
			}
			data, _ := json.Marshal(baseSnapshot(input, native))
			decision.Snapshot = string(data)
			return nil
		}
		bindings, roles, err := resolveRoles(snapshotCtx, input.Actor, input.Repo)
		if err != nil {
			policyErr = errors.New("policy_read_failed")
			return policyErr
		}
		roleIDs := make([]int64, 0, len(roles))
		for id := range roles {
			roleIDs = append(roleIDs, id)
		}
		slices.Sort(roleIDs)
		var permissions []authz_model.RolePermission
		if len(roleIDs) != 0 {
			if err := db.GetEngine(snapshotCtx).In("role_id", roleIDs).OrderBy("role_id, action, condition_hash").Find(&permissions); err != nil {
				policyErr = errors.New("policy_read_failed")
				return policyErr
			}
		}
		snapshot := baseSnapshot(input, native)
		for _, id := range roleIDs {
			role := roles[id]
			if role.Revision < 1 {
				policyErr = errors.New("policy_read_failed")
				return policyErr
			}
			snapshot.Definitions = append(snapshot.Definitions, definitionSnapshot{ID: id, Revision: role.Revision, Scope: role.Scope()})
			for _, binding := range bindings[id] {
				snapshot.Bindings = append(snapshot.Bindings, bindingSnapshot{ID: binding.ID, SubjectType: binding.SubjectType, SubjectID: binding.SubjectID, Scope: authz_model.Scope{Type: binding.ScopeType, ID: binding.ScopeID}, OwnerID: binding.ScopeOwnerID})
			}
		}
		var evaluation []roleResult
		counts := make(map[int64]int)
		roleAction := false
		unresolved, notMatched := false, false
		for _, permission := range permissions {
			counts[permission.RoleID]++
			if counts[permission.RoleID] > authz.MaxRolePermissions || ctx.Err() != nil {
				policyErr = errors.New("policy_read_failed")
				return policyErr
			}
			if err := authz.ValidatePermission(permission.Action, permission.Effect); err != nil {
				policyErr = errors.New("policy_read_failed")
				return policyErr
			}
			condition, _, hash, err := authz.ParseCondition([]byte(permission.ConditionJSON))
			if err != nil || hash != permission.ConditionHash || permission.Effect != "allow" {
				policyErr = errors.New("policy_read_failed")
				return policyErr
			}
			result := condition.Match(input.ConditionContext)
			resultName := string(result)
			for _, binding := range bindings[permission.RoleID] {
				evaluation = append(evaluation, roleResult{RoleID: permission.RoleID, BindingID: binding.ID, Revision: roles[permission.RoleID].Revision, Action: string(permission.Action), Effect: permission.Effect, ConditionHash: permission.ConditionHash, Result: resultName, RequestedAction: permission.Action == input.Action})
			}
			if result == authz.Matched && visibleAction(permission.Action, input.Permission, input.Credential, input.Repo.IsArchived) {
				decision.RoleActions = append(decision.RoleActions, permission.Action)
			}
			if permission.Action != input.Action {
				continue
			}
			switch result {
			case authz.Matched:
				roleAction = true
			case authz.Unresolved:
				unresolved = true
			case authz.NotMatched:
				notMatched = true
			}
		}
		slices.Sort(decision.RoleActions)
		decision.RoleActions = slices.Compact(decision.RoleActions)
		for _, entry := range evaluation {
			if entry.Action == string(input.Action) && entry.Result == string(authz.Matched) {
				decision.MatchedRoleIDs = append(decision.MatchedRoleIDs, entry.RoleID)
				decision.MatchedBindingIDs = append(decision.MatchedBindingIDs, entry.BindingID)
			}
		}
		slices.Sort(decision.MatchedRoleIDs)
		decision.MatchedRoleIDs = slices.Compact(decision.MatchedRoleIDs)
		slices.Sort(decision.MatchedBindingIDs)
		decision.MatchedBindingIDs = slices.Compact(decision.MatchedBindingIDs)
		snapshot.Roles = evaluation
		data, err := json.Marshal(snapshot)
		if err != nil || len(data) > authz.MaxSnapshotBytes {
			policyErr = errors.New("snapshot_limit_exceeded")
			return policyErr
		}
		decision.Snapshot = string(data)
		switch {
		case slices.Contains(native, input.Action):
			decision.CandidateDecision, decision.Reason = "allow", "native_action"
		case roleAction:
			decision.CandidateDecision, decision.Reason = "allow", "role_action"
		case unresolved:
			decision.CandidateDecision, decision.Reason = "deny", "condition_unresolved"
			decision.MissingActions = []authz.Action{input.Action}
		case notMatched:
			decision.CandidateDecision, decision.Reason = "deny", "condition_not_matched"
			decision.MissingActions = []authz.Action{input.Action}
		default:
			decision.CandidateDecision, decision.Reason = "deny", "missing_action"
			decision.MissingActions = []authz.Action{input.Action}
		}
		return nil
	}
	var err error
	if inSnapshot {
		err = read(ctx)
	} else {
		err = db.WithIndependentReadTx(ctx, read)
	}
	if err != nil {
		if policyErr != nil {
			decision.Reason = policyErr.Error()
		} else {
			decision.Reason = "policy_read_failed"
		}
		decision.CandidateDecision = "error"
		decision.RoleActions, decision.MatchedRoleIDs, decision.MatchedBindingIDs = nil, nil, nil
		data, _ := json.Marshal(baseSnapshot(input, native))
		decision.Snapshot = string(data)
		return decision, errors.New(decision.Reason)
	}
	return decision, nil
}

func resolveRoles(ctx context.Context, actor *user_model.User, repo *repo_model.Repository) (map[int64][]authz_model.SubjectRoleBinding, map[int64]authz_model.RoleDefinition, error) {
	owner, err := user_model.GetUserByID(ctx, repo.OwnerID)
	if err != nil {
		return nil, nil, err
	}
	orgIDs := make([]int64, 0)
	teamIDs := make([]int64, 0)
	if owner.IsOrganization() {
		var memberships []organization.OrgUser
		if err := db.GetEngine(ctx).Where("uid = ? AND org_id = ?", actor.ID, owner.ID).Find(&memberships); err != nil {
			return nil, nil, err
		}
		for _, membership := range memberships {
			orgIDs = append(orgIDs, membership.OrgID)
		}
		teams, err := organization.GetUserRepoTeams(ctx, owner.ID, actor.ID, repo.ID)
		if err != nil {
			return nil, nil, err
		}
		for _, team := range teams {
			teamIDs = append(teamIDs, team.ID)
		}
	}
	subjectConditions := []builder.Cond{builder.Eq{"subject_type": authz_model.SubjectUser, "subject_id": actor.ID}}
	if len(orgIDs) != 0 {
		subjectConditions = append(subjectConditions, builder.And(builder.Eq{"subject_type": authz_model.SubjectOrg}, builder.In("subject_id", orgIDs)))
	}
	if len(teamIDs) != 0 {
		subjectConditions = append(subjectConditions, builder.And(builder.Eq{"subject_type": authz_model.SubjectTeam}, builder.In("subject_id", teamIDs)))
	}
	scopeConditions := []builder.Cond{builder.Eq{"scope_type": authz_model.ScopeSystem, "scope_id": 0}}
	if owner.IsOrganization() {
		scopeConditions = append(scopeConditions, builder.Eq{"scope_type": authz_model.ScopeOrg, "scope_id": owner.ID})
	}
	scopeConditions = append(scopeConditions, builder.Eq{"scope_type": authz_model.ScopeRepo, "scope_id": repo.ID, "scope_owner_id": repo.OwnerID})
	var bindings []authz_model.SubjectRoleBinding
	cond := builder.And(builder.Or(subjectConditions...), builder.Or(scopeConditions...))
	if err := db.GetEngine(ctx).Where(cond).OrderBy("id").Find(&bindings); err != nil {
		return nil, nil, err
	}
	roleIDs := make([]int64, 0, len(bindings))
	for _, binding := range bindings {
		roleIDs = append(roleIDs, binding.RoleID)
	}
	slices.Sort(roleIDs)
	roleIDs = slices.Compact(roleIDs)
	roles := make(map[int64]authz_model.RoleDefinition, len(roleIDs))
	if len(roleIDs) != 0 {
		var found []authz_model.RoleDefinition
		if err := db.GetEngine(ctx).In("id", roleIDs).Find(&found); err != nil {
			return nil, nil, err
		}
		if len(found) != len(roleIDs) {
			return nil, nil, errors.New("policy_read_failed")
		}
		for _, role := range found {
			if role.ScopeType == authz_model.ScopeSystem || owner.IsOrganization() && role.ScopeType == authz_model.ScopeOrg && role.ScopeID == owner.ID || role.ScopeType == authz_model.ScopeRepo && role.ScopeID == repo.ID {
				roles[role.ID] = role
			}
		}
	}
	matched := make(map[int64][]authz_model.SubjectRoleBinding, len(roles))
	for _, binding := range bindings {
		if role, ok := roles[binding.RoleID]; ok && bindingCompatible(role, binding, repo, owner.IsOrganization()) {
			matched[binding.RoleID] = append(matched[binding.RoleID], binding)
		}
	}
	for id := range roles {
		if len(matched[id]) == 0 {
			delete(roles, id)
		}
	}
	return matched, roles, nil
}

func bindingCompatible(role authz_model.RoleDefinition, binding authz_model.SubjectRoleBinding, repo *repo_model.Repository, orgOwner bool) bool {
	if !role.Scope().Valid() {
		return false
	}
	if role.BuiltinKey != nil && *role.BuiltinKey == "platform-admin" && binding.ScopeType != authz_model.ScopeSystem {
		return false
	}
	switch role.ScopeType {
	case authz_model.ScopeSystem:
		return true
	case authz_model.ScopeOrg:
		return orgOwner && role.ScopeID == repo.OwnerID && (binding.ScopeType == authz_model.ScopeOrg && binding.ScopeID == role.ScopeID || binding.ScopeType == authz_model.ScopeRepo && binding.ScopeID == repo.ID)
	case authz_model.ScopeRepo:
		return binding.ScopeType == authz_model.ScopeRepo && binding.ScopeID == role.ScopeID
	}
	return false
}
