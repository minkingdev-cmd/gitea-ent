// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/organization"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/util"

	"xorm.io/builder"
)

type BindingInput struct {
	SubjectType authz_model.SubjectType
	SubjectID   int64
	RoleID      int64
}

func bindingScope(resolved *managementScope) builder.Cond {
	return builder.Eq{"scope_type": resolved.scope.Type, "scope_id": resolved.scope.ID}
}

func validateBindingSubject(ctx context.Context, resolved *managementScope, input BindingInput) error {
	if input.SubjectID <= 0 {
		return ErrInvalidPolicy
	}
	if input.SubjectType != authz_model.SubjectUser && input.SubjectType != authz_model.SubjectOrg && input.SubjectType != authz_model.SubjectTeam {
		return ErrInvalidPolicy
	}
	if err := authz_model.LockSubject(ctx, input.SubjectType, input.SubjectID); err != nil {
		return ErrPolicyStorage
	}
	if input.SubjectType == authz_model.SubjectUser {
		subject, exists, err := db.GetByID[user_model.User](ctx, input.SubjectID)
		if err != nil {
			return ErrPolicyStorage
		}
		if !exists || !subject.IsIndividual() {
			return ErrInvalidPolicy
		}
		return nil
	}
	var orgID int64
	if input.SubjectType == authz_model.SubjectOrg {
		org, exists, err := db.GetByID[user_model.User](ctx, input.SubjectID)
		if err != nil {
			return ErrPolicyStorage
		}
		if !exists || !org.IsOrganization() {
			return ErrInvalidPolicy
		}
		orgID = org.ID
	} else {
		team, exists, err := db.GetByID[organization.Team](ctx, input.SubjectID)
		if err != nil {
			return ErrPolicyStorage
		}
		if !exists {
			return ErrInvalidPolicy
		}
		orgID = team.OrgID
		org, exists, err := db.GetByID[user_model.User](ctx, orgID)
		if err != nil {
			return ErrPolicyStorage
		}
		if !exists || !org.IsOrganization() {
			return ErrInvalidPolicy
		}
		if resolved.repo != nil && !team.IncludesAllRepositories {
			exists, err := db.GetEngine(ctx).Where("org_id = ? AND team_id = ? AND repo_id = ?", orgID, team.ID, resolved.repo.ID).Exist(new(organization.TeamRepo))
			if err != nil {
				return ErrPolicyStorage
			}
			if !exists {
				return ErrInvalidPolicy
			}
		}
	}
	if resolved.scope.Type != authz_model.ScopeSystem && orgID != resolved.ownerID {
		return ErrInvalidPolicy
	}
	return nil
}

func PutBinding(ctx context.Context, actor *user_model.User, scope authz_model.Scope, input BindingInput) (*authz_model.SubjectRoleBinding, bool, error) {
	var binding *authz_model.SubjectRoleBinding
	var created bool
	err := withPolicyMutation(ctx, actor, scope, func(tx context.Context, resolved *managementScope) error {
		role, err := readRole(tx, resolved, input.RoleID, false)
		if err != nil {
			return err
		}
		if role.Definition.BuiltinKey != nil && *role.Definition.BuiltinKey == "platform-admin" && scope.Type != authz_model.ScopeSystem {
			return util.ErrPermissionDenied
		}
		if err := validateBindingSubject(tx, resolved, input); err != nil {
			return err
		}
		if _, err := readRole(tx, resolved, input.RoleID, true); err != nil {
			return err
		}
		binding = &authz_model.SubjectRoleBinding{SubjectType: input.SubjectType, SubjectID: input.SubjectID, ScopeType: scope.Type, ScopeID: scope.ID, ScopeOwnerID: resolved.ownerID, RoleID: input.RoleID, CreatedBy: resolved.actor.ID}
		created, err = authz_model.InsertBindingIfAbsent(tx, binding)
		if err != nil {
			return ErrPolicyStorage
		}
		if !created {
			return nil
		}
		return recordBindingMutation(tx, resolved, audit_model.EnterpriseAuthzBindingAdd, binding)
	})
	if err != nil {
		return nil, false, safePolicyError(err)
	}
	return binding, created, nil
}

func ListBindings(ctx context.Context, actor *user_model.User, scope authz_model.Scope, options PolicyListOptions) ([]authz_model.SubjectRoleBinding, int64, error) {
	resolved, err := authorizePolicy(ctx, actor, scope)
	if err != nil {
		return nil, 0, err
	}
	limit, offset, err := options.pagination()
	if err != nil {
		return nil, 0, err
	}
	bindings := make([]authz_model.SubjectRoleBinding, 0)
	total, err := db.GetEngine(ctx).Where(bindingScope(resolved)).OrderBy("id").Limit(limit, offset).FindAndCount(&bindings)
	if err != nil {
		return nil, 0, ErrPolicyStorage
	}
	return bindings, total, nil
}

func DeleteBinding(ctx context.Context, actor *user_model.User, scope authz_model.Scope, id int64) error {
	err := withPolicyMutation(ctx, actor, scope, func(tx context.Context, resolved *managementScope) error {
		cond := builder.And(builder.Eq{"id": id}, bindingScope(resolved))
		binding, exists, err := db.Get[authz_model.SubjectRoleBinding](tx, cond)
		if err != nil {
			return ErrPolicyStorage
		}
		if !exists {
			return util.ErrNotExist
		}
		// 旧角色对新 owner 不可见时仍可解绑，与角色删除共享锁。
		if _, err := db.GetEngine(tx).ID(binding.RoleID).Cols("revision").SetExpr("revision", "revision").NoAutoTime().Update(new(authz_model.RoleDefinition)); err != nil {
			return ErrPolicyStorage
		}
		n, err := db.GetEngine(tx).Where(cond).Delete(new(authz_model.SubjectRoleBinding))
		if err != nil {
			return ErrPolicyStorage
		}
		if n == 0 {
			return util.ErrNotExist
		}
		return recordBindingMutation(tx, resolved, audit_model.EnterpriseAuthzBindingRemove, binding)
	})
	return safePolicyError(err)
}

func recordBindingMutation(ctx context.Context, resolved *managementScope, action audit_model.Action, binding *authz_model.SubjectRoleBinding) error {
	metadata := map[string]any{"binding_id": binding.ID, "role_id": binding.RoleID, "subject_type": binding.SubjectType, "subject_id": binding.SubjectID, "scope_type": binding.ScopeType, "scope_id": binding.ScopeID, "owner_id": binding.ScopeOwnerID}
	summary := map[string]any{"id": binding.ID, "role_id": binding.RoleID, "subject_type": binding.SubjectType, "subject_id": binding.SubjectID, "scope_type": binding.ScopeType, "scope_id": binding.ScopeID, "owner_id": binding.ScopeOwnerID}
	metadata["before"], metadata["after"] = nil, summary
	if action == audit_model.EnterpriseAuthzBindingRemove {
		metadata["before"], metadata["after"] = summary, nil
	}
	return recordPolicyEvent(ctx, resolved, action, metadata)
}
