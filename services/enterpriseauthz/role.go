// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/timeutil"
	"gitea.dev/modules/util"
	"gitea.dev/modules/web/middleware"
	"gitea.dev/services/audit"
	"gitea.dev/services/automergequeue"

	"xorm.io/builder"
)

var (
	ErrInvalidPolicy    = errors.New("invalid_policy")
	ErrRevisionConflict = errors.New("revision_conflict")
	ErrBuiltinImmutable = errors.New("builtin_role_immutable")
	ErrRoleNameConflict = errors.New("role_name_conflict")
	ErrRoleReferenced   = errors.New("role_referenced")
	ErrPolicyStorage    = errors.New("policy_storage_failed")
)

type PermissionInput struct {
	Action    authz.Action `json:"action"`
	Effect    string       `json:"effect"`
	Condition []byte       `json:"condition,omitempty"`
}

type CreateRoleInput struct {
	Name           string
	Description    string
	CopyFromRoleID int64
	Permissions    *[]PermissionInput
}

type UpdateRoleInput struct {
	ExpectedRevision int64
	Name             *string
	Description      *string
	Permissions      *[]PermissionInput
}

type Role struct {
	Definition  *authz_model.RoleDefinition
	Permissions []authz_model.RolePermission
}

type PolicyListOptions struct{ Page, Limit int }

func (o PolicyListOptions) pagination() (limit, offset int, err error) {
	if o.Page < 0 || o.Limit < 0 || o.Limit > 100 {
		return 0, 0, ErrInvalidPolicy
	}
	limit = o.Limit
	if limit == 0 {
		limit = 20
	}
	page := max(1, o.Page)
	if page-1 > int(^uint(0)>>1)/limit {
		return 0, 0, ErrInvalidPolicy
	}
	return limit, (page - 1) * limit, nil
}

func authorizePolicy(ctx context.Context, actor *user_model.User, scope authz_model.Scope) (*managementScope, error) {
	resolved, err := resolveManagementScope(ctx, actor, scope)
	if err != nil {
		return nil, err
	}
	if !setting.EnterpriseAuthz.Enabled {
		return nil, util.ErrNotExist
	}
	return resolved, nil
}

func withPolicyMutation(ctx context.Context, actor *user_model.User, scope authz_model.Scope, f func(context.Context, *managementScope) error) error {
	if _, err := authorizePolicy(ctx, actor, scope); err != nil {
		return err
	}
	if setting.Audit.RecordOutput != setting.AuditRecordOutputDatabase {
		return ErrPolicyStorage
	}
	return db.WithTx(ctx, func(tx context.Context) error {
		if setting.EnterpriseMergeGate.Enabled {
			if err := LockMergeGatePolicyScopes(tx, scope); err != nil {
				return ErrPolicyStorage
			}
		}
		if scope.Type == authz_model.ScopeSystem {
			if _, err := db.Exec(tx, "UPDATE `user` SET id=id WHERE id=?", actor.ID); err != nil {
				return ErrPolicyStorage
			}
		} else {
			if err := authz_model.LockScope(tx, scope); err != nil {
				return ErrPolicyStorage
			}
		}
		resolved, err := authorizePolicy(tx, actor, scope)
		if err != nil {
			return err
		}
		auditCtx, persisted := audit.WithRequiredPersistence(tx)
		if err := f(auditCtx, resolved); err != nil {
			return err
		}
		if persisted() != nil {
			return ErrPolicyStorage
		}
		return nil
	})
}

func roleVisibility(resolved *managementScope) builder.Cond {
	conditions := []builder.Cond{builder.Eq{"scope_type": authz_model.ScopeSystem, "scope_id": 0}}
	if resolved.scope.Type != authz_model.ScopeSystem {
		conditions = append(conditions, builder.Eq{"scope_type": resolved.scope.Type, "scope_id": resolved.scope.ID})
	}
	if resolved.repo != nil && resolved.repo.Owner.IsOrganization() {
		conditions = append(conditions, builder.Eq{"scope_type": authz_model.ScopeOrg, "scope_id": resolved.ownerID})
	}
	return builder.Or(conditions...)
}

func readRole(ctx context.Context, resolved *managementScope, id int64, lock bool) (*Role, error) {
	cond := builder.And(builder.Eq{"id": id}, roleVisibility(resolved))
	if lock {
		// 与绑定/删除共享行锁，避免引用在校验后失效。
		if _, err := db.GetEngine(ctx).Where(cond).Cols("revision").SetExpr("revision", "revision").NoAutoTime().Update(new(authz_model.RoleDefinition)); err != nil {
			return nil, ErrPolicyStorage
		}
	}
	definition, exists, err := db.Get[authz_model.RoleDefinition](ctx, cond)
	if err != nil {
		return nil, ErrPolicyStorage
	}
	if !exists {
		return nil, util.ErrNotExist
	}
	var permissions []authz_model.RolePermission
	if err := db.GetEngine(ctx).Where("role_id = ?", id).OrderBy("action, condition_hash").Find(&permissions); err != nil {
		return nil, ErrPolicyStorage
	}
	role := &Role{Definition: definition, Permissions: permissions}
	if err := validateStoredRole(role); err != nil {
		return nil, err
	}
	return role, nil
}

func validateStoredRole(role *Role) error {
	if role.Definition.Revision < 1 || !role.Definition.Scope().Valid() || len(role.Permissions) > authz.MaxRolePermissions {
		return ErrPolicyStorage
	}
	for _, permission := range role.Permissions {
		if authz.ValidatePermission(permission.Action, permission.Effect) != nil {
			return ErrPolicyStorage
		}
		_, _, hash, err := authz.ParseCondition([]byte(permission.ConditionJSON))
		if err != nil || hash != permission.ConditionHash {
			return ErrPolicyStorage
		}
	}
	return nil
}

func GetRole(ctx context.Context, actor *user_model.User, scope authz_model.Scope, id int64) (*Role, error) {
	if _, err := authorizePolicy(ctx, actor, scope); err != nil {
		return nil, err
	}
	var role *Role
	err := db.WithIndependentReadTx(ctx, func(tx context.Context) error {
		resolved, err := authorizePolicy(tx, actor, scope)
		if err != nil {
			return err
		}
		role, err = readRole(tx, resolved, id, false)
		return err
	})
	if err != nil {
		return nil, safePolicyError(err)
	}
	return role, nil
}

func ListRoles(ctx context.Context, actor *user_model.User, scope authz_model.Scope, options PolicyListOptions) ([]*Role, int64, error) {
	if _, err := authorizePolicy(ctx, actor, scope); err != nil {
		return nil, 0, err
	}
	limit, offset, err := options.pagination()
	if err != nil {
		return nil, 0, err
	}
	roles := make([]*Role, 0)
	var total int64
	err = db.WithIndependentReadTx(ctx, func(tx context.Context) error {
		resolved, err := authorizePolicy(tx, actor, scope)
		if err != nil {
			return err
		}
		var definitions []*authz_model.RoleDefinition
		total, err = db.GetEngine(tx).Where(roleVisibility(resolved)).OrderBy("id").Limit(limit, offset).FindAndCount(&definitions)
		if err != nil {
			return ErrPolicyStorage
		}
		ids := make([]int64, 0, len(definitions))
		for _, definition := range definitions {
			ids = append(ids, definition.ID)
		}
		var permissions []authz_model.RolePermission
		if len(ids) != 0 {
			if err := db.GetEngine(tx).In("role_id", ids).OrderBy("action, condition_hash").Find(&permissions); err != nil {
				return ErrPolicyStorage
			}
		}
		byRole := make(map[int64][]authz_model.RolePermission)
		for _, permission := range permissions {
			byRole[permission.RoleID] = append(byRole[permission.RoleID], permission)
		}
		for _, definition := range definitions {
			role := &Role{Definition: definition, Permissions: byRole[definition.ID]}
			if err := validateStoredRole(role); err != nil {
				return err
			}
			roles = append(roles, role)
		}
		return nil
	})
	if err != nil {
		return nil, 0, safePolicyError(err)
	}
	return roles, total, nil
}

func normalizedRoleName(name string) (string, string, error) {
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || utf8.RuneCountInString(name) == 0 || utf8.RuneCountInString(name) > 64 || strings.ContainsAny(name, "\x00\r\n") {
		return "", "", ErrInvalidPolicy
	}
	return name, strings.ToLower(name), nil
}

func normalizePermissions(inputs []PermissionInput) ([]authz_model.RolePermission, error) {
	if len(inputs) > authz.MaxRolePermissions {
		return nil, ErrInvalidPolicy
	}
	permissions := make([]authz_model.RolePermission, 0, len(inputs))
	seen := make(map[string]bool)
	for _, input := range inputs {
		if authz.ValidatePermission(input.Action, input.Effect) != nil {
			return nil, ErrInvalidPolicy
		}
		condition := input.Condition
		if len(condition) == 0 {
			condition = []byte(`{}`)
		}
		_, normalized, hash, err := authz.ParseCondition(condition)
		if err != nil {
			return nil, ErrInvalidPolicy
		}
		key := string(input.Action) + ":" + hash
		if seen[key] {
			continue
		}
		seen[key] = true
		permissions = append(permissions, authz_model.RolePermission{Action: input.Action, Effect: input.Effect, ConditionJSON: normalized, ConditionHash: hash})
	}
	slices.SortFunc(permissions, func(a, b authz_model.RolePermission) int {
		if order := strings.Compare(string(a.Action), string(b.Action)); order != 0 {
			return order
		}
		return strings.Compare(a.ConditionHash, b.ConditionHash)
	})
	return permissions, nil
}

func replaceRolePermissions(ctx context.Context, id int64, permissions []authz_model.RolePermission) error {
	if _, err := db.GetEngine(ctx).Where("role_id = ?", id).Delete(new(authz_model.RolePermission)); err != nil {
		return ErrPolicyStorage
	}
	for i := range permissions {
		permissions[i].ID, permissions[i].RoleID = 0, id
	}
	if len(permissions) != 0 {
		if err := db.Insert(ctx, permissions); err != nil {
			return ErrPolicyStorage
		}
	}
	return nil
}

func CreateRole(ctx context.Context, actor *user_model.User, scope authz_model.Scope, input CreateRoleInput) (*Role, error) {
	var created *Role
	err := withPolicyMutation(ctx, actor, scope, func(tx context.Context, resolved *managementScope) error {
		name, lower, err := normalizedRoleName(input.Name)
		if err != nil || !utf8.ValidString(input.Description) || strings.ContainsRune(input.Description, 0) || input.CopyFromRoleID < 0 {
			return ErrInvalidPolicy
		}
		var permissions []authz_model.RolePermission
		if input.CopyFromRoleID != 0 {
			source, err := readRole(tx, resolved, input.CopyFromRoleID, true)
			if err != nil {
				return err
			}
			inputs := make([]PermissionInput, 0, len(source.Permissions))
			for _, permission := range source.Permissions {
				inputs = append(inputs, PermissionInput{Action: permission.Action, Effect: permission.Effect, Condition: []byte(permission.ConditionJSON)})
			}
			permissions, err = normalizePermissions(inputs)
			if err != nil {
				return ErrPolicyStorage
			}
		}
		if input.Permissions != nil {
			permissions, err = normalizePermissions(*input.Permissions)
			if err != nil {
				return err
			}
		}
		definition := &authz_model.RoleDefinition{ScopeType: scope.Type, ScopeID: scope.ID, Name: name, LowerName: lower, Description: input.Description, Revision: 1, CreatedBy: resolved.actor.ID}
		inserted, err := authz_model.InsertRoleIfAbsent(tx, definition)
		if err != nil {
			return ErrPolicyStorage
		}
		if !inserted {
			return ErrRoleNameConflict
		}
		if err := replaceRolePermissions(tx, definition.ID, permissions); err != nil {
			return err
		}
		created = &Role{Definition: definition, Permissions: permissions}
		return recordRoleMutation(tx, resolved, audit_model.EnterpriseAuthzRoleCreate, nil, created)
	})
	if err != nil {
		return nil, safePolicyError(err)
	}
	return created, nil
}

func mutableRole(ctx context.Context, resolved *managementScope, id, expectedRevision int64) (*Role, error) {
	role, err := readRole(ctx, resolved, id, true)
	if err != nil {
		return nil, err
	}
	if role.Definition.BuiltinKey != nil {
		return nil, ErrBuiltinImmutable
	}
	if role.Definition.Scope() != resolved.scope {
		return nil, util.ErrNotExist
	}
	if expectedRevision <= 0 || role.Definition.Revision != expectedRevision {
		return nil, ErrRevisionConflict
	}
	return role, nil
}

func UpdateRole(ctx context.Context, actor *user_model.User, scope authz_model.Scope, id int64, input UpdateRoleInput) (*Role, error) {
	var updated *Role
	err := withPolicyMutation(ctx, actor, scope, func(tx context.Context, resolved *managementScope) error {
		before, err := mutableRole(tx, resolved, id, input.ExpectedRevision)
		if err != nil {
			return err
		}
		definition := *before.Definition
		permissions := slices.Clone(before.Permissions)
		if input.Name != nil {
			definition.Name, definition.LowerName, err = normalizedRoleName(*input.Name)
			if err != nil {
				return err
			}
			duplicate, err := db.GetEngine(tx).Where("scope_type = ? AND scope_id = ? AND lower_name = ? AND id <> ?", scope.Type, scope.ID, definition.LowerName, id).Exist(new(authz_model.RoleDefinition))
			if err != nil {
				return ErrPolicyStorage
			}
			if duplicate {
				return ErrRoleNameConflict
			}
		}
		if input.Description != nil {
			if !utf8.ValidString(*input.Description) || strings.ContainsRune(*input.Description, 0) {
				return ErrInvalidPolicy
			}
			definition.Description = *input.Description
		}
		if input.Permissions != nil {
			permissions, err = normalizePermissions(*input.Permissions)
			if err != nil {
				return err
			}
		}
		definition.Revision++
		definition.UpdatedUnix = timeutil.TimeStampNow()
		n, err := db.GetEngine(tx).Where("id = ? AND revision = ?", id, input.ExpectedRevision).Cols("name", "lower_name", "description", "revision", "updated_unix").Update(&definition)
		if err != nil {
			var state interface{ SQLState() string }
			if errors.As(err, &state) && state.SQLState() == "23505" {
				return ErrRoleNameConflict
			}
			return ErrPolicyStorage
		}
		if n != 1 {
			return ErrRevisionConflict
		}
		if input.Permissions != nil {
			if err := replaceRolePermissions(tx, id, permissions); err != nil {
				return err
			}
		}
		updated = &Role{Definition: &definition, Permissions: permissions}
		return recordRoleMutation(tx, resolved, audit_model.EnterpriseAuthzRoleUpdate, before, updated)
	})
	if err != nil {
		return nil, safePolicyError(err)
	}
	return updated, nil
}

func DeleteRole(ctx context.Context, actor *user_model.User, scope authz_model.Scope, id, expectedRevision int64) error {
	err := withPolicyMutation(ctx, actor, scope, func(tx context.Context, resolved *managementScope) error {
		before, err := mutableRole(tx, resolved, id, expectedRevision)
		if err != nil {
			return err
		}
		referenced, err := db.GetEngine(tx).Where("role_id = ?", id).Exist(new(authz_model.SubjectRoleBinding))
		if err != nil {
			return ErrPolicyStorage
		}
		if referenced {
			return ErrRoleReferenced
		}
		referenced, err = db.GetEngine(tx).Where("required_role_id=? AND enabled=? AND deleted=?", id, true, false).Exist(new(authz_model.ProtectedPathRule))
		if err != nil {
			return ErrPolicyStorage
		}
		if referenced {
			return ErrRoleReferenced
		}
		if err := replaceRolePermissions(tx, id, nil); err != nil {
			return err
		}
		if _, err := db.GetEngine(tx).ID(id).Delete(new(authz_model.RoleDefinition)); err != nil {
			return ErrPolicyStorage
		}
		return recordRoleMutation(tx, resolved, audit_model.EnterpriseAuthzRoleDelete, before, nil)
	})
	return safePolicyError(err)
}

type (
	permissionAudit struct {
		Action        authz.Action `json:"action"`
		Effect        string       `json:"effect"`
		ConditionHash string       `json:"condition_hash"`
	}
	roleAudit struct {
		ID          int64             `json:"id"`
		Revision    int64             `json:"revision"`
		Scope       authz_model.Scope `json:"scope"`
		Permissions []permissionAudit `json:"permissions"`
	}
)

func summarizeRole(role *Role) *roleAudit {
	if role == nil {
		return nil
	}
	summary := &roleAudit{ID: role.Definition.ID, Revision: role.Definition.Revision, Scope: role.Definition.Scope(), Permissions: make([]permissionAudit, 0, len(role.Permissions))}
	for _, permission := range role.Permissions {
		summary.Permissions = append(summary.Permissions, permissionAudit{permission.Action, permission.Effect, permission.ConditionHash})
	}
	return summary
}

func managementAuditScope(resolved *managementScope) audit_model.EntityRef {
	typ := audit_model.ScopeSystem
	if resolved.scope.Type == authz_model.ScopeRepo {
		typ = audit_model.ScopeRepository
	}
	if resolved.scope.Type == authz_model.ScopeOrg {
		typ = audit_model.ScopeOrganization
	}
	return audit_model.EntityRef{Type: typ, ID: resolved.scope.ID}
}

func recordRoleMutation(ctx context.Context, resolved *managementScope, action audit_model.Action, before, after *Role) error {
	role := after
	if role == nil {
		role = before
	}
	return recordPolicyEvent(ctx, resolved, action, map[string]any{"role_id": role.Definition.ID, "before": summarizeRole(before), "after": summarizeRole(after)})
}

func safeAuditImpersonator(ctx context.Context, actorID int64) *audit_model.EntityRef {
	if actor := audit.ImpersonatorFromContext(ctx); actor != nil && actor.ID > 0 && actor.ID != actorID {
		return &audit_model.EntityRef{Type: audit_model.ScopeUser, ID: actor.ID}
	}
	return nil
}

func recordPolicyEvent(ctx context.Context, resolved *managementScope, action audit_model.Action, metadata map[string]any) error {
	var credential string
	if data := middleware.GetContextData(ctx); data != nil {
		actor, _ := data[middleware.ContextDataKeySignedUser].(*user_model.User)
		if actor != nil && actor.ID == resolved.actor.ID {
			value, _ := data[middleware.ContextDataKeyAuthCredential].(string)
			credential = safeCredentialReference(value)
		}
	}
	if err := audit.RecordEvent(ctx, audit.RecordParams{Action: action, Actor: audit_model.EntityRef{Type: audit_model.ScopeUser, ID: resolved.actor.ID}, ActorCredential: credential, Impersonator: safeAuditImpersonator(ctx, resolved.actor.ID), Scope: managementAuditScope(resolved), Metadata: metadata}); err != nil {
		return ErrPolicyStorage
	}
	if setting.EnterpriseMergeGate.Enabled && setting.EnterpriseMergeGate.Enforce {
		item := automergequeue.AutoMergeItem(fmt.Sprintf("gate-scope:%s:%d:%s", resolved.scope.Type, resolved.scope.ID, rand.Text()))
		db.AfterCommit(ctx, func() { automergequeue.AddToQueue(item) })
	}
	return nil
}

func safePolicyError(err error) error {
	if err == nil {
		return nil
	}
	for _, known := range []error{util.ErrPermissionDenied, util.ErrNotExist, ErrInvalidPolicy, ErrRevisionConflict, ErrBuiltinImmutable, ErrRoleNameConflict, ErrRoleReferenced, ErrPolicyStorage} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrPolicyStorage
}
