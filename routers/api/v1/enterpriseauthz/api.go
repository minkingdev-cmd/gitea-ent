// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"bytes"
	"encoding/json" //nolint:depguard // 保留条件原文并拒绝重复/未知字段，避免解码后丢失校验信息。
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"unicode/utf8"

	authz_model "gitea.dev/models/enterpriseauthz"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/log"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/timeutil"
	"gitea.dev/modules/util"
	"gitea.dev/routers/common"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
)

const scopeDataKey = "EnterpriseAuthzScope"

func AssignScope(typ authz_model.ScopeType) func(*context.APIContext) {
	return func(ctx *context.APIContext) {
		scope := authz_model.Scope{Type: typ}
		switch typ {
		case authz_model.ScopeRepo:
			scope.ID = ctx.Repo.Repository.ID
		case authz_model.ScopeOrg:
			scope.ID = ctx.Org.Organization.ID
		}
		ctx.Data[scopeDataKey] = scope
	}
}

func scope(ctx *context.APIContext) authz_model.Scope {
	value, _ := ctx.Data[scopeDataKey].(authz_model.Scope)
	return value
}

func RequireManagement(ctx *context.APIContext) {
	if err := authz_service.CheckManagementAuthority(ctx, ctx.Doer, scope(ctx)); err != nil {
		apiError(ctx, err)
		return
	}
	if !setting.EnterpriseAuthz.Enabled {
		ctx.APIErrorNotFound()
	}
}

func RequireDecisionManagement(ctx *context.APIContext) {
	if ctx.PublicOnly {
		ctx.APIError(http.StatusForbidden, "unrestricted_token_required")
		return
	}
	RequireManagement(ctx)
}

func RequireDiagnostic(ctx *context.APIContext) {
	if !common.RepoCredentialCeiling(ctx.Base, ctx.Doer).Read || !ctx.Repo.Permission.HasAnyUnitAccessOrPublicAccess() {
		ctx.APIError(http.StatusForbidden, "permission_denied")
		return
	}
}

func diagnosticGate(ctx *context.APIContext, targetID int64) bool {
	if targetID != 0 && targetID != ctx.Doer.ID {
		if err := authz_service.CheckManagementAuthority(ctx, ctx.Doer, scope(ctx)); err != nil {
			apiError(ctx, err)
			return false
		}
	}
	if !setting.EnterpriseAuthz.Enabled {
		ctx.APIErrorNotFound()
		return false
	}
	return true
}

func apiError(ctx *context.APIContext, err error) {
	switch {
	case errors.Is(err, util.ErrPermissionDenied):
		ctx.APIError(http.StatusForbidden, "permission_denied")
	case errors.Is(err, util.ErrNotExist):
		ctx.APIErrorNotFound()
	case errors.Is(err, authz_service.ErrInvalidPolicy):
		ctx.APIError(http.StatusUnprocessableEntity, "invalid_policy")
	case errors.Is(err, authz_service.ErrRevisionConflict):
		ctx.APIError(http.StatusConflict, "revision_conflict")
	case errors.Is(err, authz_service.ErrBuiltinImmutable):
		ctx.APIError(http.StatusConflict, "builtin_role_immutable")
	case errors.Is(err, authz_service.ErrRoleReferenced):
		ctx.APIError(http.StatusConflict, "role_referenced")
	case errors.Is(err, authz_service.ErrRoleNameConflict):
		ctx.APIError(http.StatusConflict, "role_name_conflict")
	default:
		log.Error("enterprise_authz_api: policy_storage_failed")
		ctx.JSON(http.StatusInternalServerError, context.APIError{Message: "policy_storage_failed", URL: setting.API.SwaggerURL})
	}
}

func strictObject(raw []byte, allowed ...string) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, authz_service.ErrInvalidPolicy
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, authz_service.ErrInvalidPolicy
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return nil, authz_service.ErrInvalidPolicy
		}
		key, ok := t.(string)
		if !ok || !slices.Contains(allowed, key) {
			return nil, authz_service.ErrInvalidPolicy
		}
		if _, exists := fields[key]; exists {
			return nil, authz_service.ErrInvalidPolicy
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, authz_service.ErrInvalidPolicy
		}
		fields[key] = value
	}
	if t, err = d.Token(); err != nil || t != json.Delim('}') {
		return nil, authz_service.ErrInvalidPolicy
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, authz_service.ErrInvalidPolicy
	}
	return fields, nil
}

func readBody(ctx *context.APIContext, allowed ...string) (map[string]json.RawMessage, error) {
	raw, err := io.ReadAll(io.LimitReader(ctx.Req.Body, authz.MaxBodyBytes+1))
	if err != nil || len(raw) > authz.MaxBodyBytes {
		return nil, authz_service.ErrInvalidPolicy
	}
	return strictObject(raw, allowed...)
}

func body(ctx *context.APIContext, allowed ...string) (map[string]json.RawMessage, bool) {
	fields, err := readBody(ctx, allowed...)
	if err != nil {
		apiError(ctx, err)
		return nil, false
	}
	return fields, true
}

func field[T any](fields map[string]json.RawMessage, key string, out *T) error {
	if raw, exists := fields[key]; exists && json.Unmarshal(raw, out) != nil {
		return authz_service.ErrInvalidPolicy
	}
	return nil
}

func permissions(fields map[string]json.RawMessage) (*[]authz_service.PermissionInput, error) {
	raw, exists := fields["permissions"]
	if !exists {
		return nil, nil //nolint:nilnil // 未指定权限时保留复制或更新语义，区别于显式空数组。
	}
	var entries []json.RawMessage
	if json.Unmarshal(raw, &entries) != nil || len(entries) > authz.MaxRolePermissions {
		return nil, authz_service.ErrInvalidPolicy
	}
	result := make([]authz_service.PermissionInput, 0, len(entries))
	for _, entry := range entries {
		values, err := strictObject(entry, "action", "effect", "condition")
		if err != nil {
			return nil, err
		}
		p := authz_service.PermissionInput{}
		if field(values, "action", &p.Action) != nil || field(values, "effect", &p.Effect) != nil {
			return nil, authz_service.ErrInvalidPolicy
		}
		p.Condition = values["condition"]
		result = append(result, p)
	}
	return &result, nil
}

func queryInt(ctx *context.APIContext, key string) (int64, error) {
	values, exists := ctx.Req.URL.Query()[key]
	if !exists {
		return 0, nil
	}
	if len(values) != 1 || values[0] == "" {
		return 0, authz_service.ErrInvalidPolicy
	}
	v, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil {
		return 0, authz_service.ErrInvalidPolicy
	}
	return v, nil
}

func pagination(ctx *context.APIContext) (authz_service.PolicyListOptions, error) {
	page, e1 := queryInt(ctx, "page")
	limit, e2 := queryInt(ctx, "limit")
	if e1 != nil || e2 != nil || page < 0 || limit < 0 || limit > 100 || page > int64(int(^uint(0)>>1))/100 {
		return authz_service.PolicyListOptions{}, authz_service.ErrInvalidPolicy
	}
	return authz_service.PolicyListOptions{Page: int(page), Limit: int(limit)}, nil
}

func id(ctx *context.APIContext) (int64, error) {
	v, err := strconv.ParseInt(ctx.PathParam("id"), 10, 64)
	if err != nil || v <= 0 {
		return 0, authz_service.ErrInvalidPolicy
	}
	return v, nil
}

func total(ctx *context.APIContext, n int64) {
	ctx.SetTotalCountHeader(n)
}

func Actions(ctx *context.APIContext) {
	result := api.EnterpriseAuthzActionCatalog{Version: authz.CatalogVersion, Actions: []api.EnterpriseAuthzAction{}}
	for _, a := range authz.Catalog() {
		result.Actions = append(result.Actions, api.EnterpriseAuthzAction{Key: string(a.Key), Description: a.Description, Units: a.Units, Risk: a.Risk, Mutating: a.Mutating, Observed: a.Observed, UnitsAny: a.UnitsAny})
	}
	ctx.JSON(http.StatusOK, result)
}

func ListRoles(ctx *context.APIContext) {
	options, err := pagination(ctx)
	if err != nil {
		apiError(ctx, err)
		return
	}
	roles, n, err := authz_service.ListRoles(ctx, ctx.Doer, scope(ctx), options)
	if err != nil {
		apiError(ctx, err)
		return
	}
	result := make([]*api.EnterpriseAuthzRole, 0, len(roles))
	for _, role := range roles {
		dto, err := roleDTO(role)
		if err != nil {
			apiError(ctx, err)
			return
		}
		result = append(result, dto)
	}
	total(ctx, n)
	ctx.JSON(http.StatusOK, result)
}

func GetRole(ctx *context.APIContext) {
	roleID, err := id(ctx)
	if err != nil {
		apiError(ctx, err)
		return
	}
	role, err := authz_service.GetRole(ctx, ctx.Doer, scope(ctx), roleID)
	if err != nil {
		apiError(ctx, err)
		return
	}
	dto, err := roleDTO(role)
	if err != nil {
		apiError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, dto)
}

func CreateRole(ctx *context.APIContext) {
	fields, ok := body(ctx, "name", "description", "copy_from_role_id", "permissions")
	if !ok {
		return
	}
	input := authz_service.CreateRoleInput{}
	if field(fields, "name", &input.Name) != nil || field(fields, "description", &input.Description) != nil || field(fields, "copy_from_role_id", &input.CopyFromRoleID) != nil {
		apiError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	var err error
	input.Permissions, err = permissions(fields)
	if err != nil {
		apiError(ctx, err)
		return
	}
	role, err := authz_service.CreateRole(ctx, ctx.Doer, scope(ctx), input)
	if err != nil {
		apiError(ctx, err)
		return
	}
	dto, err := roleDTO(role)
	if err != nil {
		apiError(ctx, err)
		return
	}
	ctx.JSON(http.StatusCreated, dto)
}

func UpdateRole(ctx *context.APIContext) {
	roleID, err := id(ctx)
	if err != nil {
		apiError(ctx, err)
		return
	}
	fields, ok := body(ctx, "name", "description", "expected_revision", "permissions")
	if !ok {
		return
	}
	input := authz_service.UpdateRoleInput{}
	if field(fields, "name", &input.Name) != nil || field(fields, "description", &input.Description) != nil || field(fields, "expected_revision", &input.ExpectedRevision) != nil {
		apiError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	input.Permissions, err = permissions(fields)
	if err != nil {
		apiError(ctx, err)
		return
	}
	role, err := authz_service.UpdateRole(ctx, ctx.Doer, scope(ctx), roleID, input)
	if err != nil {
		apiError(ctx, err)
		return
	}
	dto, err := roleDTO(role)
	if err != nil {
		apiError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, dto)
}

func DeleteRole(ctx *context.APIContext) {
	roleID, err := id(ctx)
	if err != nil {
		apiError(ctx, err)
		return
	}
	revision, err := queryInt(ctx, "expected_revision")
	if err != nil {
		apiError(ctx, err)
		return
	}
	if err = authz_service.DeleteRole(ctx, ctx.Doer, scope(ctx), roleID, revision); err != nil {
		apiError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

func ListBindings(ctx *context.APIContext) {
	options, err := pagination(ctx)
	if err != nil {
		apiError(ctx, err)
		return
	}
	bindings, n, err := authz_service.ListBindings(ctx, ctx.Doer, scope(ctx), options)
	if err != nil {
		apiError(ctx, err)
		return
	}
	result := make([]api.EnterpriseAuthzBinding, 0, len(bindings))
	for _, b := range bindings {
		if !slices.Contains([]authz_model.SubjectType{authz_model.SubjectUser, authz_model.SubjectTeam, authz_model.SubjectOrg}, b.SubjectType) || !(authz_model.Scope{Type: b.ScopeType, ID: b.ScopeID}).Valid() || b.ID <= 0 || b.SubjectID <= 0 || b.RoleID <= 0 || b.ScopeOwnerID < 0 {
			apiError(ctx, authz_service.ErrPolicyStorage)
			return
		}
		result = append(result, api.EnterpriseAuthzBinding{ID: b.ID, SubjectType: string(b.SubjectType), SubjectID: b.SubjectID, Scope: api.EnterpriseAuthzScope{Type: string(b.ScopeType), ID: b.ScopeID}, ScopeOwnerID: b.ScopeOwnerID, RoleID: b.RoleID, CreatedBy: b.CreatedBy, Created: b.CreatedUnix.AsTime()})
	}
	total(ctx, n)
	ctx.JSON(http.StatusOK, result)
}

func PutBinding(ctx *context.APIContext) {
	fields, ok := body(ctx, "subject_type", "subject_id", "role_id")
	if !ok {
		return
	}
	input := authz_service.BindingInput{}
	if field(fields, "subject_type", &input.SubjectType) != nil || field(fields, "subject_id", &input.SubjectID) != nil || field(fields, "role_id", &input.RoleID) != nil {
		apiError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	if _, _, err := authz_service.PutBinding(ctx, ctx.Doer, scope(ctx), input); err != nil {
		apiError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

func DeleteBinding(ctx *context.APIContext) {
	bindingID, err := id(ctx)
	if err != nil {
		apiError(ctx, err)
		return
	}
	if err = authz_service.DeleteBinding(ctx, ctx.Doer, scope(ctx), bindingID); err != nil {
		apiError(ctx, err)
		return
	}
	ctx.Status(http.StatusNoContent)
}

func ListDecisions(ctx *context.APIContext) {
	page, err := pagination(ctx)
	if err != nil {
		apiError(ctx, err)
		return
	}
	options := authz_service.DecisionListOptions{PolicyListOptions: page, Action: authz.Action(ctx.FormString("action")), CandidateDecision: ctx.FormString("decision")}
	repoID, e1 := queryInt(ctx, "repo_id")
	actorID, e2 := queryInt(ctx, "actor_id")
	since, e3 := queryInt(ctx, "since")
	until, e4 := queryInt(ctx, "until")
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		apiError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	options.RepoID = repoID
	options.Since = timeutil.TimeStamp(since)
	options.Until = timeutil.TimeStamp(until)
	if ctx.Req.URL.Query().Has("actor_id") {
		options.ActorID = &actorID
	}
	records, n, err := authz_service.ListDecisions(ctx, ctx.Doer, scope(ctx), options)
	if err != nil {
		apiError(ctx, err)
		return
	}
	result := make([]*api.EnterpriseAuthzDecision, 0, len(records))
	for i := range records {
		dto, err := decisionDTO(&records[i])
		if err != nil {
			apiError(ctx, err)
			return
		}
		result = append(result, dto)
	}
	total(ctx, n)
	ctx.JSON(http.StatusOK, result)
}

func GetDecision(ctx *context.APIContext) {
	decisionID, err := id(ctx)
	if err != nil {
		apiError(ctx, err)
		return
	}
	record, err := authz_service.GetDecision(ctx, ctx.Doer, scope(ctx), decisionID)
	if err != nil {
		apiError(ctx, err)
		return
	}
	dto, err := decisionDTO(record)
	if err != nil {
		apiError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, dto)
}

func diagnosticInput(ctx *context.APIContext) authz_service.DiagnosticInput {
	return authz_service.DiagnosticInput{Caller: ctx.Doer, Repo: ctx.Repo.Repository, Permission: &ctx.Repo.Permission, Credential: common.RepoCredentialCeiling(ctx.Base, ctx.Doer), ConditionContext: authz.ConditionContext{Source: "diagnostic"}}
}

func EffectivePermissions(ctx *context.APIContext) {
	input := diagnosticInput(ctx)
	var err error
	input.TargetUserID, err = queryInt(ctx, "user_id")
	if !diagnosticGate(ctx, input.TargetUserID) {
		return
	}
	if err != nil {
		apiError(ctx, err)
		return
	}
	result, err := authz_service.EffectivePermissions(ctx, input)
	if err != nil {
		apiError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, api.EnterpriseAuthzEffectivePermissions{EnterpriseAuthzExplanation: explanationDTO(result.NativeActions, result.RoleActions, result.Reason, result.Roles, result.Bindings, result.Conditions), UnresolvedActions: actionsDTO(result.UnresolvedActions)})
}

func Evaluate(ctx *context.APIContext) {
	fields, parseErr := readBody(ctx, "action", "user_id", "branch", "paths")
	input := diagnosticInput(ctx)
	userErr := field(fields, "user_id", &input.TargetUserID)
	if !diagnosticGate(ctx, input.TargetUserID) {
		return
	}
	if parseErr != nil || userErr != nil {
		apiError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	if field(fields, "action", &input.Action) != nil || field(fields, "user_id", &input.TargetUserID) != nil || field(fields, "branch", &input.ConditionContext.Branch) != nil || field(fields, "paths", &input.ConditionContext.Paths) != nil {
		apiError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	input.ConditionContext.BranchKnown = input.ConditionContext.Branch != ""
	input.ConditionContext.PathsComplete = len(input.ConditionContext.Paths) > 0
	result, err := authz_service.Diagnose(ctx, input)
	if err != nil {
		apiError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, api.EnterpriseAuthzDiagnostic{EnterpriseAuthzExplanation: explanationDTO(result.NativeActions, result.RoleActions, result.Reason, result.Roles, result.Bindings, result.Conditions), Action: string(result.Action), CandidateDecision: result.CandidateDecision, MatchedRoleIDs: result.MatchedRoleIDs, MatchedBindingIDs: result.MatchedBindingIDs, MissingActions: actionsDTO(result.MissingActions)})
}
