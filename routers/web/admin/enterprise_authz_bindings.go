// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package admin

import (
	"net/http"
	"strconv"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/organization"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/templates"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
)

const tplAuthzBindings templates.TplName = "admin/enterpriseauthz/bindings"

type authzBindingView struct {
	Binding     authz_model.SubjectRoleBinding
	SubjectName string
	RoleName    string
	RoleScope   string
	OwnerName   string
	Status      string
}

type authzBindingDraft struct{ SubjectType, SubjectID, RoleID string }

func authzBindingDisplay(ctx *context.Context, binding authz_model.SubjectRoleBinding, ownerID int64) (authzBindingView, error) {
	view := authzBindingView{Binding: binding, Status: "current", SubjectName: ctx.Locale.TrString("admin.enterprise_authz.deleted_subject"), RoleName: ctx.Locale.TrString("admin.enterprise_authz.deleted_role")}
	role, exists, err := db.GetByID[authz_model.RoleDefinition](ctx, binding.RoleID)
	if err != nil {
		return view, authz_service.ErrPolicyStorage
	}
	if exists {
		if !role.Scope().Valid() {
			return view, authz_service.ErrPolicyStorage
		}
		view.RoleName = role.Name
		view.RoleScope, err = authzScopeName(ctx, role.Scope())
		if err != nil {
			return view, err
		}
	} else {
		view.Status = "role_deleted"
	}
	view.OwnerName = ctx.Locale.TrString("admin.enterprise_authz.scope.system")
	if binding.ScopeOwnerID != 0 {
		owner, exists, e := db.GetByID[user_model.User](ctx, binding.ScopeOwnerID)
		if e != nil {
			return view, authz_service.ErrPolicyStorage
		}
		view.OwnerName = ctx.Locale.TrString("admin.enterprise_authz.deleted_subject")
		if exists {
			view.OwnerName = owner.Name
		}
	}
	var orgID int64
	switch binding.SubjectType {
	case authz_model.SubjectUser, authz_model.SubjectOrg:
		subject, exists, err := db.GetByID[user_model.User](ctx, binding.SubjectID)
		if err != nil {
			return view, authz_service.ErrPolicyStorage
		}
		if !exists || binding.SubjectType == authz_model.SubjectUser && !subject.IsIndividual() || binding.SubjectType == authz_model.SubjectOrg && !subject.IsOrganization() {
			view.Status = "subject_deleted"
		} else {
			view.SubjectName = subject.Name
			if binding.SubjectType == authz_model.SubjectOrg {
				orgID = subject.ID
			}
			if binding.SubjectType == authz_model.SubjectUser && (!subject.IsActive || subject.ProhibitLogin || subject.IsRestricted) {
				view.Status = "subject_ineligible"
			}
		}
	case authz_model.SubjectTeam:
		team, exists, err := db.GetByID[organization.Team](ctx, binding.SubjectID)
		if err != nil {
			return view, authz_service.ErrPolicyStorage
		}
		if !exists {
			view.Status = "subject_deleted"
			break
		}
		view.SubjectName = team.Name
		orgID = team.OrgID
		org, exists, err := db.GetByID[user_model.User](ctx, team.OrgID)
		if err != nil {
			return view, authz_service.ErrPolicyStorage
		}
		if !exists || !org.IsOrganization() {
			view.Status = "subject_deleted"
			break
		}
		view.SubjectName = org.Name + " / " + team.Name
		if binding.ScopeType == authz_model.ScopeRepo && !team.IncludesAllRepositories {
			related, err := db.GetEngine(ctx).Where("org_id = ? AND team_id = ? AND repo_id = ?", team.OrgID, team.ID, binding.ScopeID).Exist(new(organization.TeamRepo))
			if err != nil {
				return view, authz_service.ErrPolicyStorage
			}
			if !related {
				view.Status = "relation_changed"
			}
		}
	default:
		return view, authz_service.ErrPolicyStorage
	}
	if binding.ScopeType != authz_model.ScopeSystem && orgID != 0 && orgID != ownerID {
		view.Status = "relation_changed"
	}
	if binding.ScopeType == authz_model.ScopeRepo && binding.ScopeOwnerID != ownerID {
		view.Status = "owner_changed"
	}
	return view, nil
}

func authzBindingPage(ctx *context.Context, ui *authz_service.ManagementUI, status int) {
	opts, err := authzPaging(ctx)
	if err != nil {
		authzError(ctx, err)
		return
	}
	bindings, total, err := ui.Bindings(opts)
	if err != nil {
		authzError(ctx, err)
		return
	}
	scope, ok := ctx.Data["AuthzScope"].(authz_model.Scope)
	if !ok {
		authzError(ctx, authz_service.ErrPolicyStorage)
		return
	}
	ownerID := scope.ID
	if scope.Type == authz_model.ScopeRepo {
		repo, err := repo_model.GetRepositoryByID(ctx, scope.ID)
		if err != nil {
			authzError(ctx, authz_service.ErrPolicyStorage)
			return
		}
		ownerID = repo.OwnerID
	}
	views := make([]authzBindingView, 0, len(bindings))
	for _, binding := range bindings {
		view, err := authzBindingDisplay(ctx, binding, ownerID)
		if err != nil {
			authzError(ctx, err)
			return
		}
		views = append(views, view)
	}
	ctx.Data["AuthzTab"] = "bindings"
	ctx.Data["AuthzBindings"] = views
	if ctx.Data["AuthzBindingDraft"] == nil {
		ctx.Data["AuthzBindingDraft"] = authzBindingDraft{SubjectType: "user"}
	}
	draft, ok := ctx.Data["AuthzBindingDraft"].(authzBindingDraft)
	if !ok {
		authzError(ctx, authz_service.ErrPolicyStorage)
		return
	}
	kind := draft.SubjectType
	if kind != "user" && kind != "team" && kind != "org" {
		kind = "user"
	}
	if !authzPicker(ctx, ui, "AuthzBindingSubjectPicker", "authz-binding-subject-id", "subject_id", kind, "binding.search_subject", draft.SubjectID, true) || !authzPicker(ctx, ui, "AuthzBindingRolePicker", "authz-binding-role-id", "role_id", "role", "binding.search_role", draft.RoleID, true) {
		return
	}
	authzPager(ctx, opts, total)
	authzRender(ctx, status, tplAuthzBindings)
}

func EnterpriseAuthzBindings(ctx *context.Context) {
	ui := authzUI(ctx)
	if ui == nil {
		return
	}
	authzBindingPage(ctx, ui, http.StatusOK)
}

func authzBindingFailure(ctx *context.Context, ui *authz_service.ManagementUI, err error) {
	status, reason := authzFailure(err)
	if status == http.StatusForbidden || status == http.StatusNotFound {
		authzError(ctx, err)
		return
	}
	ctx.Data["AuthzError"] = ctx.Locale.TrString("admin.enterprise_authz.error." + reason)
	authzBindingPage(ctx, ui, status)
}

func EnterpriseAuthzBindingPut(ctx *context.Context) {
	ui := authzUI(ctx)
	if ui == nil {
		return
	}
	base, ok := ctx.Data["AuthzBase"].(string)
	if !ok {
		authzError(ctx, authz_service.ErrPolicyStorage)
		return
	}
	draft := authzBindingDraft{SubjectType: ctx.FormString("subject_type"), SubjectID: ctx.FormString("subject_id"), RoleID: ctx.FormString("role_id")}
	ctx.Data["AuthzBindingDraft"] = draft
	if err := authzCheckFields(ctx, "subject_type", "subject_id", "role_id"); err != nil {
		authzBindingFailure(ctx, ui, err)
		return
	}
	subjectID, err := strconv.ParseInt(draft.SubjectID, 10, 64)
	if err != nil || subjectID <= 0 {
		authzBindingFailure(ctx, ui, authz_service.ErrInvalidPolicy)
		return
	}
	roleID, err := strconv.ParseInt(draft.RoleID, 10, 64)
	if err != nil || roleID <= 0 {
		authzBindingFailure(ctx, ui, authz_service.ErrInvalidPolicy)
		return
	}
	if _, _, err = ui.PutBinding(authz_service.BindingInput{SubjectType: authz_model.SubjectType(draft.SubjectType), SubjectID: subjectID, RoleID: roleID}); err != nil {
		authzBindingFailure(ctx, ui, err)
		return
	}
	ctx.Redirect(base+"/bindings", http.StatusSeeOther)
}

func EnterpriseAuthzBindingDelete(ctx *context.Context) {
	ui := authzUI(ctx)
	if ui == nil {
		return
	}
	base, ok := ctx.Data["AuthzBase"].(string)
	if !ok {
		authzError(ctx, authz_service.ErrPolicyStorage)
		return
	}
	if err := authzCheckFields(ctx); err != nil {
		authzBindingFailure(ctx, ui, err)
		return
	}
	id, err := strconv.ParseInt(ctx.PathParam("id"), 10, 64)
	if err != nil || id <= 0 {
		authzBindingFailure(ctx, ui, authz_service.ErrInvalidPolicy)
		return
	}
	if err = ui.DeleteBinding(id); err != nil {
		authzBindingFailure(ctx, ui, err)
		return
	}
	ctx.Redirect(base+"/bindings", http.StatusSeeOther)
}
