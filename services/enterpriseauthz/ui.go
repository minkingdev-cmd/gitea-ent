// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"

	authz_model "gitea.dev/models/enterpriseauthz"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
)

type ManagementUI struct {
	ctx   context.Context
	actor *user_model.User
	scope authz_model.Scope
}

func CheckUIAuthority(ctx context.Context, actor *user_model.User) error {
	if err := CheckManagementAuthority(ctx, actor, authz_model.Scope{Type: authz_model.ScopeSystem}); err != nil {
		return safePolicyError(err)
	}
	if !setting.EnterpriseAuthz.Enabled {
		return util.ErrNotExist
	}
	return nil
}

func NewManagementUI(ctx context.Context, actor *user_model.User, scope authz_model.Scope) (*ManagementUI, error) {
	if err := CheckUIAuthority(ctx, actor); err != nil {
		return nil, err
	}
	ui := &ManagementUI{ctx: ctx, actor: &user_model.User{ID: actor.ID}, scope: scope}
	if err := ui.authorize(); err != nil {
		return nil, err
	}
	return ui, nil
}

func (ui *ManagementUI) authorize() error {
	if err := CheckUIAuthority(ui.ctx, ui.actor); err != nil {
		return err
	}
	return safePolicyError(CheckManagementAuthority(ui.ctx, ui.actor, ui.scope))
}

func (ui *ManagementUI) Roles(options PolicyListOptions) ([]*Role, int64, error) {
	if err := ui.authorize(); err != nil {
		return nil, 0, err
	}
	return ListRoles(ui.ctx, ui.actor, ui.scope, options)
}

func (ui *ManagementUI) Role(id int64) (*Role, error) {
	if err := ui.authorize(); err != nil {
		return nil, err
	}
	return GetRole(ui.ctx, ui.actor, ui.scope, id)
}

func (ui *ManagementUI) CreateRole(input CreateRoleInput) (*Role, error) {
	if err := ui.authorize(); err != nil {
		return nil, err
	}
	return CreateRole(ui.ctx, ui.actor, ui.scope, input)
}

func (ui *ManagementUI) UpdateRole(id int64, input UpdateRoleInput) (*Role, error) {
	if err := ui.authorize(); err != nil {
		return nil, err
	}
	return UpdateRole(ui.ctx, ui.actor, ui.scope, id, input)
}

func (ui *ManagementUI) DeleteRole(id, expectedRevision int64) error {
	if err := ui.authorize(); err != nil {
		return err
	}
	return DeleteRole(ui.ctx, ui.actor, ui.scope, id, expectedRevision)
}

func (ui *ManagementUI) Bindings(options PolicyListOptions) ([]authz_model.SubjectRoleBinding, int64, error) {
	if err := ui.authorize(); err != nil {
		return nil, 0, err
	}
	return ListBindings(ui.ctx, ui.actor, ui.scope, options)
}

func (ui *ManagementUI) PutBinding(input BindingInput) (*authz_model.SubjectRoleBinding, bool, error) {
	if err := ui.authorize(); err != nil {
		return nil, false, err
	}
	return PutBinding(ui.ctx, ui.actor, ui.scope, input)
}

func (ui *ManagementUI) DeleteBinding(id int64) error {
	if err := ui.authorize(); err != nil {
		return err
	}
	return DeleteBinding(ui.ctx, ui.actor, ui.scope, id)
}

func (ui *ManagementUI) Decisions(options DecisionListOptions) ([]authz_model.DecisionRecord, int64, error) {
	if err := ui.authorize(); err != nil {
		return nil, 0, err
	}
	return ListDecisions(ui.ctx, ui.actor, ui.scope, options)
}

func (ui *ManagementUI) Decision(id int64) (*authz_model.DecisionRecord, error) {
	if err := ui.authorize(); err != nil {
		return nil, err
	}
	return GetDecision(ui.ctx, ui.actor, ui.scope, id)
}

func (ui *ManagementUI) diagnosticInput(input DiagnosticInput) (DiagnosticInput, error) {
	if err := ui.authorize(); err != nil {
		return DiagnosticInput{}, err
	}
	if ui.scope.Type != authz_model.ScopeRepo || input.Repo != nil && input.Repo.ID != ui.scope.ID {
		return DiagnosticInput{}, util.ErrNotExist
	}
	repo, err := repo_model.GetRepositoryByID(ui.ctx, ui.scope.ID)
	if err != nil {
		return DiagnosticInput{}, safePolicyError(err)
	}
	actor, err := user_model.GetUserByID(ui.ctx, ui.actor.ID)
	if err != nil {
		return DiagnosticInput{}, safePolicyError(err)
	}
	permission, err := access_model.GetDoerRepoPermission(ui.ctx, repo, actor)
	if err != nil {
		return DiagnosticInput{}, ErrPolicyStorage
	}
	input.Caller = actor
	input.Repo = repo
	input.Permission = &permission
	input.Credential = CredentialCeiling{Read: true, Write: true}
	input.ConditionContext.Source = "diagnostic"
	return input, nil
}

func (ui *ManagementUI) Evaluate(input DiagnosticInput) (DiagnosticResult, error) {
	input, err := ui.diagnosticInput(input)
	if err != nil {
		return DiagnosticResult{}, err
	}
	return Diagnose(ui.ctx, input)
}

func (ui *ManagementUI) EffectivePermissions(input DiagnosticInput) (EffectivePermissionResult, error) {
	input, err := ui.diagnosticInput(input)
	if err != nil {
		return EffectivePermissionResult{}, err
	}
	return EffectivePermissions(ui.ctx, input)
}
