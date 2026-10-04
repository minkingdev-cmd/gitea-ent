// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"cmp"
	"context"
	"net/http"
	"slices"

	"gitea.dev/models/organization"
	repo_model "gitea.dev/models/repo"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/services/audit"
	authz_service "gitea.dev/services/enterpriseauthz"
)

type (
	teamAccessKey   struct{}
	teamAccessState struct {
		teamID, orgID                  int64
		fingerprint, intent, operation string
		owners                         map[int64]int64
	}
)

func teamAccessFingerprint(team *organization.Team) string {
	return accessIntent("team-state", struct {
		Name        string
		OrgID       int64
		Mode        int
		IncludesAll bool
		Units       []struct{ Type, Mode int }
	}{team.Name, team.OrgID, int(team.AccessMode), team.IncludesAllRepositories, teamUnits(team)})
}

func teamUnits(team *organization.Team) []struct{ Type, Mode int } {
	units := make(map[int]int, len(team.Units))
	for _, item := range team.Units {
		units[int(item.Type)] = int(item.AccessMode)
	}
	ordered := make([]struct{ Type, Mode int }, 0, len(units))
	for typ, mode := range units {
		ordered = append(ordered, struct{ Type, Mode int }{typ, mode})
	}
	slices.SortFunc(ordered, func(a, b struct{ Type, Mode int }) int { return cmp.Compare(a.Type, b.Type) })
	return ordered
}

func teamMutationRepositories(ctx context.Context, team *organization.Team, operation string) ([]*repo_model.Repository, error) {
	if operation == "create" || operation == "add-all" || operation == "delete" {
		return repo_model.GetOrgRepositories(ctx, team.OrgID)
	}
	repos, err := repo_model.GetTeamRepositories(ctx, &repo_model.SearchTeamRepoOptions{TeamID: team.ID})
	if err != nil {
		return nil, err
	}
	if operation == "update" && team.IncludesAllRepositories {
		return repo_model.GetOrgRepositories(ctx, team.OrgID)
	}
	return repos, nil
}

// BeginTeamAccessMutation 仅准备团队授权配置、全库关联或删除的完整仓库集合。
func BeginTeamAccessMutation(ctx context.Context, team *organization.Team, operation string) (context.Context, func(error), error) {
	noop := func(error) {}
	if !setting.EnterpriseAuthz.Enabled {
		return ctx, noop, nil
	}
	switch operation {
	case "create", "update", "delete", "add-all", "remove-all":
	default:
		return ctx, noop, accessRejection("invalid_execution_context", http.StatusForbidden)
	}
	if team == nil || team.OrgID <= 0 {
		return ctx, noop, accessRejection("invalid_execution_context", http.StatusForbidden)
	}
	state := teamAccessState{teamID: team.ID, orgID: team.OrgID, fingerprint: teamAccessFingerprint(team), operation: operation, owners: make(map[int64]int64)}
	state.intent = accessIntent("team-"+operation, struct {
		ID    int64
		State string
	}{team.ID, state.fingerprint})
	ctx, finish, err := beginAccessMutation(ctx, team.OrgID, state.intent, func(ctx context.Context) ([]*repo_model.Repository, error) {
		repos, err := teamMutationRepositories(ctx, team, operation)
		for _, repo := range repos {
			state.owners[repo.ID] = repo.OwnerID
		}
		return repos, err
	}, true)
	if err != nil {
		return ctx, noop, err
	}
	return context.WithValue(ctx, teamAccessKey{}, state), finish, nil
}

func validateTeamAccessRepositories(ctx context.Context, team *organization.Team, repos []*repo_model.Repository, full bool) error {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return nil
	}
	state, ok := ctx.Value(teamAccessKey{}).(teamAccessState)
	if !ok || state.orgID != team.OrgID || state.teamID != team.ID && state.operation != "create" || state.fingerprint != teamAccessFingerprint(team) || full && len(repos) != len(state.owners) {
		return accessRejection("invalid_execution_context", http.StatusForbidden)
	}
	if err := requireAccessMutation(ctx, team.OrgID, state.intent, repos); err != nil {
		return err
	}
	actor := audit.DoerFromContext(ctx)
	if actor == nil {
		return accessRejection("invalid_execution_context", http.StatusForbidden)
	}
	ceiling, err := authz_service.OrganizationAccessCredentialCeiling(ctx, actor, team.OrgID)
	if err != nil {
		return err
	}
	for _, repo := range repos {
		if owner, found := state.owners[repo.ID]; !found || owner != repo.OwnerID {
			return accessRejection("invalid_execution_context", http.StatusForbidden)
		}
		input := authz_service.ExecutionInput{EvaluateInput: authz_service.EvaluateInput{Actor: actor, Repo: repo, Credential: ceiling, Action: authz.ManageAccess, ConditionContext: authz.ConditionContext{Source: authz_service.ExecutionSource(ctx)}}, Intent: state.intent}
		if err := authz_service.RequireExecutionInput(ctx, input); err != nil {
			return err
		}
	}
	return nil
}

func ValidateTeamAccessMutation(ctx context.Context, team *organization.Team) error {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return nil
	}
	state, ok := ctx.Value(teamAccessKey{}).(teamAccessState)
	if !ok {
		return accessRejection("invalid_execution_context", http.StatusForbidden)
	}
	repos, err := teamMutationRepositories(ctx, team, state.operation)
	if err != nil {
		return accessRejection("policy_read_failed", http.StatusServiceUnavailable)
	}
	return validateTeamAccessRepositories(ctx, team, repos, true)
}

func beginTeamRepositoryMutation(ctx context.Context, team *organization.Team, repo *repo_model.Repository, remove bool) (context.Context, func(error), error) {
	intent := teamRepositoryIntent(team.ID, repo.ID, remove)
	return beginAccessMutation(ctx, team.OrgID, intent, func(context.Context) ([]*repo_model.Repository, error) { return []*repo_model.Repository{repo}, nil }, true)
}

func teamRepositoryIntent(teamID, repoID int64, remove bool) string {
	return accessIntent("team-repository", struct {
		TeamID, RepoID int64
		Remove         bool
	}{teamID, repoID, remove})
}

func beginTeamRepositoriesMutation(ctx context.Context, team *organization.Team, operation string) (context.Context, func(error), error) {
	if _, ok := ctx.Value(teamAccessKey{}).(teamAccessState); ok {
		return ctx, func(error) {}, nil
	}
	return BeginTeamAccessMutation(ctx, team, operation)
}

func RemoveTeamRepositoriesForDeletion(ctx context.Context, team *organization.Team) error {
	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
		state, ok := ctx.Value(teamAccessKey{}).(teamAccessState)
		if !ok || state.operation != "delete" {
			return accessRejection("invalid_execution_context", http.StatusForbidden)
		}
		if err := ValidateTeamAccessMutation(ctx, team); err != nil {
			return err
		}
	}
	return removeAllRepositoriesFromTeam(ctx, team)
}
