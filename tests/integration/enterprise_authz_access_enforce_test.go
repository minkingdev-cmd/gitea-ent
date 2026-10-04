// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"testing"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/organization"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzAccessCollaboratorHTTP(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	enableLifecycleEnforcement(t)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeAdmin}, &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeAdmin}))
	session := loginUser(t, "user4")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	prefix := "/api/v1/repos/user2/repo1/collaborators/user5"
	response := session.MakeRequest(t, NewRequestWithJSON(t, "PUT", prefix, api.AddCollaboratorOption{}).AddTokenAuth(token), 403)
	require.Contains(t, response.Body.String(), "missing_action")
	unittest.AssertNotExistsBean(t, &repo_model.Collaboration{RepoID: 1, UserID: 5})
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/collaboration", map[string]string{"collaborator": "user5"}), 403)
	row := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 1, Action: authz.ManageAccess})
	require.Equal(t, "deny", row.AuthorizationDecision)
	require.False(t, row.ExecutionStarted)
	lifecycleRole(t, repo, 4, authz.ManageAccess)
	session.MakeRequest(t, NewRequestWithJSON(t, "PUT", prefix, api.AddCollaboratorOption{}).AddTokenAuth(token), 204)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/collaboration/access_mode", map[string]string{"uid": "5", "mode": "1"}), 200)
	unittest.AssertExistsAndLoadBean(t, &repo_model.Collaboration{RepoID: 1, UserID: 5, Mode: perm.AccessModeRead})
	session.MakeRequest(t, NewRequest(t, "DELETE", prefix).AddTokenAuth(token), 204)
	unittest.AssertNotExistsBean(t, &repo_model.Collaboration{RepoID: 1, UserID: 5})
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/collaboration", map[string]string{"collaborator": "user5"}), 303)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/collaboration/delete", map[string]string{"id": "5"}), 200)
	unittest.AssertNotExistsBean(t, &repo_model.Collaboration{RepoID: 1, UserID: 5})
}

func TestEnterpriseAuthzAccessOrganizationTokenTeamRepository(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	enableLifecycleEnforcement(t)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 5})
	require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: repo.ID, UserID: 15, Mode: perm.AccessModeAdmin}, &access_model.Access{RepoID: repo.ID, UserID: 15, Mode: perm.AccessModeAdmin}))
	_, err := db.GetEngine(t.Context()).ID(3).Cols("repo_admin_change_team_access").Update(&user_model.User{RepoAdminChangeTeamAccess: true})
	require.NoError(t, err)
	session := loginUser(t, "user15")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteOrganization)
	prefix := "/api/v1/teams/7/repos/org3/repo5"
	session.MakeRequest(t, NewRequest(t, "PUT", prefix).AddTokenAuth(token), 403)
	unittest.AssertNotExistsBean(t, &organization.TeamRepo{TeamID: 7, RepoID: repo.ID})
	lifecycleRole(t, repo, 15, authz.ManageAccess)
	session.MakeRequest(t, NewRequest(t, "PUT", prefix).AddTokenAuth(token), 204)
	unittest.AssertExistsAndLoadBean(t, &organization.TeamRepo{TeamID: 7, RepoID: repo.ID})
	session.MakeRequest(t, NewRequest(t, "DELETE", prefix).AddTokenAuth(token), 204)
	session.MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/org3/repo5/contents").AddTokenAuth(token), 403)
	session.MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/org3/repo5/actions/secrets/NO_SCOPE", api.CreateOrUpdateSecretOption{Data: "SENSITIVE-never"}).AddTokenAuth(token), 403)
}

func TestEnterpriseAuthzAccessTeamHTTPAndRollback(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	enableLifecycleEnforcement(t)
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteRepository)
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	beforeMode := team.AccessMode
	response := session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/teams/2", api.EditTeamOption{Name: "test_team", Permission: "admin"}).AddTokenAuth(token), 500)
	require.NotContains(t, response.Body.String(), "policy_read_failed")
	require.Equal(t, beforeMode, unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2}).AccessMode)
	row := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 3, Action: authz.ManageAccess, NativeOutcome: "failed"})
	require.Equal(t, "allow", row.AuthorizationDecision)
	require.True(t, row.ExecutionStarted)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/teams/team1/edit", map[string]string{"team_name": "team1", "permission": "admin", "repo_access": "specific"}), 303)
	require.Equal(t, perm.AccessModeAdmin, unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2}).AccessMode)
	session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/teams/2", api.EditTeamOption{Permission: "read", UnitsMap: map[string]string{"repo.code": "read", "repo.issues": "write"}}).AddTokenAuth(token), 200)
	team = unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	require.NoError(t, team.LoadUnits(t.Context()))
	require.Equal(t, map[string]string{"repo.code": "read", "repo.issues": "write"}, team.GetUnitsMap())
	for _, action := range []string{"addall", "removeall"} {
		session.MakeRequest(t, NewRequest(t, "POST", "/org/org3/teams/team1/action/repo/"+action), 200)
	}
	unittest.AssertNotExistsBean(t, &organization.TeamRepo{TeamID: 2})
	session.MakeRequest(t, NewRequest(t, "PUT", "/api/v1/repos/org3/repo5/teams/team1").AddTokenAuth(token), 204)
	session.MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/org3/repo5/teams/team1").AddTokenAuth(token), 204)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/teams/team1/action/repo/add", map[string]string{"repo_name": "repo5"}), 303)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/org/org3/teams/team1/action/repo/remove", map[string]string{"repoid": "5"}), 303)
	response = session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/orgs/org3/teams", api.CreateTeamOption{Name: "access-http-all", Permission: "read", IncludesAllRepositories: true}).AddTokenAuth(token), 201)
	created := DecodeJSON(t, response, &api.Team{})
	require.Equal(t, 3, unittest.GetCount(t, &organization.TeamRepo{TeamID: created.ID}))
	session.MakeRequest(t, NewRequestf(t, "DELETE", "/api/v1/teams/%d", created.ID).AddTokenAuth(token), 204)
	unittest.AssertNotExistsBean(t, &organization.TeamRepo{TeamID: created.ID})
	session.MakeRequest(t, NewRequest(t, "POST", "/org/org3/teams/team1/delete"), 200)
	unittest.AssertNotExistsBean(t, &organization.Team{ID: 2})
}

func TestEnterpriseAuthzAccessLegacyModesHTTP(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled-%t", enabled), func(t *testing.T) {
			defer tests.PrepareTestEnv(t)()
			enableLifecycleEnforcement(t)
			setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce = enabled, false
			require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeAdmin}, &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeAdmin}))
			session := loginUser(t, "user4")
			token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
			session.MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/repo1/collaborators/user5", api.AddCollaboratorOption{}).AddTokenAuth(token), 204)
			unittest.AssertExistsAndLoadBean(t, &repo_model.Collaboration{RepoID: 1, UserID: 5})
			if enabled {
				row := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 1, Action: authz.ManageAccess})
				require.Equal(t, "shadow", row.DecisionMode)
				require.Equal(t, "deny", row.CandidateDecision)
				require.Equal(t, "not_enforced", row.AuthorizationDecision)
				require.Equal(t, "success", row.NativeOutcome)
			} else {
				unittest.AssertNotExistsBean(t, &authz_model.DecisionRecord{Action: authz.ManageAccess})
			}
		})
	}
}

func TestEnterpriseAuthzAccessReaderAndInfrastructureHTTP(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	enableLifecycleEnforcement(t)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	lifecycleRole(t, repo, 4, authz.ManageAccess)
	session := loginUser(t, "user4")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	request := func() *RequestWrapper {
		return NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/repo1/collaborators/user5", api.AddCollaboratorOption{}).AddTokenAuth(token)
	}
	session.MakeRequest(t, request(), 403)
	unittest.AssertNotExistsBean(t, &repo_model.Collaboration{RepoID: 1, UserID: 5})
	require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeAdmin}))
	err := db.Insert(t.Context(), &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeAdmin})
	require.NoError(t, err)
	_, err = db.Exec(t.Context(), "ALTER TABLE enterprise_subject_role_binding RENAME TO access_http_fault")
	require.NoError(t, err)
	defer func() {
		_, err := db.Exec(t.Context(), "ALTER TABLE access_http_fault RENAME TO enterprise_subject_role_binding")
		require.NoError(t, err)
	}()
	response := session.MakeRequest(t, request(), 503)
	require.Contains(t, response.Body.String(), "policy_read_failed")
	require.NotContains(t, response.Body.String(), "access_http_fault")
	require.NotContains(t, response.Body.String(), "enterprise_subject_role_binding")
	unittest.AssertNotExistsBean(t, &repo_model.Collaboration{RepoID: 1, UserID: 5})
}

func TestEnterpriseAuthzAccessPlatformRoleDoesNotGrantManagementAuthority(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	enableLifecycleEnforcement(t)
	key := "platform-admin"
	role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeSystem, Name: "Platform Admin", LowerName: key, BuiltinKey: &key, Revision: 1}
	require.NoError(t, db.Insert(t.Context(), role))
	_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.ManageAccess, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}, &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: 4, ScopeType: authz_model.ScopeSystem, RoleID: role.ID}))
	require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeAdmin}, &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeAdmin}))
	session := loginUser(t, "user4")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository, auth_model.AccessTokenScopeWriteOrganization, auth_model.AccessTokenScopeWriteAdmin)
	session.MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/repo1/collaborators/user5", api.AddCollaboratorOption{}).AddTokenAuth(token), 204)
	_, err = db.GetEngine(t.Context()).Where("repo_id = ? AND user_id = ?", 1, 4).Delete(&repo_model.Collaboration{})
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Where("repo_id = ? AND user_id = ?", 1, 4).Delete(&access_model.Access{})
	require.NoError(t, err)
	for _, path := range []string{"/api/v1/repos/user2/repo1/enterprise/authz/roles", "/api/v1/repos/user2/repo1/enterprise/authz/bindings", "/api/v1/enterprise/authz/roles"} {
		session.MakeRequest(t, NewRequest(t, "GET", path).AddTokenAuth(token), 403)
	}
	session.MakeRequest(t, NewRequest(t, "GET", "/-/admin/enterprise/authz/scopes/system/roles"), 403)
}

func TestEnterpriseAuthzAccessPreservesManagedTeamGuards(t *testing.T) {
	enableLifecycleEnforcement(t)
	TestAPIEnterpriseWeComManagedTeamLocalMaintenanceDenied(t)
}
