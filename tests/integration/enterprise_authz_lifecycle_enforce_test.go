// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"os"
	"testing"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git/gitrepo"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	repo_service "gitea.dev/services/repository"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func enableLifecycleEnforcement(t *testing.T) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
}

func lifecycleRole(t *testing.T, repo *repo_model.Repository, actorID int64, action authz.Action) *authz_model.SubjectRoleBinding {
	t.Helper()
	role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: repo.ID, Name: "lifecycle", LowerName: "lifecycle", Revision: 1, CreatedBy: repo.OwnerID}
	require.NoError(t, db.Insert(t.Context(), role))
	_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: action, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
	binding := &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: actorID, ScopeType: authz_model.ScopeRepo, ScopeID: repo.ID, ScopeOwnerID: repo.OwnerID, RoleID: role.ID}
	require.NoError(t, db.Insert(t.Context(), binding))
	return binding
}

func TestEnterpriseAuthzLifecycleEnforceDangerZone(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	enableLifecycleEnforcement(t)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: repo.ID, UserID: 4, Mode: perm.AccessModeAdmin}, &access_model.Access{RepoID: repo.ID, UserID: 4, Mode: perm.AccessModeAdmin}))
	prefix := "/api/v1/repos/user2/" + repo.Name
	webPrefix := "/user2/" + repo.Name + "/settings"
	session := loginUser(t, "user4")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	archived := true
	session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", prefix, api.EditRepoOption{Archived: &archived}).AddTokenAuth(token), 403)
	session.MakeRequest(t, NewRequest(t, "DELETE", prefix).AddTokenAuth(token), 403)
	session.MakeRequest(t, NewRequestWithJSON(t, "POST", prefix+"/transfer", api.TransferRepoOption{NewOwner: "user4"}).AddTokenAuth(token), 403)
	_, err := os.Stat(gitrepo.RepoLocalPath(repo))
	require.NoError(t, err)
	unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID, OwnerID: 2, IsArchived: false})
	lifecycleRole(t, repo, 4, authz.Archive)
	session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", prefix, api.EditRepoOption{Archived: &archived}).AddTokenAuth(token), 200)
	archived = false
	session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", prefix, api.EditRepoOption{Archived: &archived}).AddTokenAuth(token), 200)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", webPrefix, map[string]string{"action": "archive"}), 404)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", webPrefix, map[string]string{"action": "unarchive"}), 404)
}

func TestEnterpriseAuthzLifecycleEnforcePendingTransfer(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	enableLifecycleEnforcement(t)
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	for _, operation := range []string{"accept", "reject", "cancel"} {
		t.Run(operation, func(t *testing.T) {
			setting.EnterpriseAuthz.Enabled = false
			repo, err := repo_service.CreateRepository(t.Context(), owner, owner, repo_service.CreateRepoOptions{Name: "enforce-pending-" + operation})
			require.NoError(t, err)
			setting.EnterpriseAuthz.Enabled = true
			ownerSession, recipientSession := loginUser(t, "user2"), loginUser(t, "user4")
			ownerToken := getTokenForLoggedInUser(t, ownerSession, auth_model.AccessTokenScopeWriteRepository)
			recipientToken := getTokenForLoggedInUser(t, recipientSession, auth_model.AccessTokenScopeWriteRepository)
			ownerSession.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/"+repo.Name+"/transfer", api.TransferRepoOption{NewOwner: "user4"}).AddTokenAuth(ownerToken), 201)
			unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repo.ID, ActorID: 2, Action: authz.Transfer, NativeOutcome: "unknown", ExecutionStarted: true})
			if operation == "cancel" {
				ownerSession.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/"+repo.Name+"/settings", map[string]string{"action": "cancel_transfer"}), 303)
				return
			}
			endpoint := fmt.Sprintf("/api/v1/repos/user2/%s/transfer/%s", repo.Name, operation)
			recipientSession.MakeRequest(t, NewRequest(t, "POST", endpoint).AddTokenAuth(recipientToken), 403)
			unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID, OwnerID: 2, Status: repo_model.RepositoryPendingTransfer})
			binding := lifecycleRole(t, repo, 4, authz.Transfer)
			_, err = db.DeleteByID[authz_model.SubjectRoleBinding](t.Context(), binding.ID)
			require.NoError(t, err)
			recipientSession.MakeRequest(t, NewRequest(t, "POST", endpoint).AddTokenAuth(recipientToken), 403)
			require.NoError(t, db.Insert(t.Context(), binding))
			status := 200
			if operation == "accept" {
				status = 202
			}
			recipientSession.MakeRequest(t, NewRequest(t, "POST", endpoint).AddTokenAuth(recipientToken), status)
			expectedOwner := int64(2)
			if operation == "accept" {
				expectedOwner = 4
			}
			unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID, OwnerID: expectedOwner, Status: repo_model.RepositoryReady})
			unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repo.ID, ActorID: 4, OwnerID: 2, Action: authz.Transfer, NativeOutcome: "success", ExecutionStarted: true})
		})
	}
}

func TestEnterpriseAuthzLifecycleEnforceEvidenceAndDelete(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	enableLifecycleEnforcement(t)
	lifecycleRole(t, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}), 2, authz.Archive)
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	for _, table := range []string{"enterprise_role_permission", "enterprise_authz_decision", "audit_event"} {
		t.Run(table, func(t *testing.T) {
			archived := true
			_, err := db.Exec(t.Context(), "ALTER TABLE "+table+" RENAME TO lifecycle_evidence_fault")
			require.NoError(t, err)
			defer func() {
				_, err := db.Exec(t.Context(), "ALTER TABLE lifecycle_evidence_fault RENAME TO "+table)
				require.NoError(t, err)
			}()
			session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", api.EditRepoOption{Archived: &archived}).AddTokenAuth(token), 503)
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
			require.False(t, repo.IsArchived)
		})
	}
	setting.EnterpriseAuthz.Enabled = false
	repo, err := repo_service.CreateRepository(t.Context(), owner, owner, repo_service.CreateRepoOptions{Name: "enforce-delete-history"})
	require.NoError(t, err)
	setting.EnterpriseAuthz.Enabled = true
	binding := lifecycleRole(t, repo, 4, authz.Delete)
	session.MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/"+repo.Name).AddTokenAuth(token), 204)
	unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: repo.ID})
	unittest.AssertNotExistsBean(t, &authz_model.SubjectRoleBinding{ID: binding.ID})
	unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repo.ID, ActorID: 2, Action: authz.Delete, AuthorizationDecision: "allow", NativeOutcome: "success", ExecutionStarted: true})
	_, err = os.Stat(gitrepo.RepoLocalPath(repo))
	require.True(t, os.IsNotExist(err))
}
