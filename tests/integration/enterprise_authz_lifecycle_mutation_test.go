// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	repo_service "gitea.dev/services/repository"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzLifecycleMutations(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	ownerSession, adminSession := loginUser(t, "user2"), loginUser(t, "user1")
	ownerToken := getTokenForLoggedInUser(t, ownerSession, auth_model.AccessTokenScopeWriteRepository)
	adminToken := getTokenForLoggedInUser(t, adminSession, auth_model.AccessTokenScopeWriteRepository)
	for _, enabled := range []bool{false, true} {
		setting.EnterpriseAuthz.Enabled = false
		repo, err := repo_service.CreateRepository(t.Context(), owner, owner, repo_service.CreateRepoOptions{Name: fmt.Sprintf("shadow-life-%t", enabled)})
		require.NoError(t, err)
		setting.EnterpriseAuthz.Enabled = enabled
		check := func(action authz.Action, actor, oldOwner int64, source string, mutate func()) *authz_model.DecisionRecord {
			t.Helper()
			before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: action, RepoID: repo.ID})
			mutate()
			if !enabled {
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: action, RepoID: repo.ID}))
				return nil
			}
			require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{Action: action, RepoID: repo.ID}))
			return unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: actor, RepoID: repo.ID, OwnerID: oldOwner, Action: action, RequestSource: source, NativeOutcome: "success"}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision WHERE action = ?)", action))
		}
		archive := check(authz.Archive, 2, 2, "web", func() {
			ownerSession.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/"+repo.Name+"/settings", map[string]string{"action": "archive"}), 303)
		})
		if enabled {
			require.Contains(t, archive.SnapshotJSON, `"archived":false`)
		}
		archived := false
		check(authz.Archive, 2, 2, "api", func() {
			ownerSession.MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/"+repo.Name, api.EditRepoOption{Archived: &archived}).AddTokenAuth(ownerToken), 200)
		})
		transferred := check(authz.Transfer, 1, 2, "api", func() {
			adminSession.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/"+repo.Name+"/transfer", api.TransferRepoOption{NewOwner: "org3"}).AddTokenAuth(adminToken), 202)
		})
		if enabled {
			require.Contains(t, transferred.SnapshotJSON, `"target_owner_id":3`)
		}
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID, OwnerID: 3})
		check(authz.Delete, 1, 3, "api", func() {
			adminSession.MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/org3/"+repo.Name).AddTokenAuth(adminToken), 204)
		})
		unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: repo.ID})
	}
}

func TestEnterpriseAuthzPendingTransferDoesNotPretendCompletion(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, false)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	ownerSession, recipientSession := loginUser(t, "user2"), loginUser(t, "user4")
	ownerToken := getTokenForLoggedInUser(t, ownerSession, auth_model.AccessTokenScopeWriteRepository)
	recipientToken := getTokenForLoggedInUser(t, recipientSession, auth_model.AccessTokenScopeWriteRepository)
	for _, enabled := range []bool{false, true} {
		repo, err := repo_service.CreateRepository(t.Context(), owner, owner, repo_service.CreateRepoOptions{Name: fmt.Sprintf("shadow-pending-%t", enabled)})
		require.NoError(t, err)
		setting.EnterpriseAuthz.Enabled = enabled
		ownerSession.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/"+repo.Name+"/transfer", api.TransferRepoOption{NewOwner: "user4"}).AddTokenAuth(ownerToken), 201)
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID, OwnerID: 2, Status: repo_model.RepositoryPendingTransfer})
		if enabled {
			unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: repo.ID, Action: authz.Transfer, NativeOutcome: "unknown", RequestSource: "api"})
		}
		recipientSession.MakeRequest(t, NewRequest(t, "POST", "/api/v1/repos/user2/"+repo.Name+"/transfer/accept").AddTokenAuth(recipientToken), 202)
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID, OwnerID: 4, Status: repo_model.RepositoryReady})
		if enabled {
			record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: repo.ID, OwnerID: 2, Action: authz.Transfer, NativeOutcome: "success", RequestSource: "api"})
			require.Equal(t, "deny", record.CandidateDecision)
			require.Contains(t, record.SnapshotJSON, `"target_owner_id":4`)
		} else {
			require.Zero(t, unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: repo.ID, Action: authz.Transfer}))
		}
		require.NoError(t, repo_service.DeleteRepositoryDirectly(t.Context(), repo.ID))
		setting.EnterpriseAuthz.Enabled = false
	}
}

func TestEnterpriseAuthzLifecycleAPIGuards(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	for _, tc := range []struct {
		user, method, url, outcome string
		action                     authz.Action
		status                     int
		body                       any
	}{
		{"user4", "DELETE", "/api/v1/repos/user2/repo1", "denied", authz.Delete, 403, nil},
		{"user4", "POST", "/api/v1/repos/user2/repo1/transfer", "denied", authz.Transfer, 403, api.TransferRepoOption{NewOwner: "user4"}},
		{"user2", "POST", "/api/v1/repos/user2/repo1/transfer", "failed", authz.Transfer, 404, api.TransferRepoOption{NewOwner: "missing-target-owner"}},
		{"user2", "POST", "/api/v1/repos/user2/repo1/transfer", "denied", authz.Transfer, 403, api.TransferRepoOption{NewOwner: "org3", TeamIDs: &[]int64{5}}},
	} {
		setting.EnterpriseAuthz.Enabled = false
		session := loginUser(t, tc.user)
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		request := func() *RequestWrapper { return NewRequestWithJSON(t, tc.method, tc.url, tc.body).AddTokenAuth(token) }
		baseline := session.MakeRequest(t, request(), tc.status)
		setting.EnterpriseAuthz.Enabled = true
		before := unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1, Action: tc.action})
		response := session.MakeRequest(t, request(), tc.status)
		require.JSONEq(t, baseline.Body.String(), response.Body.String())
		require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1, Action: tc.action}))
		unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, Action: tc.action, NativeOutcome: tc.outcome}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1, OwnerID: 2})
	}
}

func TestEnterpriseAuthzLifecycleEvidenceFaultsPreserveMutations(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, false)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	ownerSession, adminSession := loginUser(t, "user2"), loginUser(t, "user1")
	ownerToken := getTokenForLoggedInUser(t, ownerSession, auth_model.AccessTokenScopeWriteRepository)
	adminToken := getTokenForLoggedInUser(t, adminSession, auth_model.AccessTokenScopeWriteRepository)
	role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeSystem, Name: "Lifecycle fault", LowerName: "lifecycle fault", Revision: 1, CreatedBy: 1}
	require.NoError(t, db.Insert(t.Context(), role))
	for _, table := range []string{"enterprise_role_permission", "enterprise_authz_decision", "audit_event"} {
		for _, action := range []authz.Action{authz.Archive, authz.Transfer, authz.Delete} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%t", table, action, enabled), func(t *testing.T) {
					setting.EnterpriseAuthz.Enabled = false
					repo, err := repo_service.CreateRepository(t.Context(), owner, owner, repo_service.CreateRepoOptions{Name: fmt.Sprintf("shadow-life-fault-%d", unittest.GetCount(t, &repo_model.Repository{}))})
					require.NoError(t, err)
					for _, actor := range []int64{1, 2} {
						require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: actor, ScopeType: authz_model.ScopeRepo, ScopeID: repo.ID, ScopeOwnerID: 2, RoleID: role.ID}))
					}
					setting.EnterpriseAuthz.Enabled = enabled
					func() {
						_, err := db.Exec(t.Context(), "ALTER TABLE "+table+" RENAME TO authz_lifecycle_fault")
						require.NoError(t, err)
						defer func() {
							_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE authz_lifecycle_fault RENAME TO "+table)
							require.NoError(t, err)
						}()
						switch action {
						case authz.Archive:
							archived := true
							ownerSession.MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/"+repo.Name, api.EditRepoOption{Archived: &archived}).AddTokenAuth(ownerToken), 200)
							unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID, IsArchived: true})
						case authz.Transfer:
							adminSession.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/"+repo.Name+"/transfer", api.TransferRepoOption{NewOwner: "org3"}).AddTokenAuth(adminToken), 202)
							unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID, OwnerID: 3})
						case authz.Delete:
							adminSession.MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/"+repo.Name).AddTokenAuth(adminToken), 204)
							unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: repo.ID})
						}
					}()
					if enabled && table == "enterprise_role_permission" {
						unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repo.ID, Action: action, CandidateDecision: "error", NativeOutcome: "success"})
					} else {
						require.Zero(t, unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: repo.ID, Action: action}))
					}
					if action != authz.Delete {
						require.NoError(t, repo_service.DeleteRepositoryDirectly(t.Context(), repo.ID))
					}
				})
			}
		}
	}
}

func TestEnterpriseAuthzLifecycleWebGuards(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		reader := loginUser(t, "user4")
		for _, action := range []string{"archive", "unarchive", "transfer", "delete", "advanced"} {
			before := unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1})
			for _, enabled := range []bool{false, true} {
				setting.EnterpriseAuthz.Enabled = enabled
				req := NewRequestWithValues(t, "POST", u.String()+"user2/repo1/settings", map[string]string{"action": action, "new_owner_name": "user4", "repo_name": "repo1"})
				req.RequestURI = ""
				baseURL, err := url.Parse(setting.AppURL)
				require.NoError(t, err)
				for _, cookie := range reader.jar.Cookies(baseURL) {
					req.AddCookie(cookie)
				}
				response, err := (&http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req.Request)
				require.NoError(t, err)
				require.Equal(t, 404, response.StatusCode)
				_, err = io.Copy(io.Discard, response.Body)
				require.NoError(t, err)
				require.NoError(t, response.Body.Close())
				if enabled && action != "advanced" {
					key := map[string]authz.Action{"archive": authz.Archive, "unarchive": authz.Archive, "transfer": authz.Transfer, "delete": authz.Delete}[action]
					require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1}))
					unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, ActorID: 4, Action: key, NativeOutcome: "denied", NativeStage: "authorization", RequestSource: "web"}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
				} else {
					require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1}))
				}
			}
		}
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1, OwnerID: 2, IsArchived: false})
	})
}

func TestEnterpriseAuthzLifecycleAPIArchiveGuard(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		token := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth_model.AccessTokenScopeWriteRepository)
		for _, body := range []map[string]any{{"archived": true}, {"has_actions": true}, {"archived": true, "has_actions": false}, {"description": "not an archive operation"}} {
			before := unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1})
			var actions []authz.Action
			if body["archived"] != nil {
				actions = append(actions, authz.Archive)
			}
			if body["has_actions"] != nil {
				actions = append(actions, authz.ManageCI)
			}
			for _, enabled := range []bool{false, true} {
				setting.EnterpriseAuthz.Enabled = enabled
				req := NewRequestWithJSON(t, "PATCH", u.String()+"api/v1/repos/user2/repo1", body).AddTokenAuth(token)
				req.RequestURI = ""
				response, err := http.DefaultClient.Do(req.Request)
				require.NoError(t, err)
				require.Equal(t, 403, response.StatusCode)
				_, err = io.Copy(io.Discard, response.Body)
				require.NoError(t, err)
				require.NoError(t, response.Body.Close())
				if enabled {
					require.Equal(t, before+len(actions), unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1}))
					for _, action := range actions {
						unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, ActorID: 4, Action: action, NativeOutcome: "denied", NativeStage: "authorization", RequestSource: "api"})
					}
				} else {
					require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1}))
				}
			}
		}
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1, OwnerID: 2, IsArchived: false})
	})
}

func TestEnterpriseAuthzLifecycleWebValidation(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	owner := loginUser(t, "user2")
	for _, tc := range []struct {
		action, repoName, newOwner string
		key                        authz.Action
	}{
		{"delete", "wrong-private-repository-name", "", authz.Delete},
		{"transfer", "wrong-private-repository-name", "user4", authz.Transfer},
		{"transfer", "user2/repo1", "missing-target-owner", authz.Transfer},
	} {
		before := unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1, Action: tc.key})
		for _, enabled := range []bool{false, true} {
			setting.EnterpriseAuthz.Enabled = enabled
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings", map[string]string{"action": tc.action, "repo_name": tc.repoName, "new_owner_name": tc.newOwner}), 400)
			if enabled {
				require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1, Action: tc.key}))
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, ActorID: 2, Action: tc.key, NativeOutcome: "failed", RequestSource: "web"}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
				require.NotContains(t, record.SnapshotJSON, "wrong-private-repository-name")
				require.NotContains(t, record.SnapshotJSON, "missing-target-owner")
			} else {
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1, Action: tc.key}))
			}
		}
	}
	unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1, OwnerID: 2})
}

func TestEnterpriseAuthzArchiveMirrorGuard(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	owner := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository)
	_, err := db.Exec(t.Context(), "UPDATE repository SET is_mirror = true WHERE id=1")
	require.NoError(t, err)
	defer func() {
		_, err := db.Exec(context.WithoutCancel(t.Context()), "UPDATE repository SET is_mirror = false WHERE id=1")
		require.NoError(t, err)
	}()
	for _, source := range []string{"api", "web"} {
		before := unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.Archive})
		for _, enabled := range []bool{false, true} {
			setting.EnterpriseAuthz.Enabled = enabled
			if source == "api" {
				archive := true
				owner.MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", api.EditRepoOption{Archived: &archive}).AddTokenAuth(token), 422)
			} else {
				owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings", map[string]string{"action": "archive"}), 303)
			}
			if enabled {
				require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.Archive}))
				unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, ActorID: 2, Action: authz.Archive, NativeOutcome: "denied", RequestSource: source})
			} else {
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.Archive}))
			}
		}
	}
	unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1, IsArchived: false, IsMirror: true})
}

func TestEnterpriseAuthzLifecycleNativeRollbackKeepsEvidence(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, false)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	ownerToken := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteRepository)
	adminToken := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeWriteRepository)
	for _, action := range []authz.Action{authz.Archive, authz.Transfer, authz.Delete} {
		for _, enabled := range []bool{false, true} {
			setting.EnterpriseAuthz.Enabled = false
			repo, err := repo_service.CreateRepository(t.Context(), owner, owner, repo_service.CreateRepoOptions{Name: fmt.Sprintf("native-life-failure-%s-%t", action, enabled)})
			require.NoError(t, err)
			setting.EnterpriseAuthz.Enabled = enabled
			event := "UPDATE"
			if action == authz.Delete {
				event = "DELETE"
			}
			if setting.Database.Type.IsSQLite3() {
				_, err = db.Exec(t.Context(), fmt.Sprintf("CREATE TRIGGER authz_lifecycle_native_failure BEFORE %s ON repository WHEN OLD.id = %d BEGIN SELECT RAISE(ABORT,'native_mutation_failed'); END", event, repo.ID))
				require.NoError(t, err)
			} else {
				_, err = db.Exec(t.Context(), fmt.Sprintf("CREATE FUNCTION authz_lifecycle_native_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.id = %d THEN RAISE EXCEPTION 'native_mutation_failed'; END IF; IF TG_OP = 'DELETE' THEN RETURN OLD; END IF; RETURN NEW; END $$", repo.ID))
				require.NoError(t, err)
				_, err = db.Exec(t.Context(), fmt.Sprintf("CREATE TRIGGER authz_lifecycle_native_failure BEFORE %s ON repository FOR EACH ROW EXECUTE FUNCTION authz_lifecycle_native_failure()", event))
				require.NoError(t, err)
			}
			func() {
				defer func() {
					if setting.Database.Type.IsSQLite3() {
						_, err = db.Exec(context.WithoutCancel(t.Context()), "DROP TRIGGER authz_lifecycle_native_failure")
					} else {
						_, err = db.Exec(context.WithoutCancel(t.Context()), "DROP TRIGGER authz_lifecycle_native_failure ON repository")
						require.NoError(t, err)
						_, err = db.Exec(context.WithoutCancel(t.Context()), "DROP FUNCTION authz_lifecycle_native_failure()")
					}
					require.NoError(t, err)
				}()
				switch action {
				case authz.Archive:
					archived := true
					MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/"+repo.Name, api.EditRepoOption{Archived: &archived}).AddTokenAuth(ownerToken), 500)
				case authz.Transfer:
					MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/"+repo.Name+"/transfer", api.TransferRepoOption{NewOwner: "org3"}).AddTokenAuth(adminToken), 500)
				case authz.Delete:
					MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/"+repo.Name).AddTokenAuth(adminToken), 500)
				}
			}()
			unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID, OwnerID: 2, IsArchived: false})
			if enabled {
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repo.ID, OwnerID: 2, Action: action, NativeOutcome: "failed", RequestSource: "api"})
				require.Contains(t, record.SnapshotJSON, `"owner_id":2`)
				require.Contains(t, record.SnapshotJSON, `"archived":false`)
			} else {
				unittest.AssertCount(t, &authz_model.DecisionRecord{RepoID: repo.ID}, 0)
			}
			require.NoError(t, repo_service.DeleteRepositoryDirectly(t.Context(), repo.ID))
		}
	}
}

func TestEnterpriseAuthzLifecycleWebTransferDelete(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, false)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	admin := loginUser(t, "user1")
	for _, enabled := range []bool{false, true} {
		setting.EnterpriseAuthz.Enabled = false
		repo, err := repo_service.CreateRepository(t.Context(), owner, owner, repo_service.CreateRepoOptions{Name: fmt.Sprintf("web-life-%t", enabled)})
		require.NoError(t, err)
		setting.EnterpriseAuthz.Enabled = enabled
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/"+repo.Name+"/settings", map[string]string{"action": "transfer", "repo_name": "user2/" + repo.Name, "new_owner_name": "org3"}), 200)
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID, OwnerID: 3})
		if enabled {
			record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repo.ID, ActorID: 1, OwnerID: 2, Action: authz.Transfer, NativeOutcome: "success", RequestSource: "web"})
			require.Contains(t, record.SnapshotJSON, `"target_owner_id":3`)
			unittest.AssertCount(t, &authz_model.DecisionRecord{RepoID: repo.ID, Action: authz.Transfer}, 1)
		}
		admin.MakeRequest(t, NewRequestWithValues(t, "POST", "/org3/"+repo.Name+"/settings", map[string]string{"action": "delete", "repo_name": "org3/" + repo.Name}), 200)
		unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: repo.ID})
		if enabled {
			unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repo.ID, ActorID: 1, OwnerID: 3, Action: authz.Delete, NativeOutcome: "success", RequestSource: "web"})
			unittest.AssertCount(t, &authz_model.DecisionRecord{RepoID: repo.ID, Action: authz.Delete}, 1)
		} else {
			unittest.AssertCount(t, &authz_model.DecisionRecord{RepoID: repo.ID}, 0)
		}
	}
}
