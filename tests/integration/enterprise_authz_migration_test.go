// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	admin_model "gitea.dev/models/admin"
	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitrepo"
	"gitea.dev/modules/json"
	"gitea.dev/modules/queue"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"
	"gitea.dev/services/migrations"
	repo_service "gitea.dev/services/repository"
	"gitea.dev/services/task"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzMigrationPreTargetFailures(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Other.ShowFooterTemplateLoadTime, false)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.Migrations.AllowLocalNetworks)()
	defer test.MockVariableValue(&setting.Repository.DisableMigrations)()
	defer test.MockVariableValue(&setting.Mirror.DisableNewPull)()
	t.Cleanup(func() { require.NoError(t, migrations.Init()) })
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	const action audit_model.Action = "enterprise:authz:migration:failure"
	const sensitive = "secret-token-OAuth-code"
	for _, entry := range []string{"api", "web"} {
		for _, tc := range []struct {
			name, stage, reason, outcome string
			apiStatus, webStatus         int
			owner                        int64
		}{
			{"source", "validate_source", "source_policy_denied", "denied", 422, 200, 2},
			{"invalid_source", "validate_source", "source_invalid", "failed", 422, 200, 2},
			{"disabled_site", "site_policy", "migration_disabled", "denied", 403, 403, 2},
			{"disabled_mirror", "site_policy", "mirror_creation_disabled", "denied", 403, 400, 2},
			{"conflict", "create_target", "repository_name_conflict", "denied", 409, 200, 2},
			{"quota", "create_target", "quota_exceeded", "denied", 422, 403, 2},
			{"owner", "authorize_owner", "owner_permission_denied", "denied", 403, 403, 1},
		} {
			t.Run(entry+"/"+tc.name, func(t *testing.T) {
				if tc.name == "quota" {
					owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
					_, err := db.Exec(t.Context(), "UPDATE `user` SET max_repo_creation = 0 WHERE id=2")
					require.NoError(t, err)
					defer func() {
						_, err := db.Exec(context.WithoutCancel(t.Context()), "UPDATE `user` SET max_repo_creation = ? WHERE id=2", owner.MaxRepoCreation)
						require.NoError(t, err)
					}()
				}
				setting.Migrations.AllowLocalNetworks = tc.name != "source"
				require.NoError(t, migrations.Init())
				setting.Repository.DisableMigrations = tc.name == "disabled_site"
				setting.Mirror.DisableNewPull = tc.name == "disabled_mirror"
				clone := "https://private-user:" + sensitive + "@127.0.0.1/private/repo.git?callback=private@example.com"
				if tc.name == "invalid_source" {
					clone = "https://%zz/" + sensitive
				}
				name := "pre-target-failure"
				if tc.name == "conflict" {
					name = "repo1"
				}
				reposBefore := unittest.GetCount(t, &repo_model.Repository{})
				decisionsBefore := unittest.GetCount(t, &authz_model.DecisionRecord{})
				var nativeBody string
				for _, enabled := range []bool{false, true} {
					setting.EnterpriseAuthz.Enabled = enabled
					before := unittest.GetCount(t, &audit_model.Event{Action: action})
					var body string
					if entry == "api" {
						response := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", &api.MigrateRepoOptions{CloneAddr: clone, RepoName: name, RepoOwnerID: tc.owner, Mirror: tc.name == "disabled_mirror", AuthToken: sensitive, AuthPassword: sensitive}).AddTokenAuth(token), tc.apiStatus)
						body = response.Body.String()
					} else {
						response := session.MakeRequest(t, NewRequestWithValues(t, "POST", "/repo/migrate", map[string]string{"clone_addr": clone, "repo_name": name, "uid": strconv.FormatInt(tc.owner, 10), "service": "1", "mirror": strconv.FormatBool(tc.name == "disabled_mirror"), "auth_token": sensitive, "auth_password": sensitive}), tc.webStatus)
						body = response.Body.String()
					}
					if !enabled {
						nativeBody = body
						require.Equal(t, before, unittest.GetCount(t, &audit_model.Event{Action: action}))
						continue
					}
					if entry == "api" {
						require.Equal(t, nativeBody, body)
					} else {
						require.Equal(t, shadowReadHTML(t, nativeBody), shadowReadHTML(t, body))
					}
					require.Equal(t, before+1, unittest.GetCount(t, &audit_model.Event{Action: action}))
					var records []audit_model.Event
					require.NoError(t, db.GetEngine(t.Context()).Where("action = ?", action).Desc("id").Limit(1).Find(&records))
					record := records[0]
					require.EqualValues(t, 2, record.ActorID)
					require.Equal(t, audit_model.ScopeUser, record.ScopeType)
					require.EqualValues(t, 2, record.ScopeID)
					metadata := audit_model.DecodeMetadata(record.Metadata)
					require.Equal(t, tc.stage, metadata["stage"])
					require.Equal(t, tc.reason, metadata["reason"])
					require.Equal(t, tc.outcome, metadata["native_outcome"])
					require.Equal(t, entry, metadata["request_source"])
					require.NotEmpty(t, metadata["operation_id"])
					require.NotContains(t, metadata, "repo_id")
					require.NotContains(t, metadata, "candidate_decision")
					if tc.name == "owner" {
						require.NotContains(t, metadata, "owner_id")
					}
					encoded, err := json.Marshal(record)
					require.NoError(t, err)
					for _, forbidden := range []string{sensitive, "private-user", "private@example.com", "127.0.0.1", "repo1", "pre-target-failure", "access-token:"} {
						require.NotContains(t, string(encoded), forbidden)
					}
				}
				require.Equal(t, reposBefore, unittest.GetCount(t, &repo_model.Repository{}))
				require.Equal(t, decisionsBefore, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			})
		}
	}
}

func TestEnterpriseAuthzMigrationAuditFaultPreservesResponse(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Repository.DisableMigrations, true)()
	defer test.MockVariableValue(&setting.Migrations.AllowLocalNetworks, true)()
	require.NoError(t, migrations.Init())
	t.Cleanup(func() { require.NoError(t, migrations.Init()) })
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	request := func() *RequestWrapper {
		return NewRequestWithJSON(t, http.MethodPost, "/api/v1/repos/migrate", &api.MigrateRepoOptions{CloneAddr: "http://127.0.0.1/repo.git", RepoName: "audit-fault", RepoOwnerID: 2}).AddTokenAuth(token)
	}
	baseline := MakeRequest(t, request(), http.StatusForbidden)
	_, err := db.Exec(t.Context(), "ALTER TABLE audit_event RENAME TO audit_event_migration_fault")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE audit_event_migration_fault RENAME TO audit_event")
		require.NoError(t, err)
	})
	setting.EnterpriseAuthz.Enabled = true
	response := MakeRequest(t, request(), http.StatusForbidden)
	require.Equal(t, baseline.Body.String(), response.Body.String())
	require.NotContains(t, strings.ToLower(response.Body.String()), "audit_event")
}

func TestEnterpriseAuthzMigrationTaskPreTargetFailures(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	const action audit_model.Action = "enterprise:authz:migration:failure"
	for _, failure := range []string{"create_target", "create_task"} {
		t.Run(failure, func(t *testing.T) {
			if failure == "create_task" {
				_, err := db.Exec(t.Context(), "ALTER TABLE task RENAME TO task_migration_fault")
				require.NoError(t, err)
				defer func() {
					_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE task_migration_fault RENAME TO task")
					require.NoError(t, err)
				}()
			}
			before := unittest.GetCount(t, &audit_model.Event{Action: action})
			created, err := task.CreateMigrateTask(t.Context(), actor, actor, migrations.MigrateOptions{RepoName: "repo1", CloneAddr: "https://private-user:secret-token@127.0.0.1/private/repo.git", AuthPassword: "secret-token", AuthToken: "OAuth-code"})
			require.Error(t, err)
			require.Nil(t, created)
			require.Equal(t, before+1, unittest.GetCount(t, &audit_model.Event{Action: action}))
			var events []audit_model.Event
			require.NoError(t, db.GetEngine(t.Context()).Where("action = ?", action).Desc("id").Limit(1).Find(&events))
			metadata := audit_model.DecodeMetadata(events[0].Metadata)
			stage, reason := "create_target", "repository_name_conflict"
			if failure == "create_task" {
				stage, reason = "prepare_task", "task_creation_failed"
			}
			require.Equal(t, stage, metadata["stage"])
			require.Equal(t, reason, metadata["reason"])
			require.Equal(t, "system", metadata["request_source"])
			require.Equal(t, audit_model.ScopeUser, events[0].ScopeType)
			require.EqualValues(t, 2, events[0].ScopeID)
			encoded, err := json.Marshal(events[0])
			require.NoError(t, err)
			for _, private := range []string{"private-user", "secret-token", "OAuth-code", "127.0.0.1", "repo1"} {
				require.NotContains(t, string(encoded), private)
			}
			unittest.AssertCount(t, &authz_model.DecisionRecord{}, 0)
		})
	}
	failed := unittest.AssertExistsAndLoadBean(t, &admin_model.Task{DoerID: 2, RepoID: 0, Status: api.TaskStatusFailed})
	require.Positive(t, failed.EndTime)
}

func TestEnterpriseAuthzMigrationDoesNotMisclassifyCreatedTarget(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	if setting.Database.Type.IsSQLite3() {
		_, err := db.Exec(t.Context(), `CREATE TRIGGER authz_task_update_failure BEFORE UPDATE OF repo_id ON task WHEN NEW.repo_id > 0 BEGIN SELECT RAISE(ABORT, 'task_update_failed'); END`)
		require.NoError(t, err)
		defer func() {
			_, err := db.Exec(context.WithoutCancel(t.Context()), "DROP TRIGGER authz_task_update_failure")
			require.NoError(t, err)
		}()
	} else {
		_, err := db.Exec(t.Context(), `CREATE FUNCTION authz_task_update_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.repo_id > 0 THEN RAISE EXCEPTION 'task_update_failed'; END IF; RETURN NEW; END $$`)
		require.NoError(t, err)
		_, err = db.Exec(t.Context(), `CREATE TRIGGER authz_task_update_failure BEFORE UPDATE OF repo_id ON task FOR EACH ROW EXECUTE FUNCTION authz_task_update_failure()`)
		require.NoError(t, err)
		defer func() {
			_, err := db.Exec(context.WithoutCancel(t.Context()), "DROP TRIGGER authz_task_update_failure ON task")
			require.NoError(t, err)
			_, err = db.Exec(context.WithoutCancel(t.Context()), "DROP FUNCTION authz_task_update_failure()")
			require.NoError(t, err)
		}()
	}
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	created, err := task.CreateMigrateTask(t.Context(), actor, actor, migrations.MigrateOptions{RepoName: "target-already-created", GitServiceType: api.PlainGitService})
	require.Error(t, err)
	require.Nil(t, created)
	target := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: 2, Name: "target-already-created"})
	defer func() {
		require.NoError(t, repo_service.DeleteRepositoryDirectly(context.WithoutCancel(t.Context()), target.ID))
	}()
	require.Positive(t, target.ID)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.Action("enterprise:authz:migration:failure")}, 0)
}

func TestEnterpriseAuthzMigrationAuditBudget(t *testing.T) {
	if !setting.Database.Type.IsPostgreSQL() {
		t.Skip("PostgreSQL table lock verifies the evidence deadline")
	}
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	ready, done := make(chan error, 1), make(chan error, 1)
	release := make(chan struct{})
	go func() {
		done <- db.WithIndependentTx(context.WithValue(t.Context(), db.ContextKeyTestFixtures, true), func(ctx context.Context) error {
			_, err := db.Exec(ctx, "LOCK TABLE audit_event IN ACCESS EXCLUSIVE MODE")
			ready <- err
			if err == nil {
				<-release
			}
			return err
		})
	}()
	stop := sync.OnceFunc(func() { close(release); require.NoError(t, <-done) })
	t.Cleanup(stop)
	require.NoError(t, <-ready)
	started := time.Now()
	authz_service.RecordMigrationFailure(authz_service.WithMigrationSource(t.Context(), "system"), &user_model.User{ID: 2}, 0, "create_target", "target_creation_failed")
	require.Less(t, time.Since(started), time.Second)
	stop()
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.Action("enterprise:authz:migration:failure")}, 0)
}

func TestEnterpriseAuthzMigrationResidualTargetIsNotPreTarget(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.Migrations.AllowLocalNetworks, true)()
	require.NoError(t, migrations.Init())
	t.Cleanup(func() { require.NoError(t, migrations.Init()) })
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteRepository)
	for _, entry := range []string{"task", "api"} {
		t.Run(entry, func(t *testing.T) {
			name := "residual-target-" + entry
			storageTarget := &repo_model.Repository{OwnerID: 2, OwnerName: actor.Name, Name: name}
			require.NoError(t, git.InitRepository(t.Context(), storageTarget, git.Sha1ObjectFormat.Name()))
			if setting.Database.Type.IsSQLite3() {
				_, err := db.Exec(t.Context(), `CREATE TRIGGER authz_repo_cleanup_failure BEFORE DELETE ON repository WHEN OLD.name LIKE 'residual-target-%' BEGIN SELECT RAISE(ABORT, 'cleanup_failed'); END`)
				require.NoError(t, err)
			} else {
				_, err := db.Exec(t.Context(), `CREATE FUNCTION authz_repo_cleanup_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF OLD.name LIKE 'residual-target-%' THEN RAISE EXCEPTION 'cleanup_failed'; END IF; RETURN OLD; END $$`)
				require.NoError(t, err)
				_, err = db.Exec(t.Context(), `CREATE TRIGGER authz_repo_cleanup_failure BEFORE DELETE ON repository FOR EACH ROW EXECUTE FUNCTION authz_repo_cleanup_failure()`)
				require.NoError(t, err)
			}
			defer func() {
				ctx := context.WithoutCancel(t.Context())
				if setting.Database.Type.IsSQLite3() {
					_, err := db.Exec(ctx, "DROP TRIGGER authz_repo_cleanup_failure")
					require.NoError(t, err)
				} else {
					_, err := db.Exec(ctx, "DROP TRIGGER authz_repo_cleanup_failure ON repository")
					require.NoError(t, err)
					_, err = db.Exec(ctx, "DROP FUNCTION authz_repo_cleanup_failure()")
					require.NoError(t, err)
				}
				retained, err := repo_model.GetRepositoryByName(ctx, 2, name)
				require.NoError(t, err)
				require.NoError(t, repo_service.DeleteRepositoryDirectly(ctx, retained.ID))
			}()
			if entry == "task" {
				created, err := task.CreateMigrateTask(t.Context(), actor, actor, migrations.MigrateOptions{RepoName: name, GitServiceType: api.PlainGitService})
				require.Error(t, err)
				require.Nil(t, created)
			} else {
				MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", &api.MigrateRepoOptions{CloneAddr: "http://127.0.0.1/repo.git", RepoName: name, RepoOwnerID: 2}).AddTokenAuth(token), http.StatusConflict)
			}
			retained := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: 2, Name: name})
			require.Positive(t, retained.ID)
			unittest.AssertCount(t, &audit_model.Event{Action: audit_model.Action("enterprise:authz:migration:failure")}, 0)
		})
	}
}

func TestEnterpriseAuthzMigrationExistingTarget(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.ImportLocalPaths, true)()
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	source := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	for _, enabled := range []bool{false, true} {
		for _, fail := range []bool{false, true} {
			setting.EnterpriseAuthz.Enabled = enabled
			name := fmt.Sprintf("observed-migration-%t-%t", enabled, fail)
			clone := gitrepo.RepoLocalPath(source)
			if fail {
				clone = t.TempDir()
			}
			created, err := task.CreateMigrateTask(authz_service.WithMigrationSource(t.Context(), "web"), actor, actor, migrations.MigrateOptions{CloneAddr: clone, RepoName: name, GitServiceType: api.PlainGitService})
			require.NoError(t, err)
			var before authz_model.DecisionRecord
			if enabled {
				before = *unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 1, RepoID: created.RepoID, Action: authz.Migrate, RequestSource: "web", NativeOutcome: "unknown", NativeStage: "migration"})
			} else {
				unittest.AssertCount(t, &authz_model.DecisionRecord{RepoID: created.RepoID}, 0)
			}
			persisted := unittest.AssertExistsAndLoadBean(t, &admin_model.Task{ID: created.ID})
			// 队列反序列化后不依赖请求指针、取消或业务事务。
			encoded, err := json.Marshal(persisted)
			require.NoError(t, err)
			persisted = new(admin_model.Task)
			require.NoError(t, json.Unmarshal(encoded, persisted))
			err = task.Run(t.Context(), persisted)
			outcome := "success"
			if fail {
				require.Error(t, err)
				outcome = "failed"
				unittest.AssertExistsAndLoadBean(t, &admin_model.Task{ID: created.ID, Status: api.TaskStatusFailed})
			} else {
				require.NoError(t, err)
				unittest.AssertExistsAndLoadBean(t, &admin_model.Task{ID: created.ID, Status: api.TaskStatusFinished})
				unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: created.RepoID, Status: repo_model.RepositoryReady})
			}
			if enabled {
				after := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ID: before.ID, RepoID: created.RepoID, NativeOutcome: outcome, NativeStage: "migration"})
				require.Equal(t, before.SnapshotJSON, after.SnapshotJSON)
				require.Equal(t, before.OperationID, after.OperationID)
				require.Equal(t, before.ObservationID, after.ObservationID)
				unittest.AssertCount(t, &authz_model.DecisionRecord{RepoID: created.RepoID, Action: authz.Migrate}, 1)
				unittest.AssertCount(t, &audit_model.Event{Action: audit_model.Action("enterprise:authz:migration:failure")}, 0)
			} else {
				unittest.AssertCount(t, &authz_model.DecisionRecord{RepoID: created.RepoID}, 0)
			}
			if _, err := repo_model.GetRepositoryByID(t.Context(), created.RepoID); err == nil {
				require.NoError(t, repo_service.DeleteRepositoryDirectly(t.Context(), created.RepoID))
			}
		}
	}
}

func TestEnterpriseAuthzAPIMigrationTargetOutcomes(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.ImportLocalPaths, true)()
	source := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	token := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeWriteRepository)
	for _, enabled := range []bool{false, true} {
		for _, fail := range []bool{false, true} {
			setting.EnterpriseAuthz.Enabled = enabled
			name := fmt.Sprintf("api-observed-migration-%t-%t", enabled, fail)
			clone, status, outcome := gitrepo.RepoLocalPath(source), 201, "success"
			if fail {
				clone, status, outcome = t.TempDir(), 500, "failed"
			}
			before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.Migrate})
			MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", api.MigrateRepoOptions{CloneAddr: clone, RepoName: name, RepoOwnerID: 1}).AddTokenAuth(token), status)
			if enabled {
				require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.Migrate}))
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 1, OwnerID: 1, Action: authz.Migrate, RequestSource: "api", NativeOutcome: outcome, NativeStage: "migration"}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision WHERE action = ?)", authz.Migrate))
				require.Positive(t, record.RepoID)
				require.Contains(t, record.SnapshotJSON, `"actor_id":1`)
				if fail {
					unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: record.RepoID})
				}
			} else {
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.Migrate}))
			}
			if !fail {
				repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: 1, Name: name, Status: repo_model.RepositoryReady})
				require.NoError(t, repo_service.DeleteRepositoryDirectly(t.Context(), repo.ID))
			}
		}
	}
}

func TestEnterpriseAuthzDirectMigrationCapturesOnlyRealTarget(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.ImportLocalPaths, true)()
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	source := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	for _, enabled := range []bool{false, true} {
		setting.EnterpriseAuthz.Enabled = enabled
		name := fmt.Sprintf("direct-observed-migration-%t", enabled)
		repo, err := migrations.MigrateRepository(t.Context(), actor, actor.Name, migrations.MigrateOptions{CloneAddr: gitrepo.RepoLocalPath(source), RepoName: name, GitServiceType: api.PlainGitService}, nil)
		require.NoError(t, err)
		require.NoError(t, repo_service.DeleteRepositoryDirectly(t.Context(), repo.ID))
		if enabled {
			unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 1, RepoID: repo.ID, Action: authz.Migrate, RequestSource: "system", NativeOutcome: "success", NativeStage: "migration"})
		} else {
			unittest.AssertCount(t, &authz_model.DecisionRecord{RepoID: repo.ID}, 0)
		}
		before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.Migrate})
		_, err = migrations.MigrateRepository(t.Context(), actor, actor.Name, migrations.MigrateOptions{CloneAddr: "/nonexistent/private/source", RepoName: name + "-failed", GitServiceType: api.PlainGitService}, nil)
		require.Error(t, err)
		require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.Migrate}))
	}
}

func TestEnterpriseAuthzMigrationLegacyTask(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, false)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.ImportLocalPaths, true)()
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	source := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	created, err := task.CreateMigrateTask(t.Context(), actor, actor, migrations.MigrateOptions{CloneAddr: gitrepo.RepoLocalPath(source), RepoName: "legacy-migration", GitServiceType: api.PlainGitService})
	require.NoError(t, err)
	setting.EnterpriseAuthz.Enabled = true
	loaded := unittest.AssertExistsAndLoadBean(t, &admin_model.Task{ID: created.ID})
	require.NoError(t, task.Run(t.Context(), loaded))
	unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 1, RepoID: created.RepoID, Action: authz.Migrate, RequestSource: "system", NativeOutcome: "success", NativeStage: "migration"})
	require.NoError(t, repo_service.DeleteRepositoryDirectly(t.Context(), created.RepoID))
}

func TestEnterpriseAuthzMigrationRecoversReadyTarget(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.ImportLocalPaths, true)()
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	source := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	created, err := task.CreateMigrateTask(authz_service.WithMigrationSource(t.Context(), "web"), actor, actor, migrations.MigrateOptions{CloneAddr: gitrepo.RepoLocalPath(source), RepoName: "ready-migration", GitServiceType: api.PlainGitService})
	require.NoError(t, err)
	before := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: created.RepoID, Action: authz.Migrate, NativeOutcome: "unknown"})
	opts, err := created.MigrateConfig()
	require.NoError(t, err)
	opts.MigrateToRepoID = created.RepoID
	_, err = migrations.MigrateRepository(authz_service.WithManagedMigration(t.Context()), actor, actor.Name, *opts, nil)
	require.NoError(t, err)
	loaded := unittest.AssertExistsAndLoadBean(t, &admin_model.Task{ID: created.ID})
	require.NoError(t, loaded.LoadDoer(t.Context()))
	require.NoError(t, loaded.LoadOwner(t.Context()))
	require.NoError(t, task.Run(t.Context(), loaded))
	after := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ID: before.ID, NativeOutcome: "success", NativeStage: "migration"})
	require.Equal(t, before.SnapshotJSON, after.SnapshotJSON)
	unittest.AssertCount(t, &authz_model.DecisionRecord{RepoID: created.RepoID, Action: authz.Migrate}, 1)
	require.NoError(t, repo_service.DeleteRepositoryDirectly(t.Context(), created.RepoID))
}

func TestEnterpriseAuthzMigrationRetryIsNewAttempt(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.ImportLocalPaths, true)()
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	created, err := task.CreateMigrateTask(t.Context(), actor, actor, migrations.MigrateOptions{CloneAddr: t.TempDir(), RepoName: "retry-migration", GitServiceType: api.PlainGitService})
	require.NoError(t, err)
	require.Error(t, task.Run(t.Context(), unittest.AssertExistsAndLoadBean(t, &admin_model.Task{ID: created.ID})))
	first := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: created.RepoID, Action: authz.Migrate, NativeOutcome: "failed"})
	require.NoError(t, task.RetryMigrateTask(t.Context(), created.RepoID))
	require.NoError(t, queue.GetManager().FlushAll(t.Context(), 0))
	unittest.AssertExistsAndLoadBean(t, &admin_model.Task{ID: created.ID, Status: api.TaskStatusFailed})
	unittest.AssertCount(t, &authz_model.DecisionRecord{RepoID: created.RepoID, Action: authz.Migrate}, 2)
	second := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: created.RepoID, Action: authz.Migrate, NativeOutcome: "failed"}, unittest.Cond("id <> ?", first.ID))
	require.NotEqual(t, first.OperationID, second.OperationID)
	require.NotEqual(t, first.ObservationID, second.ObservationID)
	require.NoError(t, repo_service.DeleteRepositoryDirectly(t.Context(), created.RepoID))
}

func TestEnterpriseAuthzMigrationFinalTaskFailureIsNotSuccess(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.ImportLocalPaths, true)()
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	source := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	created, err := task.CreateMigrateTask(t.Context(), actor, actor, migrations.MigrateOptions{CloneAddr: gitrepo.RepoLocalPath(source), RepoName: "finish-failure-migration", GitServiceType: api.PlainGitService})
	require.NoError(t, err)
	before := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: created.RepoID, Action: authz.Migrate, NativeOutcome: "unknown"})
	if setting.Database.Type.IsSQLite3() {
		_, err = db.Exec(t.Context(), fmt.Sprintf("CREATE TRIGGER authz_migration_finish_failure BEFORE UPDATE ON task WHEN NEW.id = %d AND NEW.status = %d BEGIN SELECT RAISE(ABORT,'finish_task_failed'); END", created.ID, api.TaskStatusFinished))
		require.NoError(t, err)
	} else {
		_, err = db.Exec(t.Context(), fmt.Sprintf("CREATE FUNCTION authz_migration_finish_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.id = %d AND NEW.status = %d THEN RAISE EXCEPTION 'finish_task_failed'; END IF; RETURN NEW; END $$", created.ID, api.TaskStatusFinished))
		require.NoError(t, err)
		_, err = db.Exec(t.Context(), "CREATE TRIGGER authz_migration_finish_failure BEFORE UPDATE ON task FOR EACH ROW EXECUTE FUNCTION authz_migration_finish_failure()")
		require.NoError(t, err)
	}
	defer func() {
		ctx := context.WithoutCancel(t.Context())
		if setting.Database.Type.IsSQLite3() {
			_, err = db.Exec(ctx, "DROP TRIGGER authz_migration_finish_failure")
		} else {
			_, err = db.Exec(ctx, "DROP TRIGGER authz_migration_finish_failure ON task")
			require.NoError(t, err)
			_, err = db.Exec(ctx, "DROP FUNCTION authz_migration_finish_failure()")
		}
		require.NoError(t, err)
	}()
	require.Error(t, task.Run(t.Context(), unittest.AssertExistsAndLoadBean(t, &admin_model.Task{ID: created.ID})))
	unittest.AssertExistsAndLoadBean(t, &admin_model.Task{ID: created.ID, Status: api.TaskStatusFailed})
	unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: created.RepoID, Status: repo_model.RepositoryReady})
	after := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ID: before.ID, NativeOutcome: "failed", NativeStage: "migration"})
	require.Equal(t, before.SnapshotJSON, after.SnapshotJSON)
	require.NoError(t, repo_service.DeleteRepositoryDirectly(t.Context(), created.RepoID))
}

func TestEnterpriseAuthzMigrationEvidenceFaultsPreserveNativeResult(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.ImportLocalPaths, true)()
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	source := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	token := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeWriteRepository)
	for _, table := range []string{"enterprise_subject_role_binding", "enterprise_authz_decision", "audit_event"} {
		for _, entry := range []string{"api", "task"} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/%t", table, entry, enabled), func(t *testing.T) {
					setting.EnterpriseAuthz.Enabled = enabled
					name := fmt.Sprintf("migration-fault-%d", unittest.GetCount(t, &repo_model.Repository{}))
					before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.Migrate})
					func() {
						_, err := db.Exec(t.Context(), "ALTER TABLE "+table+" RENAME TO authz_migration_evidence_fault")
						require.NoError(t, err)
						defer func() {
							_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE authz_migration_evidence_fault RENAME TO "+table)
							require.NoError(t, err)
						}()
						opts := migrations.MigrateOptions{CloneAddr: gitrepo.RepoLocalPath(source), RepoName: name, GitServiceType: api.PlainGitService}
						if entry == "api" {
							MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/migrate", api.MigrateRepoOptions{CloneAddr: opts.CloneAddr, RepoName: name, RepoOwnerID: 1}).AddTokenAuth(token), 201)
						} else {
							created, err := task.CreateMigrateTask(authz_service.WithMigrationSource(t.Context(), "web"), actor, actor, opts)
							require.NoError(t, err)
							require.NoError(t, task.Run(t.Context(), unittest.AssertExistsAndLoadBean(t, &admin_model.Task{ID: created.ID})))
							unittest.AssertExistsAndLoadBean(t, &admin_model.Task{ID: created.ID, Status: api.TaskStatusFinished})
						}
					}()
					repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{OwnerID: 1, Name: name, Status: repo_model.RepositoryReady})
					if enabled && table == "enterprise_subject_role_binding" {
						require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.Migrate}))
						unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repo.ID, Action: authz.Migrate, CandidateDecision: "error", NativeOutcome: "success"})
					} else {
						require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.Migrate}))
					}
					require.NoError(t, repo_service.DeleteRepositoryDirectly(t.Context(), repo.ID))
				})
			}
		}
	}
}

func TestEnterpriseAuthzExistingMigrationSourcePolicyDenial(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.Migrations.AllowLocalNetworks, false)()
	require.NoError(t, migrations.Init())
	t.Cleanup(func() { require.NoError(t, migrations.Init()) })
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	for _, entry := range []string{"direct", "task"} {
		created, err := task.CreateMigrateTask(t.Context(), actor, actor, migrations.MigrateOptions{CloneAddr: "http://127.0.0.1/private-source", RepoName: "source-denial-" + entry, GitServiceType: api.PlainGitService})
		require.NoError(t, err)
		if entry == "task" {
			require.Error(t, task.Run(t.Context(), unittest.AssertExistsAndLoadBean(t, &admin_model.Task{ID: created.ID})))
		} else {
			opts, err := created.MigrateConfig()
			require.NoError(t, err)
			opts.MigrateToRepoID = created.RepoID
			_, err = migrations.MigrateRepository(t.Context(), actor, actor.Name, *opts, nil)
			require.Error(t, err)
		}
		unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: created.RepoID, Action: authz.Migrate, NativeOutcome: "denied", NativeStage: "migration"})
		unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: created.RepoID, OwnerID: 2, Status: repo_model.RepositoryBeingMigrated})
		require.NoError(t, repo_service.DeleteRepositoryDirectly(t.Context(), created.RepoID))
	}
}
