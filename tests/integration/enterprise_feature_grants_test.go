// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"
	pull_service "gitea.dev/services/pull"
	repo_service "gitea.dev/services/repository"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func featureTestMode(t *testing.T) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true, FailClosedOnError: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
}

func TestEnterpriseFeatureGrantAPI(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	ownerSession := loginUser(t, "user2")
	adminToken := getTokenForLoggedInUser(t, loginUser(t, "user1"), auth_model.AccessTokenScopeWriteAdmin)
	ownerToken := getTokenForLoggedInUser(t, ownerSession, auth_model.AccessTokenScopeWriteRepository)
	readToken := getTokenForLoggedInUser(t, ownerSession, auth_model.AccessTokenScopeReadRepository)
	readerToken := getTokenForLoggedInUser(t, loginUser(t, "user4"), auth_model.AccessTokenScopeWriteRepository)
	root := "/api/v1/enterprise/authz/features"
	repo := "/api/v1/repos/user2/repo1/enterprise/authz/features"
	global := root + "/feature.wiki/grants/global"
	var catalog api.EnterpriseFeatureCatalog
	DecodeJSON(t, MakeRequest(t, NewRequest(t, "GET", root).AddTokenAuth(adminToken), http.StatusOK), &catalog)
	require.Len(t, catalog.Features, 13)
	put := func(path, token, state string, revision int64, status int) *api.EnterpriseFeaturePolicy {
		resp := MakeRequest(t, NewRequestWithJSON(t, "PUT", path, map[string]any{"state": state, "config": map[string]any{}, "expected_revision": revision}).AddTokenAuth(token), status)
		if status != http.StatusOK {
			return nil
		}
		policy := new(api.EnterpriseFeaturePolicy)
		DecodeJSON(t, resp, policy)
		return policy
	}
	put(global, adminToken, "required", 0, http.StatusOK)
	put(repo+"/feature.wiki", ownerToken, "disabled", 0, http.StatusConflict)
	put(repo+"/feature.wiki", readerToken, "enabled", 0, http.StatusForbidden)
	put(repo+"/feature.wiki", readToken, "enabled", 0, http.StatusForbidden)
	put(global, ownerToken, "enabled", 1, http.StatusForbidden)
	raw := MakeRequest(t, NewRequest(t, "GET", repo+"/feature.wiki/grant").AddTokenAuth(ownerToken), http.StatusOK)
	var policy api.EnterpriseFeaturePolicy
	DecodeJSON(t, raw, &policy)
	require.EqualValues(t, 0, policy.Grant.Revision)
	require.Equal(t, "required", policy.Effective.State)
	reader := MakeRequest(t, NewRequest(t, "GET", repo+"/feature.wiki").AddTokenAuth(readerToken), http.StatusOK)
	require.NotContains(t, reader.Body.String(), "created_by")
	require.NotContains(t, reader.Body.String(), `"chain"`)
	MakeRequest(t, NewRequest(t, "GET", repo+"/feature.wiki/grant").AddTokenAuth(readerToken), http.StatusForbidden)
	MakeRequest(t, NewRequest(t, "GET", repo+"/feature.wiki"), http.StatusUnauthorized)
	MakeRequest(t, NewRequest(t, "GET", repo+"/feature.typo").AddTokenAuth(ownerToken), http.StatusNotFound)
	put(repo+"/feature.typo", ownerToken, "enabled", 0, http.StatusUnprocessableEntity)
	MakeRequest(t, NewRequest(t, "DELETE", repo+"/feature.typo?expected_revision=0").AddTokenAuth(ownerToken), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "DELETE", global+"?expected_revision=1").AddTokenAuth(adminToken), http.StatusNoContent)
	policyPtr := put(global, adminToken, "enabled", 2, http.StatusOK)
	require.EqualValues(t, 3, policyPtr.Grant.Revision)
	put(global, adminToken, "enabled", 0, http.StatusConflict)
	put(global, adminToken, "enabled", 3, http.StatusOK)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseFeatureGrantUpdate}, 2)
	orgToken := getTokenForLoggedInUser(t, ownerSession, auth_model.AccessTokenScopeWriteOrganization)
	orgPath := "/api/v1/orgs/org3/enterprise/authz/features/feature.gitleaks_scan"
	put(orgPath, orgToken, "required", 0, http.StatusOK)
	MakeRequest(t, NewRequest(t, "GET", "/api/v1/orgs/org3/enterprise/authz/features").AddTokenAuth(orgToken), http.StatusOK)
	setting.EnterpriseAuthz.Enabled = false
	MakeRequest(t, NewRequest(t, "GET", repo+"/feature.wiki").AddTokenAuth(ownerToken), http.StatusNotFound)
	MakeRequest(t, NewRequest(t, "GET", root).AddTokenAuth(adminToken), http.StatusNotFound)
}

func TestEnterpriseFeatureCompoundUnitIntent(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	setting.EnterpriseAuthz.Enforce = true
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	_, err := authz_service.PutFeatureGrant(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeSystem}, authz.FeatureIssues, authz_service.FeatureGrantInput{State: authz.FeatureRequired, Config: []byte(`{}`)})
	require.NoError(t, err)
	before := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteRepository)
	off := false
	description := "must-not-be-partially-saved"
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", api.EditRepoOption{HasIssues: &off, Description: &description}).AddTokenAuth(token), http.StatusForbidden)
	after := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	require.Equal(t, before.Description, after.Description)
	require.True(t, after.UnitEnabled(t.Context(), unit.TypeIssues))
	require.NoError(t, repo_service.UpdateRepositoryUnits(t.Context(), after, []repo_model.RepoUnit{{RepoID: 1, Type: unit.TypeIssues, Config: new(repo_model.IssuesConfig)}}, []unit.Type{unit.TypeIssues}))
}

func TestEnterpriseFeatureConcurrentParentAndChild(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		_, err := authz_service.PutFeatureGrant(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeSystem}, authz.FeatureWiki, authz_service.FeatureGrantInput{State: authz.FeatureRequired, Config: []byte(`{}`)})
		results <- err
	}()
	go func() {
		<-start
		_, err := authz_service.PutFeatureGrant(t.Context(), owner, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}, authz.FeatureWiki, authz_service.FeatureGrantInput{State: authz.FeatureDisabled, Config: []byte(`{}`)})
		results <- err
	}()
	close(start)
	for range 2 {
		err := <-results
		require.True(t, err == nil || errors.Is(err, authz_service.ErrFeatureParentLocked), "%v", err)
	}
	policy, err := authz_service.GetFeaturePolicy(t.Context(), authz.FeatureWiki, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1})
	require.NoError(t, err)
	require.Equal(t, authz.FeatureRequired, policy.Effective.State)
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		return authz_model.DeleteScope(ctx, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1})
	}))
	unittest.AssertCount(t, &authz_model.FeatureGrant{ScopeType: authz_model.ScopeRepo, ScopeID: 1}, 0)
}

func TestEnterpriseFeatureImplicitPullUnitIntent(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	setting.EnterpriseAuthz.Enforce = true
	_, err := db.GetEngine(t.Context()).Where("repo_id = ? AND type = ?", 1, unit.TypePullRequests).Delete(new(repo_model.RepoUnit))
	require.NoError(t, err)
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	_, err = authz_service.PutFeatureGrant(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeSystem}, authz.FeaturePullRequests, authz_service.FeatureGrantInput{State: authz.FeatureDisabled, Config: []byte(`{}`)})
	require.NoError(t, err)
	before := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteRepository)
	allow := false
	description := "implicit-unit-must-not-save"
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", api.EditRepoOption{AllowMerge: &allow, Description: &description}).AddTokenAuth(token), http.StatusForbidden)
	after := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	require.Equal(t, before.Description, after.Description)
}

func TestEnterpriseFeatureConcurrentUnitAndParent(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	setting.EnterpriseAuthz.Enforce = true
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	start := make(chan struct{})
	parent := make(chan error, 1)
	settings := make(chan error, 1)
	go func() {
		<-start
		_, err := authz_service.PutFeatureGrant(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeSystem}, authz.FeatureIssues, authz_service.FeatureGrantInput{State: authz.FeatureRequired, Config: []byte(`{}`)})
		parent <- err
	}()
	go func() {
		<-start
		settings <- repo_service.UpdateRepositoryUnits(t.Context(), repo, nil, []unit.Type{unit.TypeIssues})
	}()
	close(start)
	require.NoError(t, <-parent)
	err := <-settings
	if err != nil {
		require.ErrorContains(t, err, "feature_required")
	}
	fresh := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	require.Equal(t, err != nil, fresh.UnitEnabled(t.Context(), unit.TypeIssues))
	policy, readErr := authz_service.GetFeaturePolicy(t.Context(), authz.FeatureIssues, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1})
	require.NoError(t, readErr)
	require.Equal(t, authz.FeatureRequired, policy.Effective.State)
	require.Equal(t, err == nil, policy.Pending)
}

func TestEnterpriseFeatureConcurrentGrantCreationCAS(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, state := range []authz.FeatureState{authz.FeatureEnabled, authz.FeatureDisabled} {
		go func() {
			<-start
			_, err := authz_service.PutFeatureGrant(t.Context(), owner, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}, authz.FeatureWiki, authz_service.FeatureGrantInput{State: state, Config: []byte(`{}`)})
			results <- err
		}()
	}
	close(start)
	success, conflict := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			success++
		} else {
			require.ErrorIs(t, err, authz_service.ErrRevisionConflict)
			conflict++
		}
	}
	require.Equal(t, 1, success)
	require.Equal(t, 1, conflict)
	unittest.AssertCount(t, &authz_model.FeatureGrant{FeatureKey: authz.FeatureWiki, ScopeType: authz_model.ScopeRepo, ScopeID: 1, Revision: 1}, 1)
}

func pgFeatureStatementTimeout(ctx context.Context, t *testing.T) string {
	t.Helper()
	rows, err := db.GetEngine(ctx).Query("SELECT current_setting('statement_timeout') AS timeout")
	require.NoError(t, err)
	require.Len(t, rows, 1)
	return string(rows[0]["timeout"])
}

func TestEnterpriseFeaturePGAuditLockFailOpenPreservesNativeTransaction(t *testing.T) {
	if !setting.Database.Type.IsPostgreSQL() {
		t.Skip("requires PostgreSQL lock cancellation and savepoint recovery")
	}
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, false
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	connection, err := db.GetXORMEngineForTesting().DB().DB.Conn(ctx)
	require.NoError(t, err)
	defer connection.Close()
	locker, err := connection.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer locker.Rollback()
	_, err = locker.ExecContext(ctx, "LOCK TABLE audit_event IN ACCESS EXCLUSIVE MODE")
	require.NoError(t, err)
	started := time.Now()
	require.NoError(t, db.WithTx(ctx, func(tx context.Context) error {
		_, err := db.Exec(tx, "SELECT set_config('statement_timeout', '7s', true)")
		require.NoError(t, err)
		previousTimeout := pgFeatureStatementTimeout(tx, t)
		bounded, stop := context.WithTimeout(tx, time.Second)
		defer stop()
		require.NoError(t, db.WithSavepoint(bounded, func(probe context.Context) error {
			require.NotEqual(t, previousTimeout, pgFeatureStatementTimeout(probe, t))
			return nil
		}))
		require.Equal(t, previousTimeout, pgFeatureStatementTimeout(tx, t))
		nested, cancelNested := context.WithCancel(tx)
		defer cancelNested()
		err = db.WithSavepoint(nested, func(outer context.Context) error {
			innerErr := db.WithSavepoint(outer, func(context.Context) error {
				cancelNested()
				return context.Canceled
			})
			require.ErrorIs(t, innerErr, context.Canceled)
			require.NotErrorIs(t, innerErr, db.ErrObservationTransactionUnavailable)
			require.Equal(t, previousTimeout, pgFeatureStatementTimeout(outer, t))
			return nil
		})
		require.ErrorIs(t, err, context.Canceled)
		require.NotErrorIs(t, err, db.ErrObservationTransactionUnavailable)
		require.Equal(t, previousTimeout, pgFeatureStatementTimeout(tx, t))
		if err := authz_service.RequireRepoFeature(tx, 1, authz.FeatureIssues); err != nil {
			return err
		}
		require.GreaterOrEqual(t, time.Since(started), 500*time.Millisecond)
		require.Less(t, time.Since(started), 3*time.Second)
		require.Equal(t, previousTimeout, pgFeatureStatementTimeout(tx, t))
		_, err = db.Exec(tx, "UPDATE repository SET description=? WHERE id=1", "native-committed-after-audit-timeout")
		return err
	}))
	require.NoError(t, locker.Rollback())
	stored := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	require.Equal(t, "native-committed-after-audit-timeout", stored.Description)
}

func TestEnterpriseFeatureSelectiveAuditInsertRejectsActualMerge(t *testing.T) {
	if !setting.Database.Type.IsPostgreSQL() && !setting.Database.Type.IsSQLite3() {
		t.Skip("requires PostgreSQL or SQLite conditional audit trigger")
	}
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	setting.EnterpriseAuthz.Enforce = true
	var err error
	if setting.Database.Type.IsPostgreSQL() {
		_, err := db.Exec(t.Context(), `CREATE FUNCTION feature_merge_audit_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action = 'enterprise:feature:decision' THEN RAISE EXCEPTION 'feature_audit_unavailable'; END IF; RETURN NEW; END $$`)
		require.NoError(t, err)
		_, err = db.Exec(t.Context(), `CREATE TRIGGER feature_merge_audit_failure BEFORE INSERT ON audit_event FOR EACH ROW EXECUTE FUNCTION feature_merge_audit_failure()`)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := db.Exec(context.WithoutCancel(t.Context()), "DROP TRIGGER feature_merge_audit_failure ON audit_event")
			require.NoError(t, err)
			_, err = db.Exec(context.WithoutCancel(t.Context()), "DROP FUNCTION feature_merge_audit_failure()")
			require.NoError(t, err)
		})
	} else {
		_, err := db.Exec(t.Context(), `CREATE TRIGGER feature_merge_audit_failure BEFORE INSERT ON audit_event WHEN NEW.action = 'enterprise:feature:decision' BEGIN SELECT RAISE(ABORT, 'feature_audit_unavailable'); END`)
		require.NoError(t, err)
		t.Cleanup(func() {
			_, err := db.Exec(context.WithoutCancel(t.Context()), "DROP TRIGGER feature_merge_audit_failure")
			require.NoError(t, err)
		})
	}
	pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, pr.LoadBaseRepo(t.Context()))
	before, _, err := gitcmd.NewCommand("show-ref").WithRepo(pr.BaseRepo).RunStdString(t.Context())
	require.NoError(t, err)
	beforeIssue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: pr.IssueID})
	require.NoError(t, db.WithIndependentReadTx(t.Context(), func(tx context.Context) error {
		return authz_service.RequireRepoFeature(tx, pr.BaseRepoID, authz.FeaturePullRequests)
	}))
	require.NoError(t, db.Insert(t.Context(), &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}))
	err = pull_service.Merge(t.Context(), pr, actor, repo_model.MergeStyleMerge, "", "must-not-be-executed", true)
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, http.StatusServiceUnavailable, rejection.Status)
	require.Equal(t, "feature_policy_unavailable", rejection.Reason)
	stored := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
	require.False(t, stored.HasMerged)
	require.Empty(t, stored.MergedCommitID)
	storedIssue := unittest.AssertExistsAndLoadBean(t, &issues_model.Issue{ID: pr.IssueID})
	require.Equal(t, beforeIssue.IsClosed, storedIssue.IsClosed)
	after, _, err := gitcmd.NewCommand("show-ref").WithRepo(pr.BaseRepo).RunStdString(t.Context())
	require.NoError(t, err)
	require.Equal(t, before, after)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseFeatureDecision}, 0)
	_, err = git.GetFullCommitID(t.Context(), pr.BaseRepo, "refs/heads/master")
	require.NoError(t, err)
}

func TestEnterpriseFeaturePGNestedShadowPolicyTimeoutPreservesNativeTransaction(t *testing.T) {
	if !setting.Database.Type.IsPostgreSQL() {
		t.Skip("requires PostgreSQL nested savepoint recovery after lock cancellation")
	}
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	unittest.AssertCount(t, &repo_model.RepoUnit{RepoID: 1, Type: unit.TypeIssues}, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	connection, err := db.GetXORMEngineForTesting().DB().DB.Conn(ctx)
	require.NoError(t, err)
	defer connection.Close()
	locker, err := connection.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer locker.Rollback()
	_, err = locker.ExecContext(ctx, "LOCK TABLE enterprise_feature_definition IN ACCESS EXCLUSIVE MODE")
	require.NoError(t, err)
	started := time.Now()
	require.NoError(t, db.WithTx(ctx, func(tx context.Context) error {
		_, err := db.Exec(tx, "SELECT set_config('statement_timeout', '7s', true)")
		require.NoError(t, err)
		previousTimeout := pgFeatureStatementTimeout(tx, t)
		return authz_service.WithRepoFeatureConfiguration(tx, 1, nil, []unit.Type{unit.TypeIssues}, func(native context.Context) error {
			require.GreaterOrEqual(t, time.Since(started), 500*time.Millisecond)
			require.Less(t, time.Since(started), 3*time.Second)
			require.Equal(t, previousTimeout, pgFeatureStatementTimeout(native, t))
			if _, err := db.Exec(native, "DELETE FROM repo_unit WHERE repo_id=? AND type=?", 1, unit.TypeIssues); err != nil {
				return err
			}
			_, err := db.Exec(native, "UPDATE repository SET description=? WHERE id=1", "native-committed-after-nested-shadow-timeout")
			return err
		})
	}))
	require.NoError(t, locker.Rollback())
	unittest.AssertCount(t, &repo_model.RepoUnit{RepoID: 1, Type: unit.TypeIssues}, 0)
	stored := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	require.Equal(t, "native-committed-after-nested-shadow-timeout", stored.Description)
}
