// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	actions_model "gitea.dev/models/actions"
	"gitea.dev/models/activities"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	secret_model "gitea.dev/models/secret"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	webhook_model "gitea.dev/models/webhook"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	actions_service "gitea.dev/services/actions"
	authz_service "gitea.dev/services/enterpriseauthz"
	pull_service "gitea.dev/services/pull"
	repo_service "gitea.dev/services/repository"
	secret_service "gitea.dev/services/secrets"
	webhook_service "gitea.dev/services/webhook"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzSettingsEnforceSecretAndCompound(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeAdmin}))
	require.NoError(t, db.Insert(t.Context(), &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeAdmin}))
	session := loginUser(t, "user4")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	before := unittest.GetCount(t, &secret_model.Secret{RepoID: 1})
	response := session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/secrets", map[string]string{"name": "ENFORCE_SETTINGS", "data": "SENSITIVE-settings-value"}), http.StatusForbidden)
	require.NotContains(t, response.Body.String(), "SENSITIVE-settings-value")
	require.Equal(t, before, unittest.GetCount(t, &secret_model.Secret{RepoID: 1}))
	repoBefore := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	archive, ci := true, !repoBefore.UnitEnabled(t.Context(), unit.TypeActions)
	description := "SENSITIVE-compound-settings"
	notificationsBefore := unittest.GetCount(t, &activities.Notification{})
	session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", api.EditRepoOption{Archived: &archive, HasActions: &ci, Description: &description}).AddTokenAuth(token), http.StatusForbidden)
	repoAfter := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	require.Equal(t, repoBefore.IsArchived, repoAfter.IsArchived)
	require.Equal(t, repoBefore.Description, repoAfter.Description)
	require.Equal(t, notificationsBefore, unittest.GetCount(t, &activities.Notification{}))
	require.Equal(t, repoBefore.UnitEnabled(t.Context(), unit.TypeActions), repoAfter.UnitEnabled(t.Context(), unit.TypeActions))
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 1, Action: "repo.manage_secret"})
	require.NotContains(t, record.SnapshotJSON, "SENSITIVE-settings-value")
	require.Equal(t, "enforce", record.DecisionMode)
	require.Equal(t, "deny", record.AuthorizationDecision)
}

func TestEnterpriseAuthzSettingsEnforceRequiredChecksNoop(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	base := "/api/v1/repos/user2/repo1/branch_protections"
	session.MakeRequest(t, NewRequestWithJSON(t, "POST", base, api.CreateBranchProtectionOption{RuleName: "enforce-checks", EnableStatusCheck: true, StatusCheckContexts: []string{"test"}}).AddTokenAuth(token), 201)
	before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: "repo.manage_ci"})
	enabled := true
	session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", base+"/enforce-checks", api.EditBranchProtectionOption{EnableStatusCheck: &enabled, StatusCheckContexts: []string{"test"}}).AddTokenAuth(token), 200)
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: "repo.manage_ci"}))
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/branches/edit", map[string]string{"rule_name": "enforce-checks", "enable_push": "all", "enable_status_check": "true", "status_check_contexts": "test"}), 303)
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: "repo.manage_ci"}))
}

func TestEnterpriseAuthzSettingsEnforceOwnerMutationFamilies(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	check := func(action string, request *RequestWrapper, status int) *httptest.ResponseRecorder {
		t.Helper()
		before := unittest.GetCount(t, &authz_model.DecisionRecord{DecisionMode: "enforce", Action: authz.Action(action)})
		response := session.MakeRequest(t, request.AddTokenAuth(token), status)
		require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{DecisionMode: "enforce", Action: authz.Action(action)}))
		record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: authz.Action(action), DecisionMode: "enforce"}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision WHERE decision_mode = 'enforce')"))
		require.Equal(t, "success", record.NativeOutcome)
		require.True(t, record.ExecutionStarted)
		require.NotContains(t, record.SnapshotJSON, "SENSITIVE")
		return response
	}
	protectionURL := "/api/v1/repos/user2/repo1/branch_protections"
	check("repo.manage_branch_protection", NewRequestWithJSON(t, "POST", protectionURL, api.CreateBranchProtectionOption{RuleName: "enforce-owner", ProtectedFilePatterns: "private/*"}), 201)
	rule := unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{RepoID: 1, RuleName: "enforce-owner"})
	check("repo.manage_branch_protection", NewRequestWithJSON(t, "POST", protectionURL+"/priority", api.UpdateBranchProtectionPriories{IDs: []int64{rule.ID}}), 204)
	check("repo.manage_branch_protection", NewRequestWithJSON(t, "PATCH", protectionURL+"/enforce-owner", api.EditBranchProtectionOption{ProtectedFilePatterns: new("sensitive/*")}), 200)
	check("repo.manage_branch_protection", NewRequest(t, "DELETE", protectionURL+"/enforce-owner"), 204)
	check("repo.manage_branch_protection", NewRequestWithValues(t, "POST", "/user2/repo1/settings/branches/edit", map[string]string{"rule_name": "enforce-web-owner", "enable_push": "all", "protected_file_patterns": "private/*"}), 303)
	webRule := unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{RepoID: 1, RuleName: "enforce-web-owner"})
	check("repo.manage_branch_protection", NewRequestWithJSON(t, "POST", "/user2/repo1/settings/branches/priority", map[string]any{"ids": []int64{webRule.ID}}), 200)
	check("repo.manage_branch_protection", NewRequestWithValues(t, "POST", "/user2/repo1/settings/branches/edit", map[string]string{"rule_name": "enforce-web-owner", "enable_push": "all", "protected_file_patterns": "sensitive/*"}), 303)
	check("repo.manage_branch_protection", NewRequest(t, "POST", fmt.Sprintf("/user2/repo1/settings/branches/%d/delete", webRule.ID)), 200)
	hookURL := "/api/v1/repos/user2/repo1/hooks"
	hook := DecodeJSON(t, check("repo.manage_webhook", NewRequestWithJSON(t, "POST", hookURL, api.CreateHookOption{Type: "gitea", Config: api.CreateHookOptionConfig{"content_type": "json", "url": "https://example.invalid/SENSITIVE-url"}}), 201), &api.Hook{})
	check("repo.manage_webhook", NewRequestWithJSON(t, "PATCH", fmt.Sprintf("%s/%d", hookURL, hook.ID), api.EditHookOption{Active: new(false)}), 200)
	check("repo.manage_webhook", NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", hookURL, hook.ID)), 204)
	secretURL := "/api/v1/repos/user2/repo1/actions/secrets/ENFORCE_OWNER"
	check("repo.manage_secret", NewRequestWithJSON(t, "PUT", secretURL, api.CreateOrUpdateSecretOption{Data: "SENSITIVE-value"}), 201)
	check("repo.manage_secret", NewRequestWithJSON(t, "PUT", secretURL, api.CreateOrUpdateSecretOption{Data: "SENSITIVE-updated"}), 204)
	check("repo.manage_secret", NewRequest(t, "DELETE", secretURL), 204)
	variableURL := "/api/v1/repos/user2/repo1/actions/variables/ENFORCE_OWNER"
	check("repo.manage_ci", NewRequestWithJSON(t, "POST", variableURL, api.CreateVariableOption{Value: "SENSITIVE-variable"}), 201)
	check("repo.manage_ci", NewRequestWithJSON(t, "PUT", variableURL, api.UpdateVariableOption{Value: "SENSITIVE-updated"}), 204)
	check("repo.manage_ci", NewRequest(t, "DELETE", variableURL), 204)
	check("repo.manage_ci", NewRequest(t, "POST", "/api/v1/repos/user2/repo1/actions/runners/registration-token"), 200)
	unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunner{ID: 34348, RepoID: 1})
	check("repo.manage_ci", NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/runners/34348", map[string]string{"description": "SENSITIVE-runner"}), 303)
	check("repo.manage_ci", NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/runners/34348/update-runner", map[string]string{"disabled": "true"}), 200)
	check("repo.manage_ci", NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/runners/34348/update-runner", map[string]string{"disabled": "false"}), 200)
	check("repo.manage_ci", NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/actions/runners/34348", api.EditActionRunnerOption{Disabled: new(true)}), 200)
	check("repo.manage_ci", NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/actions/runners/34348"), 204)
	check("repo.manage_ci", NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/general/token_permissions", map[string]string{"override_owner_config": "true", "token_permission_mode": "restricted"}), 303)
	check("repo.manage_ci", NewRequestWithValues(t, "POST", "/user2/repo1/actions/disable", map[string]string{"workflow": "enforce-owner.yaml"}), 200)
	check("repo.manage_ci", NewRequestWithValues(t, "POST", "/user2/repo1/actions/enable", map[string]string{"workflow": "enforce-owner.yaml"}), 200)
}

func TestEnterpriseAuthzSettingsEnforceGrantAndCeiling(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeAdmin}))
	access := &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeAdmin}
	require.NoError(t, db.Insert(t.Context(), access))
	role := &authz_model.RoleDefinition{Name: "settings-secret", LowerName: "settings-secret", ScopeType: authz_model.ScopeRepo, ScopeID: 1, Revision: 1, CreatedBy: 2}
	require.NoError(t, db.Insert(t.Context(), role))
	_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	for _, action := range []authz.Action{authz.ManageSecret, authz.Archive} {
		require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: action, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
	}
	binding := &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: 4, ScopeType: authz_model.ScopeRepo, ScopeID: 1, ScopeOwnerID: 2, RoleID: role.ID, CreatedBy: 2}
	require.NoError(t, db.Insert(t.Context(), binding))
	session := loginUser(t, "user4")
	writeToken := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	readToken := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadRepository)
	url := "/api/v1/repos/user2/repo1/actions/secrets/ENFORCE_GRANT"
	session.MakeRequest(t, NewRequestWithJSON(t, "PUT", url, api.CreateOrUpdateSecretOption{Data: "SENSITIVE-grant"}).AddTokenAuth(readToken), 403)
	unittest.AssertNotExistsBean(t, &secret_model.Secret{RepoID: 1, Name: "ENFORCE_GRANT"})
	session.MakeRequest(t, NewRequestWithJSON(t, "PUT", url, api.CreateOrUpdateSecretOption{Data: "SENSITIVE-grant"}).AddTokenAuth(writeToken), 403)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/secrets", map[string]string{"name": "ENFORCE_GRANT", "data": "SENSITIVE-grant"}), 200)
	// 角色只有 secret/archive，原生 Admin 的 CI 能力仍保留。
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/variables/new", map[string]string{"name": "ENFORCE_NATIVE_CI", "data": "ok"}), 200)
	access.Mode = perm.AccessModeRead
	_, err = db.GetEngine(t.Context()).ID(access.ID).Cols("mode").Update(access)
	require.NoError(t, err)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/secrets/delete", map[string]string{"id": strconv.FormatInt(unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{RepoID: 1, Name: "ENFORCE_GRANT"}).ID, 10)}), 404)
	access.Mode = perm.AccessModeAdmin
	_, err = db.GetEngine(t.Context()).ID(access.ID).Cols("mode").Update(access)
	require.NoError(t, err)
	_, err = db.DeleteByID[authz_model.SubjectRoleBinding](t.Context(), binding.ID)
	require.NoError(t, err)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/secrets/delete", map[string]string{"id": strconv.FormatInt(unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{RepoID: 1, Name: "ENFORCE_GRANT"}).ID, 10)}), 403)
	unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{RepoID: 1, Name: "ENFORCE_GRANT"})
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/secrets", map[string]string{"name": "ENFORCE_WEB_DENY", "data": "SENSITIVE-web"}), 403)
	unittest.AssertNotExistsBean(t, &secret_model.Secret{RepoID: 1, Name: "ENFORCE_WEB_DENY"})
}

func TestEnterpriseAuthzSettingsSharedBoundariesRejectMissingAdmission(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	check := func(err error) {
		t.Helper()
		var rejection *authz_service.ExecutionError
		require.ErrorAs(t, err, &rejection)
		require.Equal(t, 403, rejection.Status)
	}
	_, _, err := secret_service.CreateOrUpdateSecret(t.Context(), 0, 1, "BYPASS_SECRET", "SENSITIVE-bypass", "")
	check(err)
	_, err = actions_service.CreateVariable(t.Context(), 0, 1, "BYPASS_VARIABLE", "value", "")
	check(err)
	check(webhook_service.CreateWebhook(t.Context(), &webhook_model.Webhook{RepoID: 1, URL: "https://example.invalid", Type: "gitea"}))
	_, err = actions_service.NewRunnerToken(t.Context(), 0, 1)
	check(err)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	check(repo_service.UpdateRepositoryUnits(t.Context(), repo, nil, []unit.Type{unit.TypeActions}))
	check(pull_service.CreateOrUpdateProtectedBranch(t.Context(), repo, &git_model.ProtectedBranch{RepoID: 1, RuleName: "bypass-protection"}, git_model.WhitelistOptions{}))
	unittest.AssertNotExistsBean(t, &secret_model.Secret{Name: "BYPASS_SECRET"})
	unittest.AssertNotExistsBean(t, &actions_model.ActionVariable{Name: "BYPASS_VARIABLE"})
	// 非仓库 scope 的既有 helper 不冒充仓库管理。
	_, _, err = secret_service.CreateOrUpdateSecret(t.Context(), 2, 0, "OWNER_SECRET", "value", "")
	require.NoError(t, err)
	_, err = actions_service.CreateVariable(t.Context(), 2, 0, "OWNER_VARIABLE", "value", "")
	require.NoError(t, err)
}

func TestEnterpriseAuthzSettingsRunnerRegistrationMachineEvidence(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	token := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunnerToken{ID: 4})
	before := unittest.GetCount(t, &authz_model.DecisionRecord{DecisionMode: "enforce", Action: authz.ManageCI})
	response := MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/actions/runner.v1.RunnerService/Register", map[string]string{"token": token.Token, "name": "SENSITIVE-machine-runner", "version": "v1"}), 200)
	require.NotEmpty(t, response.Body.String())
	require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{DecisionMode: "enforce", Action: authz.ManageCI}))
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 0, RepoID: 1, DecisionMode: "enforce", Action: authz.ManageCI})
	require.True(t, record.ExecutionStarted)
	require.Equal(t, "success", record.NativeOutcome)
	require.NotContains(t, record.SnapshotJSON, token.Token)
	require.NotContains(t, record.SnapshotJSON, "SENSITIVE-machine-runner")
	require.Contains(t, record.SnapshotJSON, `"native_only":true`)
}

func TestEnterpriseAuthzSettingsEnforcePreservesNativeGuards(t *testing.T) {
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
	t.Run("API-denial", TestEnterpriseAuthzAPISettingsNativeDenial)
	t.Run("Web-denial", TestEnterpriseAuthzWebSettingsNativeDenial)
	t.Run("Web-mutations", TestEnterpriseAuthzWebSettingsMutations)
	t.Run("webhook-disabled", TestEnterpriseAuthzWebhookDisabledGuard)
	t.Run("runner-scope", TestEnterpriseAuthzRunnerGuardIsDeniedNotFailed)
	t.Run("required-workflow", TestEnterpriseAuthzRequiredScopedWorkflowGuardIsDenied)
	t.Run("webhook-test-is-not-management", TestEnterpriseAuthzWebhookExecutionIsNotManagement)
}

func TestEnterpriseAuthzSettingsSharedObjectBinding(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
	check := func(err error) {
		t.Helper()
		var rejection *authz_service.ExecutionError
		require.ErrorAs(t, err, &rejection)
		require.Equal(t, 403, rejection.Status)
	}
	hook := &webhook_model.Webhook{RepoID: 1, URL: "https://example.invalid"}
	require.NoError(t, db.Insert(t.Context(), hook))
	hook.RepoID, hook.OwnerID = 0, 2
	check(webhook_service.UpdateWebhook(t.Context(), hook))
	runner := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunner{ID: 34348, RepoID: 1})
	runner.RepoID, runner.OwnerID = 0, 2
	check(actions_service.UpdateRunner(t.Context(), runner, "name"))
	check(actions_service.SetRunnerDisabled(t.Context(), runner, true))
	variable := &actions_model.ActionVariable{RepoID: 1, Name: "BINDING_TEST", Data: "value"}
	require.NoError(t, db.Insert(t.Context(), variable))
	variable.RepoID, variable.OwnerID = 0, 2
	_, err := actions_service.UpdateVariableNameData(t.Context(), variable)
	check(err)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	rule := &git_model.ProtectedBranch{RepoID: 2, RuleName: "scope-forgery"}
	require.NoError(t, db.Insert(t.Context(), rule))
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	ctx, admission, err := authz_service.BeginExecution(t.Context(), []authz_service.ExecutionInput{{EvaluateInput: authz_service.EvaluateInput{Actor: actor, Repo: repo, Action: authz.ManageBranchProtection, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "web"}}, Intent: authz_service.SettingsIntent(authz.ManageBranchProtection, rule.RuleName)}})
	require.NoError(t, err)
	require.NoError(t, admission.Start(ctx))
	defer admission.Finish(ctx, authz_service.NativeFailed, authz_service.StageOperation)
	check(pull_service.UpdateProtectedBranch(ctx, repo, rule, git_model.WhitelistOptions{}))
}

func TestEnterpriseAuthzSettingsMissingWebhookPreservesNativeResponse(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
	session := loginUser(t, "user2")
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/hooks/delete", map[string]string{"id": "999999"}), 200)
}

func TestEnterpriseAuthzSettingsEnforceInfrastructurePolicy(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.FailClosedOnError, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	_, err := db.Exec(t.Context(), "ALTER TABLE enterprise_subject_role_binding RENAME TO settings_binding_unavailable")
	require.NoError(t, err)
	defer func() {
		_, err := db.Exec(t.Context(), "ALTER TABLE settings_binding_unavailable RENAME TO enterprise_subject_role_binding")
		require.NoError(t, err)
	}()
	url := "/api/v1/repos/user2/repo1/actions/secrets/ENFORCE_INFRA"
	request := func() *RequestWrapper {
		return NewRequestWithJSON(t, "PUT", url, api.CreateOrUpdateSecretOption{Data: "SENSITIVE-infra"}).AddTokenAuth(token)
	}
	response := session.MakeRequest(t, request(), 503)
	require.NotContains(t, response.Body.String(), "settings_binding_unavailable")
	unittest.AssertNotExistsBean(t, &secret_model.Secret{Name: "ENFORCE_INFRA"})
	setting.EnterpriseAuthz.FailClosedOnError = false
	session.MakeRequest(t, request(), 201)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.ManageSecret, AuthorizationDecision: "fallback"})
	require.True(t, record.ExecutionStarted)
	require.Equal(t, "success", record.NativeOutcome)
}
