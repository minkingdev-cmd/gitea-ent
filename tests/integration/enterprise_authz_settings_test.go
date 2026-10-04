// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	actions_model "gitea.dev/models/actions"
	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	repo_model "gitea.dev/models/repo"
	secret_model "gitea.dev/models/secret"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	"gitea.dev/models/webhook"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzAPISettingsMutations(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	for _, enabled := range []bool{false, true} {
		setting.EnterpriseAuthz.Enabled = enabled
		prefix := fmt.Sprintf("shadow-settings-%t", enabled)
		check := func(action authz.Action, request *RequestWrapper, status int) *api.Hook {
			t.Helper()
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			response := session.MakeRequest(t, request.AddTokenAuth(token), status)
			if enabled {
				require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: action, RequestSource: "api", NativeOutcome: "success"}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
				require.NotContains(t, record.SnapshotJSON, "SENSITIVE-settings")
				var event audit_model.Event
				found, err := db.GetEngine(t.Context()).Where("action = ? AND metadata LIKE ?", audit_model.EnterpriseAuthzDecision, "%"+record.ObservationID+"%").Get(&event)
				require.NoError(t, err)
				require.True(t, found)
				require.NotContains(t, event.Metadata+event.Message, "SENSITIVE-settings")
			} else {
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			}
			if action == authz.ManageWebhook && status != 204 {
				return DecodeJSON(t, response, &api.Hook{})
			}
			return nil
		}
		branchURL := "/api/v1/repos/user2/repo1/branch_protections"
		check(authz.ManageBranchProtection, NewRequestWithJSON(t, "POST", branchURL, &api.CreateBranchProtectionOption{RuleName: prefix, EnablePush: true}), 201)
		check(authz.ManageBranchProtection, NewRequestWithJSON(t, "PATCH", branchURL+"/"+prefix, &api.EditBranchProtectionOption{EnablePush: new(false)}), 200)
		check(authz.ManageBranchProtection, NewRequest(t, "DELETE", branchURL+"/"+prefix), 204)
		hookURL := "/api/v1/repos/user2/repo1/hooks"
		hook := check(authz.ManageWebhook, NewRequestWithJSON(t, "POST", hookURL, api.CreateHookOption{Type: "gitea", Config: api.CreateHookOptionConfig{"content_type": "json", "url": "https://example.invalid/SENSITIVE-settings-callback"}, AuthorizationHeader: "Bearer SENSITIVE-settings-token"}), 201)
		check(authz.ManageWebhook, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("%s/%d", hookURL, hook.ID), api.EditHookOption{Active: new(false)}), 200)
		check(authz.ManageWebhook, NewRequest(t, "DELETE", fmt.Sprintf("%s/%d", hookURL, hook.ID)), 204)
		secretURL := "/api/v1/repos/user2/repo1/actions/secrets/" + fmt.Sprintf("SHADOW_%t", enabled)
		check(authz.ManageSecret, NewRequestWithJSON(t, "PUT", secretURL, api.CreateOrUpdateSecretOption{Data: "SENSITIVE-settings-secret"}), 201)
		check(authz.ManageSecret, NewRequestWithJSON(t, "PUT", secretURL, api.CreateOrUpdateSecretOption{Data: "SENSITIVE-settings-updated"}), 204)
		check(authz.ManageSecret, NewRequest(t, "DELETE", secretURL), 204)
	}
}

func TestEnterpriseAuthzAPISettingsNativeDenial(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user4")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	for _, tc := range []struct {
		action authz.Action
		url    string
		method string
	}{
		{authz.ManageBranchProtection, "/api/v1/repos/user2/repo1/branch_protections", "POST"},
		{authz.ManageWebhook, "/api/v1/repos/user2/repo1/hooks", "POST"},
		{authz.ManageSecret, "/api/v1/repos/user2/repo1/actions/secrets/SHADOW_DENIED", "PUT"},
		{authz.ManageCI, "/api/v1/repos/user2/repo1/actions/runners/registration-token", "POST"},
		{authz.ManageCI, "/api/v1/repos/user2/repo1/actions/runners/1", "DELETE"},
		{authz.ManageCI, "/api/v1/repos/user2/repo1/actions/runners/1", "PATCH"},
	} {
		setting.EnterpriseAuthz.Enabled = false
		request := func() *RequestWrapper {
			return NewRequestWithJSON(t, tc.method, tc.url, map[string]string{}).AddTokenAuth(token)
		}
		baseline := session.MakeRequest(t, request(), 403)
		before := unittest.GetCount(t, &authz_model.DecisionRecord{})
		setting.EnterpriseAuthz.Enabled = true
		response := session.MakeRequest(t, request(), 403)
		require.JSONEq(t, baseline.Body.String(), response.Body.String())
		require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
		unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 1, Action: tc.action, RequestSource: "api", NativeOutcome: "denied", NativeStage: "authorization"})
	}
}

func TestEnterpriseAuthzWebSettingsMutations(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	for _, enabled := range []bool{false, true} {
		setting.EnterpriseAuthz.Enabled = enabled
		prefix := fmt.Sprintf("shadow-web-%t", enabled)
		check := func(action authz.Action, request *RequestWrapper, status int, outcome string) {
			t.Helper()
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			session.MakeRequest(t, request, status)
			if enabled {
				require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: action, RequestSource: "web", NativeOutcome: outcome}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
			} else {
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			}
		}
		check(authz.ManageBranchProtection, NewRequestWithValues(t, "POST", "/user2/repo1/settings/branches/edit", map[string]string{"rule_name": prefix, "enable_push": "all"}), 303, "success")
		rule := unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{RepoID: 1, RuleName: prefix})
		check(authz.ManageBranchProtection, NewRequest(t, "POST", fmt.Sprintf("/user2/repo1/settings/branches/%d/delete", rule.ID)), 200, "success")
		check(authz.ManageBranchProtection, NewRequestWithValues(t, "POST", "/user2/repo1/settings/branches/edit", map[string]string{"rule_name": ""}), 303, "failed")
		check(authz.ManageCI, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/general/actions_unit", map[string]string{"enable_actions": "true"}), 303, "success")
		check(authz.ManageCI, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/general/token_permissions", map[string]string{"override_owner_config": "true", "token_permission_mode": "restricted"}), 303, "success")
		check(authz.ManageCI, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/general/token_permissions", map[string]string{"override_owner_config": "true", "token_permission_mode": "invalid"}), 303, "failed")
		check(authz.ManageWebhook, NewRequestWithValues(t, "POST", "/user2/repo1/settings/hooks/gitea/new", map[string]string{"payload_url": "https://example.invalid/SENSITIVE-settings-callback", "http_method": "POST", "content_type": "1", "authorization_header": "Bearer SENSITIVE-settings-token", "name": prefix}), 303, "success")
		hook := unittest.AssertExistsAndLoadBean(t, &webhook.Webhook{RepoID: 1, Name: prefix})
		check(authz.ManageWebhook, NewRequestWithValues(t, "POST", fmt.Sprintf("/user2/repo1/settings/hooks/gitea/%d", hook.ID), map[string]string{"payload_url": "https://example.invalid/SENSITIVE-settings-edited", "http_method": "POST", "content_type": "1", "name": prefix}), 303, "success")
		check(authz.ManageWebhook, NewRequestWithValues(t, "POST", "/user2/repo1/settings/hooks/delete", map[string]string{"id": strconv.FormatInt(hook.ID, 10)}), 200, "success")
		check(authz.ManageSecret, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/secrets", map[string]string{"name": fmt.Sprintf("SHADOW_WEB_%t", enabled), "data": "SENSITIVE-settings-secret"}), 200, "success")
		secret := unittest.AssertExistsAndLoadBean(t, &secret_model.Secret{RepoID: 1, Name: strings.ToUpper(fmt.Sprintf("SHADOW_WEB_%t", enabled))})
		check(authz.ManageSecret, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/secrets/delete", map[string]string{"id": strconv.FormatInt(secret.ID, 10)}), 200, "success")
		check(authz.ManageSecret, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/secrets", map[string]string{"name": "bad", "data": ""}), 400, "failed")
	}
}

func TestEnterpriseAuthzRequiredCheckIsSeparateAction(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	before := unittest.GetCount(t, &authz_model.DecisionRecord{})
	session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branch_protections", api.CreateBranchProtectionOption{RuleName: "shadow-required", EnableStatusCheck: true, StatusCheckContexts: []string{"SENSITIVE-settings-check"}}).AddTokenAuth(token), 201)
	require.Equal(t, before+2, unittest.GetCount(t, &authz_model.DecisionRecord{}))
	protection := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.ManageBranchProtection, NativeOutcome: "success"})
	ci := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.ManageCI, NativeOutcome: "success"})
	require.Equal(t, protection.OperationID, ci.OperationID)
	require.NotEqual(t, protection.ObservationID, ci.ObservationID)
	require.NotContains(t, ci.SnapshotJSON, "SENSITIVE-settings-check")
}

func TestEnterpriseAuthzWebRequiredCheckIsSeparateAction(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	for _, checks := range []string{"SENSITIVE-settings-check", ""} {
		before := unittest.GetCount(t, &authz_model.DecisionRecord{})
		var latest authz_model.DecisionRecord
		_, err := db.GetEngine(t.Context()).Desc("id").Get(&latest)
		require.NoError(t, err)
		form := map[string]string{"rule_name": "shadow-required-web", "enable_push": "all", "status_check_contexts": checks}
		if checks != "" {
			form["enable_status_check"] = "true"
		}
		session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/branches/edit", form), 303)
		require.Equal(t, before+2, unittest.GetCount(t, &authz_model.DecisionRecord{}))
		ci := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.ManageCI, NativeOutcome: "success", RequestSource: "web"}, unittest.Cond("id > ?", latest.ID))
		require.NotContains(t, ci.SnapshotJSON, "SENSITIVE-settings-check")
	}
}

func TestEnterpriseAuthzSettingsReadsDoNotObserveMutation(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadRepository)
	before := unittest.GetCount(t, &authz_model.DecisionRecord{})
	for _, url := range []string{"/api/v1/repos/user2/repo1/branch_protections", "/api/v1/repos/user2/repo1/hooks", "/api/v1/repos/user2/repo1/actions/secrets", "/user2/repo1/settings/branches", "/user2/repo1/settings/hooks", "/user2/repo1/settings/actions/general"} {
		session.MakeRequest(t, NewRequest(t, "GET", url).AddTokenAuth(token), 200)
	}
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
}

func TestEnterpriseAuthzWebSettingsNativeDenial(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user4")
	for _, tc := range []struct {
		action authz.Action
		url    string
	}{
		{authz.ManageBranchProtection, "/user2/repo1/settings/branches/edit"},
		{authz.ManageWebhook, "/user2/repo1/settings/hooks/gitea/new"},
		{authz.ManageSecret, "/user2/repo1/settings/actions/secrets"},
		{authz.ManageCI, "/user2/repo1/settings/actions/general/actions_unit"},
	} {
		request := func() *RequestWrapper { return NewRequestWithValues(t, "POST", tc.url, map[string]string{}) }
		setting.EnterpriseAuthz.Enabled = false
		session.MakeRequest(t, request(), 404)
		before := unittest.GetCount(t, &authz_model.DecisionRecord{})
		setting.EnterpriseAuthz.Enabled = true
		session.MakeRequest(t, request(), 404)
		require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
		unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 1, Action: tc.action, NativeOutcome: "denied", NativeStage: "authorization", RequestSource: "web"})
	}
}

func TestEnterpriseAuthzCISettingsMutations(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, false)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/general/actions_unit", map[string]string{"enable_actions": "true"}), 303)
	for _, enabled := range []bool{false, true} {
		setting.EnterpriseAuthz.Enabled = enabled
		name := fmt.Sprintf("SHADOW_CI_%t", enabled)
		check := func(request *RequestWrapper, status int, source string) {
			t.Helper()
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			if source == "api" {
				request = request.AddTokenAuth(token)
			}
			session.MakeRequest(t, request, status)
			if enabled {
				require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: authz.ManageCI, RequestSource: source, NativeOutcome: "success"}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
			} else {
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			}
		}
		url := "/api/v1/repos/user2/repo1/actions/variables/" + name
		check(NewRequestWithJSON(t, "POST", url, api.CreateVariableOption{Value: "SENSITIVE-settings-variable"}), 201, "api")
		check(NewRequestWithJSON(t, "PUT", url, api.UpdateVariableOption{Value: "SENSITIVE-settings-updated"}), 204, "api")
		check(NewRequest(t, "DELETE", url), 204, "api")
		check(NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/variables/new", map[string]string{"name": name, "data": "SENSITIVE-settings-variable"}), 200, "web")
		variable := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionVariable{RepoID: 1, Name: strings.ToUpper(name)})
		check(NewRequestWithValues(t, "POST", fmt.Sprintf("/user2/repo1/settings/actions/variables/%d/edit", variable.ID), map[string]string{"name": name, "data": "SENSITIVE-settings-updated"}), 200, "web")
		check(NewRequest(t, "POST", fmt.Sprintf("/user2/repo1/settings/actions/variables/%d/delete", variable.ID)), 200, "web")
		check(NewRequest(t, "POST", "/api/v1/repos/user2/repo1/actions/runners/registration-token"), 200, "api")
		check(NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/actions/runners/34348", api.EditActionRunnerOption{Disabled: &enabled}), 200, "api")
		check(NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/runners/34348", map[string]string{"description": "shadow-runner"}), 303, "web")
		check(NewRequest(t, "POST", "/user2/repo1/settings/actions/runners/reset_registration_token"), 200, "web")
		check(NewRequestWithValues(t, "POST", "/user2/repo1/actions/disable", map[string]string{"workflow": "shadow-unused.yaml"}), 200, "web")
		check(NewRequestWithValues(t, "POST", "/user2/repo1/actions/enable", map[string]string{"workflow": "shadow-unused.yaml"}), 200, "web")
	}
}

func TestEnterpriseAuthzSettingsEvidenceFaultsPreserveNativeChanges(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, false)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/general/actions_unit", map[string]string{"enable_actions": "true"}), 303)
	session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branch_protections", api.CreateBranchProtectionOption{RuleName: "shadow-fault-rule"}).AddTokenAuth(token), 201)
	hookResp := session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/hooks", api.CreateHookOption{Type: "gitea", Config: api.CreateHookOptionConfig{"content_type": "json", "url": "https://example.invalid/SENSITIVE-settings-callback"}}).AddTokenAuth(token), 201)
	hook := DecodeJSON(t, hookResp, api.Hook{})
	session.MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/repo1/actions/secrets/SHADOW_FAULT", api.CreateOrUpdateSecretOption{Data: "SENSITIVE-settings-initial"}).AddTokenAuth(token), 201)
	for _, table := range []string{"enterprise_subject_role_binding", "enterprise_authz_decision", "audit_event"} {
		t.Run(table, func(t *testing.T) {
			setting.EnterpriseAuthz.Enabled = false
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			_, err := db.Exec(t.Context(), "ALTER TABLE "+table+" RENAME TO authz_settings_fault")
			require.NoError(t, err)
			func() {
				defer func() {
					_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE authz_settings_fault RENAME TO "+table)
					require.NoError(t, err)
				}()
				for _, enabled := range []bool{false, true} {
					setting.EnterpriseAuthz.Enabled = enabled
					session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/branch_protections/shadow-fault-rule", api.EditBranchProtectionOption{EnablePush: new(enabled)}).AddTokenAuth(token), 200)
					session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", fmt.Sprintf("/api/v1/repos/user2/repo1/hooks/%d", hook.ID), api.EditHookOption{Active: new(enabled)}).AddTokenAuth(token), 200)
					session.MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/repo1/actions/secrets/SHADOW_FAULT", api.CreateOrUpdateSecretOption{Data: fmt.Sprintf("SENSITIVE-settings-%t", enabled)}).AddTokenAuth(token), 204)
					session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/general/token_permissions", map[string]string{"override_owner_config": "true", "token_permission_mode": "restricted"}), 303)
					session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", api.EditRepoOption{HasActions: new(true)}).AddTokenAuth(token), 200)
				}
			}()
			rule := unittest.AssertExistsAndLoadBean(t, &git_model.ProtectedBranch{RepoID: 1, RuleName: "shadow-fault-rule"})
			require.True(t, rule.CanPush)
			require.True(t, unittest.AssertExistsAndLoadBean(t, &webhook.Webhook{ID: hook.ID}).IsActive)
			if table == "enterprise_subject_role_binding" {
				require.Equal(t, before+5, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				require.Equal(t, 5, unittest.GetCount(t, &authz_model.DecisionRecord{CandidateDecision: "error", NativeOutcome: "success"}))
			} else {
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			}
		})
	}
}

func TestEnterpriseAuthzWebhookDisabledGuard(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.DisableWebhooks, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	for _, apiRoute := range []bool{false, true} {
		request := func() *RequestWrapper {
			if apiRoute {
				return NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/hooks", api.CreateHookOption{}).AddTokenAuth(token)
			}
			return NewRequestWithValues(t, "POST", "/user2/repo1/settings/hooks/gitea/new", map[string]string{})
		}
		setting.EnterpriseAuthz.Enabled = false
		baseline := session.MakeRequest(t, request(), 403)
		before := unittest.GetCount(t, &authz_model.DecisionRecord{})
		setting.EnterpriseAuthz.Enabled = true
		response := session.MakeRequest(t, request(), 403)
		if apiRoute {
			require.JSONEq(t, baseline.Body.String(), response.Body.String())
		}
		require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
		unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: authz.ManageWebhook, NativeOutcome: "denied", NativeStage: "authorization"}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
	}
}

func TestEnterpriseAuthzAdvancedUnitsDoNotPretendCISettings(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ManageCI})
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings", map[string]string{"action": "advanced", "repo_name": "repo1", "enable_code": "true", "enable_wiki": "true"}), 200)
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ManageCI}))
}

func TestEnterpriseAuthzRunnerGuardIsDeniedNotFailed(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, false)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/general/actions_unit", map[string]string{"enable_actions": "true"}), 303)
	for _, tc := range []struct{ method, url, source, outcome string }{
		{"DELETE", "/api/v1/repos/user2/repo1/actions/runners/34349", "api", "denied"},
		{"PATCH", "/api/v1/repos/user2/repo1/actions/runners/34349", "api", "denied"},
		{"POST", "/user2/repo1/settings/actions/runners/34349", "web", "denied"},
		{"DELETE", "/api/v1/repos/user2/repo1/actions/runners/999999", "api", "failed"},
	} {
		request := func() *RequestWrapper {
			if tc.source == "api" {
				return NewRequestWithJSON(t, tc.method, tc.url, api.EditActionRunnerOption{}).AddTokenAuth(token)
			}
			return NewRequestWithValues(t, tc.method, tc.url, map[string]string{"description": "must-not-change"})
		}
		setting.EnterpriseAuthz.Enabled = false
		baseline := session.MakeRequest(t, request(), 404)
		setting.EnterpriseAuthz.Enabled = true
		before := unittest.GetCount(t, &authz_model.DecisionRecord{})
		response := session.MakeRequest(t, request(), 404)
		if tc.source == "api" {
			require.JSONEq(t, baseline.Body.String(), response.Body.String())
		}
		require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
		record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: authz.ManageCI}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
		require.Equal(t, tc.outcome, record.NativeOutcome, tc.url)
	}
	runner := unittest.AssertExistsAndLoadBean(t, &actions_model.ActionRunner{ID: 34349})
	require.NotEqual(t, "must-not-change", runner.Description)
}

func TestEnterpriseAuthzRequiredScopedWorkflowGuardIsDenied(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, false)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/settings/actions/general/actions_unit", map[string]string{"enable_actions": "true"}), 303)
	require.NoError(t, actions_model.AddScopedWorkflowSource(t.Context(), 2, 2))
	require.NoError(t, actions_model.SetScopedWorkflowSourceConfigs(t.Context(), 2, 2, map[string]*actions_model.ScopedWorkflowConfig{"required.yaml": {Required: true}}))
	request := func() *RequestWrapper {
		return NewRequestWithValues(t, "POST", "/user2/repo1/actions/disable", map[string]string{"workflow": "required.yaml", "scoped_workflow_source_repo_id": "2"})
	}
	baseline := session.MakeRequest(t, request(), 400)
	setting.EnterpriseAuthz.Enabled = true
	before := unittest.GetCount(t, &authz_model.DecisionRecord{})
	response := session.MakeRequest(t, request(), 400)
	require.JSONEq(t, baseline.Body.String(), response.Body.String())
	require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: authz.ManageCI}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
	require.Equal(t, "denied", record.NativeOutcome)
}

func TestEnterpriseAuthzWebhookExecutionIsNotManagement(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user4")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ManageWebhook})
	session.MakeRequest(t, NewRequest(t, "POST", "/api/v1/repos/user2/repo1/hooks/1/tests").AddTokenAuth(token), 403)
	session.MakeRequest(t, NewRequest(t, "POST", "/user2/repo1/settings/hooks/1/test"), 404)
	session.MakeRequest(t, NewRequest(t, "POST", "/user2/repo1/settings/hooks/1/replay/invalid"), 404)
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.ManageWebhook}))
}

func TestEnterpriseAuthzAPIRepoActionsUnitIsCISetting(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteRepository)
	for _, enabled := range []bool{false, true} {
		for _, actions := range []bool{false, true} {
			setting.EnterpriseAuthz.Enabled = enabled
			before := unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.ManageCI})
			MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", api.EditRepoOption{HasActions: &actions}).AddTokenAuth(token), 200)
			if enabled {
				require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.ManageCI}))
				unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, ActorID: 2, Action: authz.ManageCI, RequestSource: "api", NativeOutcome: "success"}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
			} else {
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.ManageCI}))
			}
		}
	}

	setting.EnterpriseAuthz.Enabled = true
	actions, archived := false, true
	beforeCI := unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.ManageCI})
	beforeArchive := unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.Archive})
	MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", api.EditRepoOption{HasActions: &actions, Archived: &archived}).AddTokenAuth(token), 200)
	require.Equal(t, beforeCI+1, unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.ManageCI}))
	require.Equal(t, beforeArchive+1, unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.Archive}))
	ci := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.ManageCI, NativeOutcome: "success"}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision WHERE action = ?)", authz.ManageCI))
	archive := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.Archive, NativeOutcome: "success"}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision WHERE action = ?)", authz.Archive))
	require.Equal(t, ci.OperationID, archive.OperationID)
	require.NotEqual(t, ci.ObservationID, archive.ObservationID)
}

func TestEnterpriseAuthzAPIRepoPartialSettingsSuccess(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	repo.IsMirror = true
	_, err := db.Exec(t.Context(), "UPDATE repository SET is_mirror = true WHERE id = ?", repo.ID)
	require.NoError(t, err)
	token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteRepository)
	for _, enabled := range []bool{false, true} {
		setting.EnterpriseAuthz.Enabled = enabled
		response := MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1", api.EditRepoOption{HasActions: new(enabled), Archived: new(true)}).AddTokenAuth(token), 422)
		require.Contains(t, response.Body.String(), "mirror")
		current := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		require.Equal(t, enabled, current.UnitEnabled(t.Context(), unit.TypeActions))
		require.False(t, current.IsArchived)
		if enabled {
			ci := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.ManageCI, NativeOutcome: "success"})
			archive := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.Archive, NativeOutcome: "denied"})
			require.Equal(t, ci.OperationID, archive.OperationID)
			require.NotEqual(t, ci.ObservationID, archive.ObservationID)
		} else {
			unittest.AssertCount(t, &authz_model.DecisionRecord{RepoID: 1}, 0)
		}
	}
}
