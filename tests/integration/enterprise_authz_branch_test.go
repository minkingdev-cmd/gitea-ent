// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

func TestEnterpriseAuthzShadowBranchCreation(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		for _, web := range []bool{false, true} {
			for _, enabled := range []bool{false, true} {
				setting.EnterpriseAuthz.Enabled = enabled
				before := unittest.GetCount(t, &authz_model.DecisionRecord{})
				branch := fmt.Sprintf("shadow-branch-web-%t-enabled-%t", web, enabled)
				request := func() *RequestWrapper {
					if web {
						return NewRequestWithValues(t, "POST", "/user2/repo1/branches/_new/branch/master", map[string]string{"new_branch_name": branch})
					}
					return NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branches", api.CreateBranchRepoOption{BranchName: branch}).AddTokenAuth(token)
				}
				status := 201
				source := "api"
				if web {
					status, source = 303, "web"
				}
				session.MakeRequest(t, request(), status)
				if enabled {
					require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
					unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, ActorID: 2, Action: authz.CreateBranch, RequestSource: source, NativeOutcome: "success"}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
				} else {
					require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				}
				conflictStatus := 409
				if web {
					conflictStatus = 303
				}
				session.MakeRequest(t, request(), conflictStatus)
				if enabled {
					require.Equal(t, before+2, unittest.GetCount(t, &authz_model.DecisionRecord{}))
					unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.CreateBranch, NativeOutcome: "failed"}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
				}
			}
		}
	})
}

func TestEnterpriseAuthzShadowFileAndCodeownersMutation(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		for _, web := range []bool{false, true} {
			for _, enabled := range []bool{false, true} {
				setting.EnterpriseAuthz.Enabled = enabled
				before := unittest.GetCount(t, &authz_model.DecisionRecord{})
				branch := fmt.Sprintf("shadow-file-%t-%t", web, enabled)
				opts := getCreateFileOptions()
				opts.NewBranchName = branch
				opts.ContentBase64 = base64.StdEncoding.EncodeToString([]byte("* @user2\n"))
				source := "api"
				if web {
					source = "file_editor"
					session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/_new/master/", map[string]string{"tree_path": ".gitea/CODEOWNERS", "content": "* @user2\n", "commit_choice": "commit-to-new-branch", "new_branch_name": branch}), http.StatusOK)
				} else {
					response := session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/.gitea/CODEOWNERS", opts).AddTokenAuth(token), 201)
					result := DecodeJSON(t, response, api.FileResponse{})
					require.Equal(t, ".gitea/CODEOWNERS", result.Content.Path)
				}
				if enabled {
					require.Equal(t, before+3, unittest.GetCount(t, &authz_model.DecisionRecord{}))
					for _, action := range []authz.Action{authz.CreateBranch, authz.PushBranch, authz.ManageCodeowners} {
						record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: action, RequestSource: source, NativeOutcome: "success"})
						require.NotContains(t, record.SnapshotJSON, ".gitea/CODEOWNERS")
						require.NotContains(t, record.SnapshotJSON, "* @user2")
					}
				} else {
					require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				}
			}
		}
	})
}

func TestEnterpriseAuthzShadowFileNativeGuardCannotBeBypassed(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	role, err := authz_service.CreateRole(t.Context(), owner, scope, authz_service.CreateRoleInput{Name: "shadow writer", Permissions: &[]authz_service.PermissionInput{{Action: authz.PushBranch, Effect: "allow"}}})
	require.NoError(t, err)
	_, _, err = authz_service.PutBinding(t.Context(), owner, scope, authz_service.BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: role.Definition.ID})
	require.NoError(t, err)
	session := loginUser(t, "user4")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
	request := func() *RequestWrapper {
		return NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/shadow-no-write", getCreateFileOptions()).AddTokenAuth(token)
	}
	setting.EnterpriseAuthz.Enabled = false
	baseline := session.MakeRequest(t, request(), 403)
	before := unittest.GetCount(t, &authz_model.DecisionRecord{})
	setting.EnterpriseAuthz.Enabled = true
	response := session.MakeRequest(t, request(), 403)
	require.JSONEq(t, baseline.Body.String(), response.Body.String())
	require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
	unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 1, Action: authz.PushBranch, CandidateDecision: "allow", NativeOutcome: "denied", NativeStage: "authorization"})
}

func TestEnterpriseAuthzEditorPageDoesNotObserveMutation(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user4")
	before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.PushBranch})
	session.MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/_edit/master/README.md"), 200)
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.PushBranch}))
}

func TestEnterpriseAuthzFileForceExistingBranchDoesNotObserveCreate(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		setting.EnterpriseAuthz.Enabled = false
		session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branches", api.CreateBranchRepoOption{BranchName: "shadow-force-existing"}).AddTokenAuth(token), 201)
		setting.EnterpriseAuthz.Enabled = true
		before := unittest.GetCount(t, &authz_model.DecisionRecord{})
		opts := getCreateFileOptions()
		opts.NewBranchName = "shadow-force-existing"
		opts.ForcePush = true
		response := session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/shadow-force-file", opts).AddTokenAuth(token), 201)
		require.Equal(t, "shadow-force-file", DecodeJSON(t, response, api.FileResponse{}).Content.Path)
		require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
		unittest.AssertNotExistsBean(t, &authz_model.DecisionRecord{Action: authz.CreateBranch})
		unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.PushBranch, NativeOutcome: "success"})
	})
}

func TestEnterpriseAuthzBranchHookRejectionIsDenied(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branch_protections", &api.BranchProtection{RuleName: "shadow-denied/**", EnablePush: false}).AddTokenAuth(token), 201)
		for _, enabled := range []bool{false, true} {
			setting.EnterpriseAuthz.Enabled = enabled
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branches", api.CreateBranchRepoOption{BranchName: fmt.Sprintf("shadow-denied/%t", enabled)}).AddTokenAuth(token), 500)
			if enabled {
				require.Equal(t, before+2, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				created := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.CreateBranch, NativeOutcome: "denied"})
				protected := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.PushProtectedBranch, NativeOutcome: "denied", NativeStage: "pre_receive", RequestSource: "api"})
				require.Equal(t, created.OperationID, protected.OperationID)
			} else {
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			}
		}
	})
}

func TestEnterpriseAuthzBranchReferenceMutations(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		for _, enabled := range []bool{false, true} {
			setting.EnterpriseAuthz.Enabled = false
			branch := fmt.Sprintf("shadow-ref-%t", enabled)
			session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branches", api.CreateBranchRepoOption{BranchName: branch, OldRefName: "branch2"}).AddTokenAuth(token), 201)
			setting.EnterpriseAuthz.Enabled = enabled
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			renamed := branch + "-renamed"
			session.MakeRequest(t, NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/branches/"+branch, api.RenameBranchRepoOption{Name: renamed}).AddTokenAuth(token), 204)
			session.MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/repo1/branches/"+renamed, api.UpdateBranchRepoOption{NewCommitID: "master", Force: true}).AddTokenAuth(token), 204)
			session.MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/branches/"+renamed).AddTokenAuth(token), 204)
			if enabled {
				require.Equal(t, before+4, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				unittest.AssertCount(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, RequestSource: "api", Action: authz.PushBranch, NativeOutcome: "success"}, 3)
				unittest.AssertCount(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, RequestSource: "api", Action: authz.CreateBranch, NativeOutcome: "success"}, 1)
			} else {
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			}
		}
	})
}

func TestEnterpriseAuthzWebBranchReferencesAndGuards(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		owner := loginUser(t, "user2")
		reader := loginUser(t, "user4")
		token := getTokenForLoggedInUser(t, reader, auth_model.AccessTokenScopeWriteRepository)
		for _, enabled := range []bool{false, true} {
			setting.EnterpriseAuthz.Enabled = enabled
			branch := fmt.Sprintf("shadow-web-ref-%t", enabled)
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/branches/_new/branch/master", map[string]string{"new_branch_name": branch}), 303)
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/branches/rename", map[string]string{"from": branch, "to": branch + "-renamed"}), 303)
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/branches/delete", map[string]string{"name": branch + "-renamed"}), 200)
			deleted := unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: 1, Name: branch + "-renamed", IsDeleted: true})
			owner.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/branches/restore", map[string]string{"branch_id": strconv.FormatInt(deleted.ID, 10)}), 200)
			if enabled {
				require.Equal(t, before+5, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				unittest.AssertCount(t, &authz_model.DecisionRecord{RequestSource: "web", Action: authz.CreateBranch, NativeOutcome: "success"}, 3)
			} else {
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			}
			before = unittest.GetCount(t, &authz_model.DecisionRecord{})
			reader.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branches", api.CreateBranchRepoOption{BranchName: "denied"}).AddTokenAuth(token), 403)
			reader.MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/branches/"+branch+"-renamed").AddTokenAuth(token), 403)
			reader.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/branches/delete", map[string]string{"name": branch + "-renamed"}), 404)
			if enabled {
				require.Equal(t, before+3, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				unittest.AssertCount(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 1, NativeOutcome: "denied", NativeStage: "authorization"}, 3)
			} else {
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			}
		}
	})
}

func TestEnterpriseAuthzAPIMirrorBranchGuards(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	_, err := db.GetEngine(t.Context()).ID(1).Cols("is_mirror").Update(&repo_model.Repository{IsMirror: true})
	require.NoError(t, err)
	token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteRepository)
	for _, enabled := range []bool{false, true} {
		setting.EnterpriseAuthz.Enabled = enabled
		before := unittest.GetCount(t, &authz_model.DecisionRecord{})
		requests := []*RequestWrapper{
			NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branches", api.CreateBranchRepoOption{BranchName: "mirror-create"}),
			NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/branches/master"),
			NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/repo1/branches/master", api.UpdateBranchRepoOption{NewCommitID: "0123456789012345678901234567890123456789"}),
			NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/branches/master", api.RenameBranchRepoOption{Name: "mirror-rename"}),
		}
		for _, req := range requests {
			MakeRequest(t, req.AddTokenAuth(token), http.StatusForbidden)
		}
		expected := before
		if enabled {
			expected += len(requests)
		}
		require.Equal(t, expected, unittest.GetCount(t, &authz_model.DecisionRecord{}))
		if enabled {
			require.Equal(t, 3, unittest.GetCount(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: authz.PushBranch, NativeOutcome: "denied", NativeStage: "authorization"}))
			require.Equal(t, 1, unittest.GetCount(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: authz.CreateBranch, NativeOutcome: "denied", NativeStage: "operation"}))
		}
	}
}

func TestEnterpriseAuthzAPIEmptyBranchFailures(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	_, err := db.GetEngine(t.Context()).ID(1).Cols("is_empty").Update(&repo_model.Repository{IsEmpty: true})
	require.NoError(t, err)
	token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteRepository)
	for _, enabled := range []bool{false, true} {
		setting.EnterpriseAuthz.Enabled = enabled
		before := unittest.GetCount(t, &authz_model.DecisionRecord{})
		requests := []*RequestWrapper{
			NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branches", api.CreateBranchRepoOption{BranchName: "empty-create"}),
			NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/branches/master"),
			NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/repo1/branches/master", api.UpdateBranchRepoOption{NewCommitID: "0123456789012345678901234567890123456789"}),
			NewRequestWithJSON(t, "PATCH", "/api/v1/repos/user2/repo1/branches/master", api.RenameBranchRepoOption{Name: "empty-rename"}),
		}
		for _, req := range requests {
			resp := MakeRequest(t, req.AddTokenAuth(token), http.StatusNotFound)
			require.Contains(t, resp.Body.String(), "Git Repository is empty.")
		}
		expected := before
		if enabled {
			expected += len(requests)
		}
		require.Equal(t, expected, unittest.GetCount(t, &authz_model.DecisionRecord{}))
		if enabled {
			require.Equal(t, 3, unittest.GetCount(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: authz.PushBranch, NativeOutcome: "failed", NativeStage: "operation"}))
			require.Equal(t, 1, unittest.GetCount(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: authz.CreateBranch, NativeOutcome: "failed", NativeStage: "operation"}))
		}
	}
}

type shadowBranchPreparationFailureHook struct {
	active      atomic.Bool
	syncFailure bool
}

func (h *shadowBranchPreparationFailureHook) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.active.Load() {
		sql := strings.ToUpper(strings.NewReplacer("\"", "", "`", "").Replace(c.SQL))
		if strings.HasPrefix(sql, "SELECT ") && strings.Contains(sql, "FROM BRANCH ") {
			if !h.syncFailure || !strings.Contains(sql, "COUNT(") {
				return c.Ctx, errors.New("shadow native branch preparation failure")
			}
		}
	}
	return c.Ctx, nil
}

func (h *shadowBranchPreparationFailureHook) AfterProcess(*contexts.ContextHook) error { return nil }

func TestEnterpriseAuthzAPIDeleteBranchPreparationFailures(t *testing.T) {
	for _, syncFailure := range []bool{false, true} {
		t.Run(strconv.FormatBool(syncFailure), func(t *testing.T) {
			defer tests.PrepareTestEnv(t)()
			defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
			defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
			if syncFailure {
				_, err := db.GetEngine(t.Context()).Where("repo_id = ?", 1).Delete(new(git_model.Branch))
				require.NoError(t, err)
			}
			token := getTokenForLoggedInUser(t, loginUser(t, "user2"), auth_model.AccessTokenScopeWriteRepository)
			hook := &shadowBranchPreparationFailureHook{syncFailure: syncFailure}
			unittest.GetXORMEngine().AddHook(hook)
			defer hook.active.Store(false)
			var baseline string
			for _, enabled := range []bool{false, true} {
				setting.EnterpriseAuthz.Enabled = enabled
				before := unittest.GetCount(t, &authz_model.DecisionRecord{})
				hook.active.Store(true)
				resp := MakeRequest(t, NewRequest(t, "DELETE", "/api/v1/repos/user2/repo1/branches/branch2").AddTokenAuth(token), http.StatusInternalServerError)
				hook.active.Store(false)
				if !enabled {
					baseline = resp.Body.String()
					require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				} else {
					require.Equal(t, baseline, resp.Body.String())
					require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
					unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: authz.PushBranch, NativeOutcome: "failed", NativeStage: "operation"})
				}
			}
		})
	}
}
