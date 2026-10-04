// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/lfs"
	repo_module "gitea.dev/modules/repository"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"
	files_service "gitea.dev/services/repository/files"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

type fileExecutionRefRace struct {
	active atomic.Bool
	move   func() error
}

func (h *fileExecutionRefRace) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	return c.Ctx, nil
}

func (h *fileExecutionRefRace) AfterProcess(c *contexts.ContextHook) error {
	sql := strings.ToUpper(strings.NewReplacer("\"", "", "`", "").Replace(c.SQL))
	if strings.HasPrefix(sql, "UPDATE ENTERPRISE_AUTHZ_DECISION ") && strings.Contains(sql, "EXECUTION_STARTED") && h.active.Swap(false) {
		return h.move()
	}
	return nil
}

func TestEnterpriseAuthzFilePushKeepsAdmittedOldRef(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		t.Setenv(repo_module.EnvIsInternal, "true")
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		owner := loginUser(t, "user2")
		ownerToken := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository)
		attributes := getCreateFileOptions()
		attributes.ContentBase64 = base64.StdEncoding.EncodeToString([]byte("admitted-ordinary filter=lfs diff=lfs merge=lfs -text\n"))
		owner.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/.gitattributes", attributes).AddTokenAuth(ownerToken), http.StatusCreated)
		options := getCreateFileOptions()
		options.NewBranchName = "concurrent-codeowners"
		options.ContentBase64 = base64.StdEncoding.EncodeToString([]byte("* @user2\n"))
		concurrent := DecodeJSON(t, owner.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/CODEOWNERS", options).AddTokenAuth(ownerToken), http.StatusCreated), api.FileResponse{})
		require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}))
		require.NoError(t, db.Insert(t.Context(), &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}))
		require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: 1, RuleName: "master", CanPush: true, CanForcePush: true}))
		role := &authz_model.RoleDefinition{Name: "lease-writer", LowerName: "lease-writer", ScopeType: authz_model.ScopeRepo, ScopeID: 1, Revision: 1, CreatedBy: 2}
		require.NoError(t, db.Insert(t.Context(), role))
		_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
		require.NoError(t, err)
		require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.PushProtectedBranch, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
		require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: 4, ScopeType: authz_model.ScopeRepo, ScopeID: 1, ScopeOwnerID: 2, RoleID: role.ID, CreatedBy: 2}))
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		gitRepo, err := git.OpenRepository(t.Context(), repo)
		require.NoError(t, err)
		defer gitRepo.Close()
		before, err := gitRepo.GetBranchCommitID(t.Context(), "master")
		require.NoError(t, err)
		hook := &fileExecutionRefRace{move: func() error {
			return gitcmd.NewCommand("update-ref").AddDynamicArguments("refs/heads/master", concurrent.Commit.SHA, before).WithRepo(gitRepo).RunWithStderr(t.Context())
		}}
		hook.active.Store(true)
		unittest.GetXORMEngine().AddHook(hook)
		defer hook.active.Store(false)
		writer := loginUser(t, "user4")
		token := getTokenForLoggedInUser(t, writer, auth_model.AccessTokenScopeWriteRepository)
		options.NewBranchName, options.ForcePush = "", true
		options.ContentBase64 = base64.StdEncoding.EncodeToString([]byte("ordinary change\n"))
		response := writer.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/admitted-ordinary", options).AddTokenAuth(token), NoExpectedStatus)
		require.False(t, hook.active.Load(), "race must happen after admission and before the push")
		after, err := gitRepo.GetBranchCommitID(t.Context(), "master")
		require.NoError(t, err)
		require.Equal(t, concurrent.Commit.SHA, after, response.Body.String())
		require.GreaterOrEqual(t, response.Code, 400, response.Body.String())
		unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 1, Action: authz.PushProtectedBranch, DecisionMode: "enforce", AuthorizationDecision: "allow", ExecutionStarted: true, NativeOutcome: "failed"})
		pointer, err := lfs.GeneratePointer(strings.NewReader("ordinary change\n"))
		require.NoError(t, err)
		_, err = git_model.GetLFSMetaObjectByOid(t.Context(), repo.ID, pointer.Oid)
		require.ErrorIs(t, err, git_model.ErrLFSObjectNotExist)
	})
}

func TestEnterpriseAuthzFileLeaseDoesNotGrantForce(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		t.Setenv(repo_module.EnvIsInternal, "true")
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		before, err := git.GetBranchCommitID(t.Context(), repo, "master")
		require.NoError(t, err)
		owner := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository)
		options := getCreateFileOptions()
		options.ContentBase64 = base64.StdEncoding.EncodeToString([]byte("* @user2\n"))
		created := DecodeJSON(t, owner.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/CODEOWNERS", options).AddTokenAuth(token), http.StatusCreated), api.FileResponse{})
		actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		ctx, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: repo, Action: authz.PushBranch, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "api"}})
		temporary, err := files_service.NewTemporaryUploadRepository(repo)
		require.NoError(t, err)
		defer temporary.Close()
		require.NoError(t, temporary.Clone(ctx, "master", true))
		err = temporary.Push(ctx, actor, before, "master", false)
		require.Error(t, err, "a lease must not turn a normal push into a forced rewind")
		after, err := git.GetBranchCommitID(t.Context(), repo, "master")
		require.NoError(t, err)
		require.Equal(t, created.Commit.SHA, after)
	})
}

func TestEnterpriseAuthzFileFamiliesActualDiffAndAtomicDenial(t *testing.T) {
	for _, operation := range []string{"api_create", "api_update", "api_rename", "api_delete", "api_bulk", "api_patch", "web_edit", "web_delete_recursive", "web_upload", "web_patch", "web_cherry_pick", "web_revert"} {
		t.Run(operation, func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, _ *url.URL) {
				defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
				defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
				defer test.MockVariableValue(&setting.EnterpriseAuthz.FailClosedOnError, true)()
				defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
				owner := loginUser(t, "user2")
				ownerToken := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository)
				create := getCreateFileOptions()
				create.ContentBase64 = base64.StdEncoding.EncodeToString([]byte("* @user2\n"))
				file := "docs/CODEOWNERS"
				if operation == "api_rename" {
					file = "ordinary-owners"
				}
				if operation == "api_create" || operation == "api_bulk" || operation == "api_patch" || operation == "web_patch" || operation == "web_upload" {
					file = "ordinary-owners"
				}
				if operation == "web_cherry_pick" {
					create.NewBranchName = "controlled-source"
				}
				response := owner.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/"+file, create).AddTokenAuth(ownerToken), http.StatusCreated)
				created := DecodeJSON(t, response, api.FileResponse{})
				require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}))
				require.NoError(t, db.Insert(t.Context(), &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}))
				require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: 1, RuleName: "master", CanPush: true}))
				writer := loginUser(t, "user4")
				token := getTokenForLoggedInUser(t, writer, auth_model.AccessTokenScopeWriteRepository)
				patch := "diff --git a/CODEOWNERS b/CODEOWNERS\nnew file mode 100644\n--- /dev/null\n+++ b/CODEOWNERS\n@@ -0,0 +1 @@\n+* @user4\n"
				request := func() *httptest.ResponseRecorder {
					if operation == "api_create" {
						return writer.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/CODEOWNERS", create).AddTokenAuth(token), NoExpectedStatus)
					}
					if operation == "api_update" || operation == "api_rename" {
						return writer.MakeRequest(t, NewRequestWithJSON(t, "PUT", "/api/v1/repos/user2/repo1/contents/docs/CODEOWNERS", &api.UpdateFileOptions{SHA: created.Content.SHA, FromPath: file, ContentBase64: base64.StdEncoding.EncodeToString([]byte("* @user4\n"))}).AddTokenAuth(token), NoExpectedStatus)
					}
					if operation == "api_delete" {
						return writer.MakeRequest(t, NewRequestWithJSON(t, "DELETE", "/api/v1/repos/user2/repo1/contents/docs/CODEOWNERS", &api.DeleteFileOptions{SHA: created.Content.SHA}).AddTokenAuth(token), NoExpectedStatus)
					}
					if operation == "api_bulk" {
						return writer.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents", &api.ChangeFilesOptions{Files: []*api.ChangeFileOperation{{Operation: "create", Path: "CODEOWNERS", ContentBase64: create.ContentBase64}, {Operation: "create", Path: "ordinary-compound", ContentBase64: create.ContentBase64}}}).AddTokenAuth(token), NoExpectedStatus)
					}
					if operation == "api_patch" {
						return writer.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/diffpatch", &api.ApplyDiffPatchFileOptions{Content: patch}).AddTokenAuth(token), NoExpectedStatus)
					}
					path, params := "/user2/repo1/_edit/master/docs/CODEOWNERS", map[string]string{"commit_choice": "direct", "tree_path": "docs/CODEOWNERS", "content": "* @user4\n"}
					switch operation {
					case "web_delete_recursive":
						path = "/user2/repo1/_delete/master/docs"
					case "web_patch":
						path, params["content"] = "/user2/repo1/_diffpatch/master/", patch
					case "web_cherry_pick", "web_revert":
						path = "/user2/repo1/_cherrypick/" + created.Commit.SHA + "/master"
						if operation == "web_revert" {
							params["revert"] = "true"
						}
					case "web_upload":
						body := &bytes.Buffer{}
						form := multipart.NewWriter(body)
						part, err := form.CreateFormFile("file", "CODEOWNERS")
						require.NoError(t, err)
						_, err = part.Write([]byte("* @user4\n"))
						require.NoError(t, err)
						require.NoError(t, form.Close())
						upload := NewRequestWithBody(t, "POST", "/user2/repo1/upload-file", body)
						upload.Header.Set("Content-Type", form.FormDataContentType())
						id := DecodeJSON(t, writer.MakeRequest(t, upload, http.StatusOK), map[string]string{})["uuid"]
						path, params = "/user2/repo1/_upload/master", map[string]string{"commit_choice": "direct", "files": id}
					}
					return testEditorActionPostRequest(t, writer, path, params)
				}
				repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
				gitRepo, err := git.OpenRepository(t.Context(), repo)
				require.NoError(t, err)
				defer gitRepo.Close()
				before, err := gitRepo.GetBranchCommitID(t.Context(), "master")
				require.NoError(t, err)
				response = request()
				require.Equal(t, http.StatusForbidden, response.Code, response.Body.String())
				after, err := gitRepo.GetBranchCommitID(t.Context(), "master")
				require.NoError(t, err)
				require.Equal(t, before, after)
				denied := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 1, Action: authz.ManageCodeowners, DecisionMode: "enforce", AuthorizationDecision: "deny"})
				require.False(t, denied.ExecutionStarted)
				require.Equal(t, 1, unittest.GetCount(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 1, Action: authz.ManageCodeowners, DecisionMode: "enforce", AuthorizationDecision: "deny"}))
				require.NotContains(t, denied.SnapshotJSON, "@user4")
				role := &authz_model.RoleDefinition{Name: "file-controlled", LowerName: "file-controlled", ScopeType: authz_model.ScopeRepo, ScopeID: 1, Revision: 1, CreatedBy: 2}
				require.NoError(t, db.Insert(t.Context(), role))
				_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
				require.NoError(t, err)
				for _, action := range []authz.Action{authz.ManageCodeowners, authz.PushProtectedBranch} {
					require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: action, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
				}
				require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: 4, ScopeType: authz_model.ScopeRepo, ScopeID: 1, ScopeOwnerID: 2, RoleID: role.ID, CreatedBy: 2}))
				response = request()
				require.Contains(t, []int{http.StatusOK, http.StatusCreated}, response.Code, response.Body.String())
				after, err = gitRepo.GetBranchCommitID(t.Context(), "master")
				require.NoError(t, err)
				require.NotEqual(t, before, after)
				unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 1, Action: authz.ManageCodeowners, DecisionMode: "enforce", AuthorizationDecision: "allow", ExecutionStarted: true, NativeOutcome: "success"})
			})
		})
	}
}
