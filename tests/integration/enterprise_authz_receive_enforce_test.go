// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
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
	"gitea.dev/modules/private"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzReceiveEnforceActualCodeownersAtomic(t *testing.T) {
	for _, ssh := range []bool{false, true} {
		t.Run(fmt.Sprintf("ssh_%t", ssh), func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, u *url.URL) {
				defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
				defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
				defer test.MockVariableValue(&setting.EnterpriseAuthz.FailClosedOnError, true)()
				defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
				require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}))
				require.NoError(t, db.Insert(t.Context(), &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}))
				run := func(cloneURL *url.URL) {
					work := filepath.Join(t.TempDir(), "actual-diff")
					doGitClone(work, cloneURL)(t)
					doGitCheckoutWriteFileCommit(localGitAddCommitOptions{LocalRepoPath: work, CheckoutBranch: "master", TreeFilePath: "CODEOWNERS", TreeFileContent: "* @user4\n"})(t)
					_, stderr, pushErr := gitcmd.NewCommand("push", "origin", "HEAD:refs/heads/enforce-controlled", "HEAD:refs/heads/enforce-other", "HEAD:refs/tags/enforce-tag").WithDir(work).RunStdString(t.Context())
					require.Error(t, pushErr, stderr)
					repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
					gitRepo, err := git.OpenRepository(t.Context(), repo)
					require.NoError(t, err)
					defer gitRepo.Close()
					require.False(t, gitRepo.IsBranchExist(t.Context(), "enforce-controlled"))
					require.False(t, gitRepo.IsBranchExist(t.Context(), "enforce-other"))
					require.False(t, gitRepo.IsTagExist(t.Context(), "enforce-tag"))
					record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 1, Action: "repo.manage_codeowners", DecisionMode: "enforce", AuthorizationDecision: "deny"})
					require.False(t, record.ExecutionStarted)
					require.Equal(t, "unknown", record.NativeOutcome)
					role := &authz_model.RoleDefinition{Name: "git-controlled", LowerName: "git-controlled", ScopeType: authz_model.ScopeRepo, ScopeID: 1, Revision: 1, CreatedBy: 2}
					require.NoError(t, db.Insert(t.Context(), role))
					_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
					require.NoError(t, err)
					require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.ManageCodeowners, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
					binding := &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: 4, ScopeType: authz_model.ScopeRepo, ScopeID: 1, ScopeOwnerID: 2, RoleID: role.ID, CreatedBy: 2}
					require.NoError(t, db.Insert(t.Context(), binding))
					require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: 1, RuleName: "enforce-controlled", CanPush: true}))
					_, _, pushErr = gitcmd.NewCommand("push", "origin", "HEAD:refs/heads/enforce-controlled", "HEAD:refs/heads/enforce-other", "HEAD:refs/tags/enforce-tag").WithDir(work).RunStdString(t.Context())
					require.Error(t, pushErr)
					require.False(t, gitRepo.IsBranchExist(t.Context(), "enforce-controlled"))
					require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.PushProtectedBranch, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
					_, _, pushErr = gitcmd.NewCommand("push", "origin", "HEAD:refs/heads/enforce-controlled", "HEAD:refs/heads/enforce-other", "HEAD:refs/tags/enforce-tag").WithDir(work).RunStdString(t.Context())
					require.NoError(t, pushErr)
					require.True(t, gitRepo.IsBranchExist(t.Context(), "enforce-controlled"))
					require.True(t, gitRepo.IsBranchExist(t.Context(), "enforce-other"))
					require.True(t, gitRepo.IsTagExist(t.Context(), "enforce-tag"))
					allowed := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, Action: authz.PushProtectedBranch, DecisionMode: "enforce", AuthorizationDecision: "allow", NativeOutcome: "success", NativeStage: "transport"})
					require.True(t, allowed.ExecutionStarted)
					require.Equal(t, 3, unittest.GetCount(t, &authz_model.DecisionRecord{OperationID: allowed.OperationID, DecisionMode: "enforce", NativeOutcome: "success"}))
					require.Equal(t, 2, unittest.GetCount(t, &authz_model.DecisionRecord{OperationID: allowed.OperationID, DecisionMode: "shadow", Action: authz.CreateBranch, NativeOutcome: "success"}))
					_, _, pushErr = gitcmd.NewCommand("push", "origin", ":refs/heads/enforce-controlled", ":refs/tags/enforce-tag").WithDir(work).RunStdString(t.Context())
					require.Error(t, pushErr)
					require.True(t, gitRepo.IsBranchExist(t.Context(), "enforce-controlled"))
					require.True(t, gitRepo.IsTagExist(t.Context(), "enforce-tag"))
					doGitCheckoutWriteFileCommit(localGitAddCommitOptions{LocalRepoPath: work, CheckoutBranch: "master", TreeFilePath: "CODEOWNERS", TreeFileContent: "* @user2\n"})(t)
					before, err := gitRepo.GetBranchCommitID(t.Context(), "enforce-controlled")
					require.NoError(t, err)
					_, err = db.GetEngine(t.Context()).Where("repo_id = ? AND branch_name = ?", 1, "enforce-controlled").Cols("require_signed_commits").Update(&git_model.ProtectedBranch{RequireSignedCommits: true})
					require.NoError(t, err)
					_, stderr, pushErr = gitcmd.NewCommand("push", "origin", "HEAD:refs/heads/enforce-controlled").WithDir(work).RunStdString(t.Context())
					require.Error(t, pushErr)
					require.Contains(t, stderr, "unverified commit")
					_, err = db.GetEngine(t.Context()).Where("repo_id = ? AND branch_name = ?", 1, "enforce-controlled").Cols("require_signed_commits").Update(&git_model.ProtectedBranch{})
					require.NoError(t, err)
					_, err = db.DeleteByID[authz_model.SubjectRoleBinding](t.Context(), binding.ID)
					require.NoError(t, err)
					_, _, pushErr = gitcmd.NewCommand("push", "origin", "HEAD:refs/heads/enforce-controlled").WithDir(work).RunStdString(t.Context())
					require.Error(t, pushErr)
					after, err := gitRepo.GetBranchCommitID(t.Context(), "enforce-controlled")
					require.NoError(t, err)
					require.Equal(t, before, after)
					_, _, pushErr = gitcmd.NewCommand("push", "origin", ":refs/heads/enforce-other", ":refs/tags/enforce-tag").WithDir(work).RunStdString(t.Context())
					require.Error(t, pushErr)
					require.True(t, gitRepo.IsBranchExist(t.Context(), "enforce-other"))
					require.True(t, gitRepo.IsTagExist(t.Context(), "enforce-tag"))
					binding.ID = 0
					require.NoError(t, db.Insert(t.Context(), binding))
					_, _, pushErr = gitcmd.NewCommand("push", "origin", ":refs/heads/enforce-other", ":refs/tags/enforce-tag").WithDir(work).RunStdString(t.Context())
					require.NoError(t, pushErr)
					require.False(t, gitRepo.IsBranchExist(t.Context(), "enforce-other"))
					require.False(t, gitRepo.IsTagExist(t.Context(), "enforce-tag"))
				}
				if ssh {
					withKeyFile(t, "enforce-writer", func(keyFile string) {
						apiCtx := NewAPITestContext(t, "user4", "repo1", auth_model.AccessTokenScopeWriteUser)
						doAPICreateUserKey(apiCtx, "enforce-writer", keyFile, func(*testing.T, api.PublicKey) {})(t)
						run(createSSHUrl("user2/repo1.git", u))
					})
				} else {
					cloneURL := u.JoinPath("user2", "repo1.git")
					cloneURL.User = url.UserPassword("user4", userPassword)
					run(cloneURL)
				}
			})
		})
	}
}

func TestEnterpriseAuthzFileEnforceBeforeLFSWrite(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
		defer test.MockVariableValue(&setting.EnterpriseAuthz.FailClosedOnError, true)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		owner := loginUser(t, "user2")
		ownerToken := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository)
		attributes := getCreateFileOptions()
		attributes.ContentBase64 = base64.StdEncoding.EncodeToString([]byte("CODEOWNERS filter=lfs diff=lfs merge=lfs -text\nalready-authorized filter=lfs diff=lfs merge=lfs -text\n"))
		owner.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/.gitattributes", attributes).AddTokenAuth(ownerToken), http.StatusCreated)
		require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}))
		require.NoError(t, db.Insert(t.Context(), &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}))
		writer := loginUser(t, "user4")
		token := getTokenForLoggedInUser(t, writer, auth_model.AccessTokenScopeWriteRepository)
		before, err := db.GetEngine(t.Context()).Table("lfs_meta_object").Count()
		require.NoError(t, err)
		options := getCreateFileOptions()
		content := "SENSITIVE-LFS-unauthorized-codeowners"
		options.ContentBase64 = base64.StdEncoding.EncodeToString([]byte(content))
		pointer, err := lfs.GeneratePointer(strings.NewReader(content))
		require.NoError(t, err)
		store := lfs.NewContentStore()
		exists, err := store.Exists(pointer)
		require.NoError(t, err)
		require.False(t, exists)
		writer.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/CODEOWNERS", options).AddTokenAuth(token), http.StatusForbidden)
		after, err := db.GetEngine(t.Context()).Table("lfs_meta_object").Count()
		require.NoError(t, err)
		require.Equal(t, before, after)
		exists, err = store.Exists(pointer)
		require.NoError(t, err)
		require.False(t, exists)
		owner.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/already-authorized", options).AddTokenAuth(ownerToken), http.StatusCreated)
		existing, err := git_model.GetLFSMetaObjectByOid(t.Context(), 1, pointer.Oid)
		require.NoError(t, err)
		writer.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/CODEOWNERS", options).AddTokenAuth(token), http.StatusForbidden)
		retained, err := git_model.GetLFSMetaObjectByOid(t.Context(), 1, pointer.Oid)
		require.NoError(t, err)
		require.Equal(t, existing.ID, retained.ID)
		exists, err = store.Exists(pointer)
		require.NoError(t, err)
		require.True(t, exists)
	})
}

func TestEnterpriseAuthzReceiveTicketNeverGrantsExecution(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
		defer test.MockVariableValue(&setting.EnterpriseAuthz.FailClosedOnError, false)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		owner := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository)
		options := getCreateFileOptions()
		options.ContentBase64 = base64.StdEncoding.EncodeToString([]byte("* @user2\n"))
		file := DecodeJSON(t, owner.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/CODEOWNERS", options).AddTokenAuth(token), http.StatusCreated), api.FileResponse{})
		require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}))
		require.NoError(t, db.Insert(t.Context(), &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}))
		actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		input := authz_service.EvaluateInput{Actor: actor, Repo: repo, Action: authz.PushBranch, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "git_http"}}
		valid := authz_service.NewHookOperationTicket(t.Context(), input, nil)
		owned := authz_service.NewHookOperationTicket(t.Context(), input, []authz_service.HookOwnedObservation{{Action: authz.MergePullRequest, Branch: "ticket-controlled"}, {Action: authz.ManageCodeowners, Branch: "ticket-controlled"}})
		input.Repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
		wrongRepo := authz_service.NewHookOperationTicket(t.Context(), input, nil)
		for _, ticket := range []authz.HookOperationTicket{"", authz.HookOperationTicket(string(valid) + "tampered"), wrongRepo, owned, valid, valid} {
			extra := private.HookPreReceive(t.Context(), "user2", "repo1", private.HookOptions{UserID: 4, UserName: "user4", AuthzOperation: ticket, OldCommitIDs: []string{strings.Repeat("0", 40)}, NewCommitIDs: []string{file.Commit.SHA}, RefFullNames: []git.RefName{git.RefNameFromBranch("ticket-controlled")}})
			require.Error(t, extra.Error)
			require.NotContains(t, extra.UserMsg, "@user2")
		}
		gitRepo, err := git.OpenRepository(t.Context(), repo)
		require.NoError(t, err)
		defer gitRepo.Close()
		require.False(t, gitRepo.IsBranchExist(t.Context(), "ticket-controlled"))
		require.Zero(t, unittest.GetCount(t, &authz_model.DecisionRecord{ActorID: 4, DecisionMode: "enforce", AuthorizationDecision: "allow"}))
	})
}
