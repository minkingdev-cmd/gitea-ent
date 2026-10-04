// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
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
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzExecutionConcurrentPolicySnapshot(t *testing.T) {
	if !setting.Database.Type.IsPostgreSQL() {
		t.Skip("需要 PostgreSQL 的并发 REPEATABLE READ 事务")
	}
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		owner := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, owner, auth_model.AccessTokenScopeWriteRepository)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		gitRepo, err := git.OpenRepository(t.Context(), repo)
		require.NoError(t, err)
		defer gitRepo.Close()
		old, err := gitRepo.GetBranchCommitID(t.Context(), "master")
		require.NoError(t, err)
		opts := getCreateFileOptions()
		opts.ContentBase64 = base64.StdEncoding.EncodeToString([]byte("* @user4\n"))
		file := DecodeJSON(t, owner.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/contents/CODEOWNERS", opts).AddTokenAuth(token), http.StatusCreated), api.FileResponse{})
		require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}))
		require.NoError(t, db.Insert(t.Context(), &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeWrite}))
		require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: 1, RuleName: "master", CanPush: true}))
		role := &authz_model.RoleDefinition{Name: "snapshot-grant", LowerName: "snapshot-grant", ScopeType: authz_model.ScopeRepo, ScopeID: 1, Revision: 1}
		require.NoError(t, db.Insert(t.Context(), role))
		_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
		require.NoError(t, err)
		for _, action := range []authz.Action{authz.PushProtectedBranch, authz.ManageCodeowners} {
			require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: action, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
		}
		binding := &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: 4, ScopeType: authz_model.ScopeRepo, ScopeID: 1, ScopeOwnerID: 2, RoleID: role.ID}
		require.NoError(t, db.Insert(t.Context(), binding))
		entered, release := make(chan struct{}), make(chan struct{})
		input := authz_service.GitExecutionInput{Actor: unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}), Repo: repo, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, Source: "git_http", Ref: git.RefNameFromBranch("master"), OldCommitID: old, NewCommitID: file.Commit.SHA, GitRepo: gitRepo, NativeGuard: func(snapshot context.Context, _ *user_model.User, current *repo_model.Repository) error {
			if _, err := repo_model.GetRepositoryByID(snapshot, current.ID); err != nil {
				return err
			}
			close(entered)
			select {
			case <-release:
				return nil
			case <-snapshot.Done():
				return snapshot.Err()
			}
		}}
		type result struct {
			ctx       context.Context
			admission *authz_service.Admission
			err       error
		}
		finished := make(chan result, 1)
		go func() {
			ctx, admission, err := authz_service.BeginGitExecution(t.Context(), []authz_service.GitExecutionInput{input})
			finished <- result{ctx, admission, err}
		}()
		select {
		case <-entered:
		case early := <-finished:
			t.Fatalf("未到达快照边界：%v", early.err)
		}
		_, deleteErr := db.DeleteByID[authz_model.SubjectRoleBinding](t.Context(), binding.ID)
		close(release)
		require.NoError(t, deleteErr)
		first := <-finished
		require.NoError(t, first.err)
		require.NoError(t, first.admission.Start(first.ctx))
		first.admission.Finish(first.ctx, authz_service.NativeFailed, authz_service.StageOperation)
		input.NativeGuard = nil
		_, next, err := authz_service.BeginGitExecution(t.Context(), []authz_service.GitExecutionInput{input})
		require.Error(t, err)
		require.Nil(t, next)
		require.Equal(t, 2, unittest.GetCount(t, &authz_model.DecisionRecord{ActorID: 4, AuthorizationDecision: "allow", NativeOutcome: "failed", ExecutionStarted: true}))
		require.Equal(t, 2, unittest.GetCount(t, &authz_model.DecisionRecord{ActorID: 4, AuthorizationDecision: "deny", NativeOutcome: "unknown", ExecutionStarted: false}))
	})
}
