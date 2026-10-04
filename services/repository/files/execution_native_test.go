// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package files

import (
	"context"
	"strings"
	"testing"

	audit_model "gitea.dev/models/audit"
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
	"gitea.dev/modules/test"
	"gitea.dev/services/audit"
	authz_service "gitea.dev/services/enterpriseauthz"
	pull_service "gitea.dev/services/pull"

	"github.com/stretchr/testify/require"
)

func TestFileAdmissionRechecksCurrentNativeProtection(t *testing.T) {
	for _, variant := range []string{"unchanged", "unprotected", "force-unprotected", "newbranch-inherits", "push-revoked", "file-revoked", "signed-revoked", "signed-actual", "force-revoked", "write-revoked", "native-read-failed"} {
		t.Run(variant, func(t *testing.T) {
			unittest.PrepareTestEnv(t)
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true))
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true))
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz.FailClosedOnError, false))
			t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
			access := &access_model.Access{RepoID: repo.ID, UserID: actor.ID, Mode: perm.AccessModeWrite}
			require.NoError(t, db.Insert(t.Context(), access))
			rule := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "master", CanPush: true, CanForcePush: true, EnableForcePushAllowlist: true, ForcePushAllowlistUserIDs: []int64{actor.ID}}
			path := "README.md"
			if variant == "newbranch-inherits" {
				rule.RuleName, rule.ProtectedFilePatterns, path = "new-target", "README.md", "ordinary-new.txt"
			}
			require.NoError(t, db.Insert(t.Context(), rule))
			role := &authz_model.RoleDefinition{Name: "file-native", LowerName: "file-native", ScopeType: authz_model.ScopeRepo, ScopeID: repo.ID, Revision: 1}
			require.NoError(t, db.Insert(t.Context(), role))
			_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
			require.NoError(t, err)
			require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.PushProtectedBranch, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
			require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{RoleID: role.ID, SubjectType: authz_model.SubjectUser, SubjectID: actor.ID, ScopeType: authz_model.ScopeRepo, ScopeID: repo.ID, ScopeOwnerID: repo.OwnerID}))
			temporary, err := NewTemporaryUploadRepository(repo)
			require.NoError(t, err)
			t.Cleanup(temporary.Close)
			require.NoError(t, temporary.Clone(t.Context(), "master", false))
			require.NoError(t, temporary.SetDefaultIndex(t.Context()))
			old, err := temporary.GetLastCommit(t.Context())
			require.NoError(t, err)
			require.NoError(t, VerifyBranchProtection(t.Context(), repo, temporary.gitRepo, actor, "master", []string{path}))
			blob, err := temporary.HashObjectAndWrite(t.Context(), strings.NewReader("native admission test\n"))
			require.NoError(t, err)
			require.NoError(t, temporary.AddObjectToIndex(t.Context(), "100644", blob, path))
			tree, err := temporary.WriteTree(t.Context())
			require.NoError(t, err)
			force := variant == "force-revoked" || variant == "force-unprotected"
			parent := old
			if force {
				parent = ""
			}
			commit, err := temporary.CommitTree(t.Context(), &CommitTreeUserOptions{DoerUser: actor, TreeHash: tree, ParentCommitID: parent, CommitMessage: "native admission"})
			require.NoError(t, err)
			status, reason := 403, "native_visibility_denied"
			switch variant {
			case "unprotected":
				rule.CanPush, rule.UnprotectedFilePatterns = false, "README.md"
				_, err = db.GetEngine(t.Context()).ID(rule.ID).Cols("can_push", "unprotected_file_patterns").Update(rule)
			case "force-unprotected":
				rule.ForcePushAllowlistUserIDs, rule.UnprotectedFilePatterns = nil, "README.md"
				_, err = db.GetEngine(t.Context()).ID(rule.ID).Cols("force_push_allowlist_user_i_ds", "unprotected_file_patterns").Update(rule)
			case "push-revoked":
				rule.CanPush = false
				_, err = db.GetEngine(t.Context()).ID(rule.ID).Cols("can_push").Update(rule)
			case "file-revoked":
				rule.ProtectedFilePatterns = "README.md"
				_, err = db.GetEngine(t.Context()).ID(rule.ID).Cols("protected_file_patterns").Update(rule)
			case "signed-revoked", "signed-actual":
				rule.RequireSignedCommits = true
				_, err = db.GetEngine(t.Context()).ID(rule.ID).Cols("require_signed_commits").Update(rule)
				if variant == "signed-actual" {
					t.Cleanup(test.MockVariableValue(&setting.Repository.Signing.SigningKey, "configured-after-commit"))
					t.Cleanup(test.MockVariableValue(&setting.Repository.Signing.CRUDActions, []string{"always"}))
					require.NoError(t, VerifyBranchProtection(t.Context(), repo, temporary.gitRepo, actor, "master", []string{"README.md"}))
				}
			case "force-revoked":
				rule.ForcePushAllowlistUserIDs = nil
				_, err = db.GetEngine(t.Context()).ID(rule.ID).Cols("force_push_allowlist_user_i_ds").Update(rule)
			case "write-revoked":
				access.Mode = perm.AccessModeRead
				_, err = db.GetEngine(t.Context()).ID(access.ID).Cols("mode").Update(access)
			case "native-read-failed":
				status, reason = 503, "policy_read_failed"
				_, err = db.Exec(t.Context(), "ALTER TABLE access RENAME TO file_native_access_unavailable")
				t.Cleanup(func() {
					_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE file_native_access_unavailable RENAME TO access")
					require.NoError(t, err)
				})
			}
			require.NoError(t, err)
			if variant == "newbranch-inherits" {
				format, err := temporary.gitRepo.GetObjectFormat(t.Context())
				require.NoError(t, err)
				_, err = pull_service.CheckFileProtection(t.Context(), temporary.gitRepo, rule.RuleName, format.EmptyObjectID().String(), commit, rule.GetProtectedFilePatterns(), 1, nil)
				require.NoError(t, err)
			}
			_, admission, _, err := temporary.beginPushExecution(audit.WithOrigin(t.Context(), audit_model.OriginUI), actor, commit, rule.RuleName, force)
			if variant == "unchanged" || variant == "unprotected" || variant == "force-unprotected" || variant == "newbranch-inherits" {
				require.NoError(t, err)
				require.NotNil(t, admission)
				return
			}
			var denied *authz_service.ExecutionError
			require.ErrorAs(t, err, &denied)
			require.Equal(t, status, denied.Status)
			require.Equal(t, reason, denied.Reason)
			require.Nil(t, admission)
			unittest.AssertNotExistsBean(t, &authz_model.DecisionRecord{ActorID: actor.ID, DecisionMode: "enforce", AuthorizationDecision: "allow"})
		})
	}
}

func TestFilePushSignatureVerification(t *testing.T) {
	unittest.PrepareTestEnv(t)
	repo, err := git.OpenRepositoryLocal(t.Context(), "../../../routers/private/tests/repos/repo1_hook_verification")
	require.NoError(t, err)
	t.Cleanup(func() { repo.Close() })
	temporary := &TemporaryUploadRepository{gitRepo: repo}
	for _, variant := range []struct {
		old, commit string
		verified    bool
	}{
		{"72920278f2f999e3005801e5d5b8ab8139d3641c", "d766f2917716d45be24bfa968b8409544941be32", true},
		{"9779d17a04f1e2640583d35703c62460b2d86e0a", "72920278f2f999e3005801e5d5b8ab8139d3641c", false},
	} {
		err := temporary.checkPushSignatures(t.Context(), variant.old, variant.commit)
		if variant.verified {
			require.NoError(t, err)
			continue
		}
		var denied *authz_service.ExecutionError
		require.ErrorAs(t, err, &denied)
		require.Equal(t, 403, denied.Status)
		require.Equal(t, "native_visibility_denied", denied.Reason)
	}
}

func TestFileNewBranchSignedNativeContract(t *testing.T) {
	unittest.PrepareTestEnv(t)
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	require.NoError(t, db.Insert(t.Context(), &access_model.Access{RepoID: repo.ID, UserID: actor.ID, Mode: perm.AccessModeWrite}))
	require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "signed-new-target", CanPush: true, RequireSignedCommits: true}))
	t.Cleanup(test.MockVariableValue(&setting.Repository.Signing.SigningKey, "configured-after-commit"))
	t.Cleanup(test.MockVariableValue(&setting.Repository.Signing.CRUDActions, []string{"parentsigned"}))
	gitRepo, err := git.OpenRepositoryLocal(t.Context(), "../../../routers/private/tests/repos/repo1_hook_verification")
	require.NoError(t, err)
	t.Cleanup(func() { gitRepo.Close() })
	format, err := gitRepo.GetObjectFormat(t.Context())
	require.NoError(t, err)
	temporary := &TemporaryUploadRepository{gitRepo: gitRepo}
	require.NoError(t, temporary.checkPushNative(t.Context(), actor, repo, format.EmptyObjectID().String(), "93eac826f6188f34646cea81bf426aa5ba7d3bfe", "signed-new-target"))
}
