// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"net/url"
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
	repo_module "gitea.dev/modules/repository"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/audit"
	authz_service "gitea.dev/services/enterpriseauthz"
	files_service "gitea.dev/services/repository/files"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzFilePushRechecksNativeRules(t *testing.T) {
	for _, variant := range []string{"push", "file", "force"} {
		t.Run(variant, func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, _ *url.URL) {
				t.Setenv(repo_module.EnvIsInternal, "true")
				t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true))
				t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz.Enforce, true))
				t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz.FailClosedOnError, false))
				t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
				repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
				actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
				require.NoError(t, db.Insert(t.Context(), &access_model.Access{RepoID: repo.ID, UserID: actor.ID, Mode: perm.AccessModeWrite}))
				rule := &git_model.ProtectedBranch{RepoID: repo.ID, RuleName: "master", CanPush: true, CanForcePush: true, EnableForcePushAllowlist: true, ForcePushAllowlistUserIDs: []int64{actor.ID}}
				require.NoError(t, db.Insert(t.Context(), rule))
				role := &authz_model.RoleDefinition{Name: "file-current-native", LowerName: "file-current-native", ScopeType: authz_model.ScopeRepo, ScopeID: repo.ID, Revision: 1}
				require.NoError(t, db.Insert(t.Context(), role))
				_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
				require.NoError(t, err)
				require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.PushProtectedBranch, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
				require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{RoleID: role.ID, SubjectType: authz_model.SubjectUser, SubjectID: actor.ID, ScopeType: authz_model.ScopeRepo, ScopeID: repo.ID, ScopeOwnerID: repo.OwnerID}))
				gitRepo, err := git.OpenRepository(t.Context(), repo)
				require.NoError(t, err)
				t.Cleanup(func() { gitRepo.Close() })
				temporary, err := files_service.NewTemporaryUploadRepository(repo)
				require.NoError(t, err)
				t.Cleanup(temporary.Close)
				require.NoError(t, temporary.Clone(t.Context(), "master", false))
				require.NoError(t, temporary.SetDefaultIndex(t.Context()))
				old, err := temporary.GetLastCommit(t.Context())
				require.NoError(t, err)
				require.NoError(t, files_service.VerifyBranchProtection(t.Context(), repo, gitRepo, actor, "master", []string{"README.md"}))
				blob, err := temporary.HashObjectAndWrite(t.Context(), strings.NewReader("current native rule\n"))
				require.NoError(t, err)
				require.NoError(t, temporary.AddObjectToIndex(t.Context(), "100644", blob, "README.md"))
				tree, err := temporary.WriteTree(t.Context())
				require.NoError(t, err)
				parent := old
				if variant == "force" {
					parent = ""
				}
				commit, err := temporary.CommitTree(t.Context(), &files_service.CommitTreeUserOptions{DoerUser: actor, TreeHash: tree, ParentCommitID: parent, CommitMessage: "native rule snapshot"})
				require.NoError(t, err)
				switch variant {
				case "push":
					rule.CanPush = false
					_, err = db.GetEngine(t.Context()).ID(rule.ID).Cols("can_push").Update(rule)
				case "file":
					rule.ProtectedFilePatterns = "README.md"
					_, err = db.GetEngine(t.Context()).ID(rule.ID).Cols("protected_file_patterns").Update(rule)
				case "force":
					rule.ForcePushAllowlistUserIDs = nil
					_, err = db.GetEngine(t.Context()).ID(rule.ID).Cols("force_push_allowlist_user_i_ds").Update(rule)
				}
				require.NoError(t, err)
				err = temporary.Push(audit.WithOrigin(t.Context(), audit_model.OriginUI), actor, commit, "master", variant == "force")
				after, refErr := gitRepo.GetBranchCommitID(t.Context(), "master")
				require.NoError(t, refErr)
				assert.Equal(t, old, after)
				var denied *authz_service.ExecutionError
				require.ErrorAs(t, err, &denied)
				require.Equal(t, 403, denied.Status)
				require.Equal(t, "native_visibility_denied", denied.Reason)
				unittest.AssertNotExistsBean(t, &authz_model.DecisionRecord{ActorID: actor.ID, DecisionMode: "enforce", AuthorizationDecision: "allow"})
			})
		})
	}
}
