// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	deploykey_model "gitea.dev/models/deploykey"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/perm"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/private"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzShadowGitHTTPUploadPack(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	session := loginUser(t, "user2")
	token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadRepository)
	limitedToken := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeReadUser)
	deploy, err := deploykey_model.AddDeployKeyToken(t.Context(), 1, "shadow-read", perm.AccessModeRead)
	require.NoError(t, err)
	for _, credential := range []string{"anonymous", "password", "pat", "deploy", "user_only_pat"} {
		t.Run(credential, func(t *testing.T) {
			request := func() *RequestWrapper {
				req := NewRequestWithBody(t, "POST", "/user2/repo1/git-upload-pack", strings.NewReader("0000")).SetHeader("Content-Type", "application/x-git-upload-pack-request")
				switch credential {
				case "password":
					req.AddBasicAuth("user2", userPassword)
				case "pat":
					req.AddBasicAuth(token, "x-oauth-basic")
				case "deploy":
					req.AddBasicAuth("deploy-token", deploy.Token)
				case "user_only_pat":
					req.AddBasicAuth(limitedToken, "x-oauth-basic")
				}
				return req
			}
			setting.EnterpriseAuthz.Enabled = false
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			baseline := MakeRequest(t, request(), 200)
			require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			setting.EnterpriseAuthz.Enabled = true
			response := MakeRequest(t, request(), 200)
			require.Equal(t, baseline.Body.String(), response.Body.String())
			require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.Clone, RequestSource: "git_http", NativeOutcome: "success", NativeStage: "transport"}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
			event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, unittest.Cond("metadata LIKE ?", "%"+record.ObservationID+"%"))
			if credential == "user_only_pat" {
				require.Equal(t, "deny", record.CandidateDecision)
				require.Contains(t, record.SnapshotJSON, `"read":false`)
				require.NotContains(t, record.SnapshotJSON, `"native_actions":["repo.clone"`)
			}
			if credential == "pat" || credential == "deploy" {
				require.NotEmpty(t, event.ActorCredential)
			}
			require.NotContains(t, record.SnapshotJSON, token)
			require.NotContains(t, record.SnapshotJSON, deploy.Token)
		})
	}
	before := unittest.GetCount(t, &authz_model.DecisionRecord{})
	MakeRequest(t, NewRequest(t, "GET", "/user2/repo1/info/refs?service=git-upload-pack"), 200)
	MakeRequest(t, NewRequest(t, "GET", "/user2/repo2/info/refs?service=git-upload-pack"), 401)
	require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
}

func TestEnterpriseAuthzShadowSSHUploadPackGuard(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		setting.EnterpriseAuthz.Enabled = false
		before := unittest.GetCount(t, &authz_model.DecisionRecord{})
		baseline, extra := private.ServCommand(t.Context(), 1, "user2", "repo1", perm.AccessModeRead, "git-upload-pack", "")
		require.NoError(t, extra.Error)
		require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
		setting.EnterpriseAuthz.Enabled = true
		response, extra := private.ServCommand(t.Context(), 1, "user2", "repo1", perm.AccessModeRead, "git-upload-pack", "")
		require.NoError(t, extra.Error)
		require.Equal(t, baseline, response)
		require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
		record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: authz.Clone, RequestSource: "ssh", NativeOutcome: "unknown", NativeStage: "authorization"})
		event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, unittest.Cond("metadata LIKE ?", "%"+record.ObservationID+"%"))
		require.NotEmpty(t, event.ActorCredential)
		before = unittest.GetCount(t, &authz_model.DecisionRecord{})
		content := "sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBGXEEzWmm1dxb+57RoK5KVCL0w2eNv9cqJX2AGGVlkFsVDhOXHzsadS3LTK4VlEbbrDMJdoti9yM8vclA8IeRacAAAAEc3NoOg== nocomment"
		deploy, err := deploykey_model.AddDeployKeySSH(t.Context(), 19, "shadow-deploy", content, perm.AccessModeRead)
		require.NoError(t, err)
		_, extra = private.ServCommand(t.Context(), deploy.KeyID, "user15", "big_test_private_1", perm.AccessModeRead, "git-upload-pack", "")
		require.NoError(t, extra.Error)
		require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
		deployRecord := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 19, Action: authz.Clone, RequestSource: "ssh", NativeOutcome: "unknown", NativeStage: "authorization"})
		deployEvent := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, unittest.Cond("metadata LIKE ?", "%"+deployRecord.ObservationID+"%"))
		require.Contains(t, deployEvent.ActorCredential, "deploy-key:")
		_, extra = private.ServCommand(t.Context(), deploy.KeyID, "user15", "big_test_private_2", perm.AccessModeRead, "git-upload-pack", "")
		require.Error(t, extra.Error)
		_, extra = private.ServCommand(t.Context(), 1, "user15", "big_test_private_1", perm.AccessModeRead, "git-upload-pack", "")
		require.Error(t, extra.Error)
		require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
	})
}

func TestEnterpriseAuthzShadowGitHTTPActualCloneAndFetch(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.Clone})
		u = u.JoinPath("user2", "repo1.git")
		work := filepath.Join(t.TempDir(), "clone")
		doGitClone(work, u)(t)
		_, _, err := gitcmd.NewCommand("fetch", "--depth=1", "origin").WithDir(work).RunStdString(t.Context())
		require.NoError(t, err)
		require.Greater(t, unittest.GetCount(t, &authz_model.DecisionRecord{RepoID: 1, Action: authz.Clone, RequestSource: "git_http", NativeOutcome: "success", NativeStage: "transport"}), before)
	})
}

func TestEnterpriseAuthzShadowGitReadEvidenceFaults(t *testing.T) {
	for _, table := range []string{"enterprise_subject_role_binding", "enterprise_authz_decision", "audit_event"} {
		t.Run(table, func(t *testing.T) {
			defer tests.PrepareTestEnv(t)()
			defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
			defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
			request := func() *RequestWrapper {
				return NewRequestWithBody(t, "POST", "/user2/repo1/git-upload-pack", strings.NewReader("0000")).SetHeader("Content-Type", "application/x-git-upload-pack-request").AddBasicAuth("user2", userPassword)
			}
			setting.EnterpriseAuthz.Enabled = false
			baseline := MakeRequest(t, request(), 200)
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			auditBefore := unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
			_, err := db.Exec(t.Context(), "ALTER TABLE "+table+" RENAME TO authz_git_read_fault")
			require.NoError(t, err)
			defer func() {
				_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE authz_git_read_fault RENAME TO "+table)
				require.NoError(t, err)
			}()
			setting.EnterpriseAuthz.Enabled = true
			response := MakeRequest(t, request(), 200)
			require.Equal(t, baseline.Body.String(), response.Body.String())
			if table == "enterprise_subject_role_binding" {
				require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				require.Equal(t, auditBefore+1, unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}))
				unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.Clone, NativeOutcome: "success", CandidateDecision: "error"})
			} else if table == "enterprise_authz_decision" {
				require.Equal(t, auditBefore, unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}))
			} else {
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			}
		})
	}
}

func TestEnterpriseAuthzShadowSSHActualCloneAndFetch(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		apiContext := NewAPITestContext(t, "user2", "repo1", auth_model.AccessTokenScopeWriteUser)
		withKeyFile(t, "shadow-ssh-clone", func(keyFile string) {
			var keyID int64
			doAPICreateUserKey(apiContext, "shadow-ssh-clone", keyFile, func(t *testing.T, key api.PublicKey) { keyID = key.ID })(t)
			require.Positive(t, keyID)
			cloneURL := createSSHUrl("user2/repo1.git", u)
			for _, enabled := range []bool{false, true} {
				setting.EnterpriseAuthz.Enabled = enabled
				before := unittest.GetCount(t, &authz_model.DecisionRecord{})
				work := filepath.Join(t.TempDir(), "clone")
				doGitClone(work, cloneURL)(t)
				_, _, err := gitcmd.NewCommand("fetch", "--depth=1", "origin").WithDir(work).RunStdString(t.Context())
				require.NoError(t, err)
				if enabled {
					require.Equal(t, before+2, unittest.GetCount(t, &authz_model.DecisionRecord{}))
					require.Equal(t, 2, unittest.GetCount(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: authz.Clone, RequestSource: "ssh", NativeOutcome: "unknown", NativeStage: "authorization"}))
				} else {
					require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				}
			}
			doAPIDeleteUserKey(apiContext, keyID)(t)
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			doGitCloneFail(cloneURL)(t)
			require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
		})
	})
}

func TestEnterpriseAuthzShadowSSHReadEvidenceFaults(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		for _, table := range []string{"enterprise_subject_role_binding", "enterprise_authz_decision", "audit_event"} {
			t.Run(table, func(t *testing.T) {
				setting.EnterpriseAuthz.Enabled = false
				baseline, extra := private.ServCommand(t.Context(), 1, "user2", "repo1", perm.AccessModeRead, "git-upload-pack", "")
				require.NoError(t, extra.Error)
				before := unittest.GetCount(t, &authz_model.DecisionRecord{})
				auditBefore := unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
				_, err := db.Exec(t.Context(), "ALTER TABLE "+table+" RENAME TO authz_ssh_read_fault")
				require.NoError(t, err)
				renamed := true
				restore := func() {
					if renamed {
						_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE authz_ssh_read_fault RENAME TO "+table)
						require.NoError(t, err)
						renamed = false
					}
				}
				defer restore()
				setting.EnterpriseAuthz.Enabled = true
				response, extra := private.ServCommand(t.Context(), 1, "user2", "repo1", perm.AccessModeRead, "git-upload-pack", "")
				require.NoError(t, extra.Error)
				require.Equal(t, baseline, response)
				restore()
				added := 0
				if table == "enterprise_subject_role_binding" {
					added = 1
				}
				require.Equal(t, before+added, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				require.Equal(t, auditBefore+added, unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}))
				if added > 0 {
					unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.Clone, CandidateDecision: "error", NativeOutcome: "unknown", NativeStage: "authorization"})
				}
			})
		}
	})
}
