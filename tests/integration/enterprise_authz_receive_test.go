// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/private"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzReceiveHookStagesAndTerminal(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, true)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		master := unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: 1, Name: "master"})
		other := unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: 1, Name: "branch2"})
		ticket := authz_service.NewHookOperationTicket(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: repo, Credential: authz_service.CredentialCeiling{Read: true, Write: true, Reference: "access-token:42"}, Action: authz.PushBranch, ConditionContext: authz.ConditionContext{Source: "git_http"}}, nil)
		opts := private.HookOptions{UserID: 2, UserName: "user2", AuthzOperation: ticket, OldCommitIDs: []string{master.CommitID, other.CommitID}, NewCommitIDs: []string{master.CommitID, other.CommitID}, RefFullNames: []git.RefName{git.RefNameFromBranch("master"), git.RefNameFromBranch("branch2")}}
		extra := private.HookPreReceive(t.Context(), "user2", "repo1", opts)
		require.NoError(t, extra.Error)
		require.Equal(t, 2, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.PushBranch, RequestSource: "git_http", NativeOutcome: "unknown", NativeStage: "pre_receive"}))
		pre := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.PushBranch}, unittest.Cond("id = (SELECT MIN(id) FROM enterprise_authz_decision)"))
		// post 只包含已更新的 ref；另一条不能因为 pre 通过而变成成功。
		opts.OldCommitIDs = opts.OldCommitIDs[:1]
		opts.NewCommitIDs = opts.NewCommitIDs[:1]
		opts.RefFullNames = opts.RefFullNames[:1]
		_, extra = private.HookPostReceive(t.Context(), "user2", "repo1", opts)
		require.NoError(t, extra.Error)
		require.Equal(t, 1, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.PushBranch, NativeOutcome: "success", NativeStage: "transport"}))
		require.Equal(t, 1, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.PushBranch, NativeOutcome: "unknown"}))
		terminal := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ID: pre.ID})
		require.Equal(t, pre.SnapshotJSON, terminal.SnapshotJSON)
		event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, unittest.Cond("metadata LIKE ?", "%"+terminal.ObservationID+"%"))
		require.Equal(t, "success", audit_model.DecodeMetadata(event.Metadata)["native_outcome"])
		extra = private.HookPreReceive(t.Context(), "user2", "repo1", opts)
		require.NoError(t, extra.Error)
		require.Equal(t, 2, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.PushBranch}))
		pending := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.PushBranch, NativeOutcome: "unknown"})
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branch_protections", &api.BranchProtection{RuleName: "branch2", EnablePush: false}).AddTokenAuth(token), 201)
		opts.OldCommitIDs = []string{other.CommitID}
		opts.NewCommitIDs = []string{other.CommitID}
		opts.RefFullNames = []git.RefName{git.RefNameFromBranch("branch2")}
		extra = private.HookPreReceive(t.Context(), "user2", "repo1", opts)
		require.Error(t, extra.Error)
		require.Equal(t, 2, unittest.GetCount(t, &authz_model.DecisionRecord{RequestSource: "git_http"}))
		refused := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ID: pending.ID})
		require.Equal(t, "denied", refused.NativeOutcome)
		require.Equal(t, pending.SnapshotJSON, refused.SnapshotJSON)
		require.Equal(t, pending.Action, refused.Action)
		response := session.MakeRequest(t, NewRequest(t, "GET", "/api/v1/repos/user2/repo1/enterprise/authz/decisions").AddTokenAuth(token), http.StatusOK)
		results := DecodeJSON(t, response, []api.EnterpriseAuthzDecision{})
		require.NotEmpty(t, results)
		response = session.MakeRequest(t, NewRequestf(t, "GET", "/api/v1/repos/user2/repo1/enterprise/authz/decisions/%d", terminal.ID).AddTokenAuth(token), http.StatusOK)
		detail := DecodeJSON(t, response, api.EnterpriseAuthzDecision{})
		require.Equal(t, terminal.ObservationID, detail.ObservationID)
	})
}

func TestEnterpriseAuthzReceiveActualGitHTTPAndSSHPush(t *testing.T) {
	for _, ssh := range []bool{false, true} {
		t.Run(fmt.Sprintf("ssh_%t", ssh), func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, u *url.URL) {
				defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
				defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
				run := func(cloneURL *url.URL) {
					setting.EnterpriseAuthz.Enabled = false
					work := filepath.Join(t.TempDir(), "push")
					doGitClone(work, cloneURL)(t)
					for _, enabled := range []bool{false, true} {
						setting.EnterpriseAuthz.Enabled = enabled
						before := unittest.GetCount(t, &authz_model.DecisionRecord{})
						branch := fmt.Sprintf("shadow-protocol-%t", enabled)
						_, _, err := gitcmd.NewCommand("push", "origin").AddDynamicArguments("HEAD:refs/heads/" + branch).WithDir(work).RunStdString(t.Context())
						require.NoError(t, err)
						_, _, err = gitcmd.NewCommand().AddOptionValues("-c", "user.name=Shadow Test").AddOptionValues("-c", "user.email=shadow@example.invalid").AddArguments("commit", "--allow-empty", "-m", "shadow protocol update").WithDir(work).RunStdString(t.Context())
						require.NoError(t, err)
						_, _, err = gitcmd.NewCommand("push", "origin").AddDynamicArguments("HEAD:refs/heads/" + branch).WithDir(work).RunStdString(t.Context())
						require.NoError(t, err)
						if enabled {
							require.Equal(t, before+2, unittest.GetCount(t, &authz_model.DecisionRecord{}))
							source := "git_http"
							if ssh {
								source = "ssh"
							}
							created := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: authz.CreateBranch, RequestSource: source, NativeOutcome: "success", NativeStage: "transport"})
							pushed := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: authz.PushBranch, RequestSource: source, NativeOutcome: "success", NativeStage: "transport"})
							require.NotEqual(t, created.OperationID, pushed.OperationID)
						} else {
							require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
						}
						before = unittest.GetCount(t, &authz_model.DecisionRecord{})
						var lastID int64
						if enabled {
							lastID = unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)")).ID
						}
						a, b := branch+"-multi-a", branch+"-multi-b"
						_, _, err = gitcmd.NewCommand("push", "origin").AddDynamicArguments("HEAD:refs/heads/"+a, "HEAD:refs/heads/"+b, "HEAD:refs/tags/"+branch).WithDir(work).RunStdString(t.Context())
						require.NoError(t, err)
						if enabled {
							require.Equal(t, before+2, unittest.GetCount(t, &authz_model.DecisionRecord{}))
							var records []authz_model.DecisionRecord
							require.NoError(t, db.GetEngine(t.Context()).Where("id > ? AND action = ?", lastID, authz.CreateBranch).Find(&records))
							require.Len(t, records, 2)
							require.Equal(t, records[0].OperationID, records[1].OperationID)
							require.NotEqual(t, records[0].ObservationID, records[1].ObservationID)
						} else {
							require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
						}
						before = unittest.GetCount(t, &authz_model.DecisionRecord{})
						_, _, err = gitcmd.NewCommand("push", "origin", "--delete").AddDynamicArguments(a, b).WithDir(work).RunStdString(t.Context())
						require.NoError(t, err)
						if enabled {
							require.Equal(t, before+2, unittest.GetCount(t, &authz_model.DecisionRecord{}))
						} else {
							require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
						}
						before = unittest.GetCount(t, &authz_model.DecisionRecord{})
						_, _, err = gitcmd.NewCommand("push", "origin", "--delete", "master").WithDir(work).RunStdString(t.Context())
						require.Error(t, err)
						if enabled {
							require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
							unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 2, RepoID: 1, Action: authz.PushBranch, CandidateDecision: "allow", NativeOutcome: "denied", NativeStage: "pre_receive"}, unittest.Cond("id = (SELECT MAX(id) FROM enterprise_authz_decision)"))
						} else {
							require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
						}
					}
				}
				if ssh {
					withKeyFile(t, "shadow-ssh-push", func(keyFile string) {
						context := NewAPITestContext(t, "user2", "repo1", auth_model.AccessTokenScopeWriteUser)
						doAPICreateUserKey(context, "shadow-ssh-push", keyFile, func(*testing.T, api.PublicKey) {})(t)
						run(createSSHUrl("user2/repo1.git", u))
					})
				} else {
					cloneURL := u.JoinPath("user2", "repo1.git")
					cloneURL.User = url.UserPassword("user2", userPassword)
					run(cloneURL)
				}
			})
		})
	}
}

func TestEnterpriseAuthzAGitCreatesOnlyRealPullRequest(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("shadow_%t", enabled), func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, u *url.URL) {
				defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, enabled)()
				defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
				work := t.TempDir()
				u.Path = "user2/repo1.git"
				u.User = url.UserPassword("user4", userPassword)
				doGitClone(work, u)(t)
				doGitCheckoutWriteFileCommit(localGitAddCommitOptions{LocalRepoPath: work, CheckoutBranch: "master", TreeFilePath: "agit-private-path.txt", TreeFileContent: "SENSITIVE-agit-content"})(t)
				before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.CreatePullRequest})
				_, _, err := gitcmd.NewCommand("push", "origin", "HEAD:refs/for/master", "-o").AddDynamicArguments("topic=shadow-agit-topic").WithDir(work).RunStdString(t.Context())
				require.NoError(t, err)
				repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
				require.Equal(t, 4, repo.NumPulls)
				if enabled {
					require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.CreatePullRequest}))
					record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 1, Action: authz.CreatePullRequest, RequestSource: "git_http", CandidateDecision: "deny", NativeOutcome: "success"})
					require.NotContains(t, record.SnapshotJSON, "agit-private")
					require.NotContains(t, record.SnapshotJSON, "SENSITIVE-agit")
				} else {
					require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.CreatePullRequest}))
				}
				before = unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.CreatePullRequest})
				doGitCheckoutWriteFileCommit(localGitAddCommitOptions{LocalRepoPath: work, CheckoutBranch: "master", TreeFilePath: "agit-private-path.txt", TreeFileContent: "updated content"})(t)
				_, _, err = gitcmd.NewCommand("push", "origin", "HEAD:refs/for/master", "-o").AddDynamicArguments("topic=shadow-agit-topic").WithDir(work).RunStdString(t.Context())
				require.NoError(t, err)
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.CreatePullRequest}))
				unittest.AssertCount(t, &authz_model.DecisionRecord{Action: authz.PushBranch}, 0)
				unittest.AssertCount(t, &authz_model.DecisionRecord{Action: authz.CreateBranch}, 0)
			})
		})
	}
}

func TestEnterpriseAuthzAGitGuardIsObservedWithoutBranchPush(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, _ *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		master := unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: 1, Name: "master"})
		_, err := db.Exec(t.Context(), "DELETE FROM repo_unit WHERE repo_id = 1 AND type = ?", unit.TypePullRequests)
		require.NoError(t, err)
		for _, enabled := range []bool{false, true} {
			setting.EnterpriseAuthz.Enabled = enabled
			ticket := authz_service.NewHookOperationTicket(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: repo, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, Action: authz.CreatePullRequest, ConditionContext: authz.ConditionContext{Source: "ssh"}}, nil)
			before := unittest.GetCount(t, &authz_model.DecisionRecord{})
			extra := private.HookPreReceive(t.Context(), "user2", "repo1", private.HookOptions{UserID: 4, UserName: "user4", AuthzOperation: ticket, OldCommitIDs: []string{strings.Repeat("0", 40)}, NewCommitIDs: []string{master.CommitID}, RefFullNames: []git.RefName{"refs/for/master/private-topic"}})
			require.Error(t, extra.Error)
			if enabled {
				require.Equal(t, before+1, unittest.GetCount(t, &authz_model.DecisionRecord{}))
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 1, Action: authz.CreatePullRequest, RequestSource: "ssh", NativeOutcome: "denied", NativeStage: "pre_receive"})
				require.NotContains(t, record.SnapshotJSON, "private-topic")
			} else {
				require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
			}
		}
		unittest.AssertCount(t, &authz_model.DecisionRecord{Action: authz.PushBranch}, 0)
	})
}

func TestEnterpriseAuthzBranchEditorReceiveEvidenceFaults(t *testing.T) {
	onGiteaRun(t, func(t *testing.T, u *url.URL) {
		defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, false)()
		defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		func() {
			cloneURL := u.JoinPath("user2", "repo1.git")
			cloneURL.User = url.UserPassword("user2", userPassword)
			work := filepath.Join(t.TempDir(), "fault-push")
			doGitClone(work, cloneURL)(t)
			for tableIndex, table := range []string{"enterprise_subject_role_binding", "enterprise_authz_decision", "audit_event"} {
				t.Run(table, func(t *testing.T) {
					before := unittest.GetCount(t, &authz_model.DecisionRecord{})
					_, err := db.Exec(t.Context(), "ALTER TABLE "+table+" RENAME TO authz_branch_fault")
					require.NoError(t, err)
					func() {
						defer func() {
							_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE authz_branch_fault RENAME TO "+table)
							require.NoError(t, err)
						}()
						for _, enabled := range []bool{false, true} {
							setting.EnterpriseAuthz.Enabled = enabled
							prefix := fmt.Sprintf("fault-%d-%t", tableIndex, enabled)
							MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/branches", api.CreateBranchRepoOption{BranchName: prefix}).AddTokenAuth(token), http.StatusCreated)
							session.MakeRequest(t, NewRequestWithValues(t, "POST", "/user2/repo1/_new/master/", map[string]string{"tree_path": prefix + ".txt", "content": "SENSITIVE-editor-fault", "commit_choice": "direct", "last_commit": ""}), http.StatusOK)
							doGitCheckoutWriteFileCommit(localGitAddCommitOptions{LocalRepoPath: work, CheckoutBranch: "master", TreeFilePath: prefix + ".txt", TreeFileContent: "SENSITIVE-receive-fault"})(t)
							_, _, err := gitcmd.NewCommand("push", "origin").AddDynamicArguments("HEAD:refs/heads/" + prefix + "-receive").WithDir(work).RunStdString(t.Context())
							require.NoError(t, err)
							_, _, err = gitcmd.NewCommand("push", "origin", "HEAD:refs/for/master", "-o").AddDynamicArguments("topic=" + prefix).WithDir(work).RunStdString(t.Context())
							require.NoError(t, err)
						}
					}()
					setting.EnterpriseAuthz.Enabled = false
					response := session.MakeRequest(t, NewRequest(t, "GET", fmt.Sprintf("/user2/repo1/raw/branch/master/fault-%d-true.txt", tableIndex)), http.StatusOK)
					require.Equal(t, "SENSITIVE-editor-fault", response.Body.String())
					if table == "enterprise_subject_role_binding" {
						require.Equal(t, before+4, unittest.GetCount(t, &authz_model.DecisionRecord{}))
						require.Equal(t, 4, unittest.GetCount(t, &authz_model.DecisionRecord{CandidateDecision: "error", NativeOutcome: "success"}))
					} else {
						require.Equal(t, before, unittest.GetCount(t, &authz_model.DecisionRecord{}))
					}
					unittest.AssertExistsAndLoadBean(t, &git_model.Branch{RepoID: 1, Name: fmt.Sprintf("fault-%d-true-receive", tableIndex)})
				})
			}
		}()
	})
}

func TestEnterpriseAuthzAGitSSHPullRequest(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("shadow_%t", enabled), func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, u *url.URL) {
				defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, enabled)()
				defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
				withKeyFile(t, "shadow-agit", func(keyFile string) {
					apiContext := NewAPITestContext(t, "user4", "repo1", auth_model.AccessTokenScopeWriteUser)
					doAPICreateUserKey(apiContext, "shadow-agit", keyFile, func(*testing.T, api.PublicKey) {})(t)
					work := t.TempDir()
					doGitClone(work, createSSHUrl("user2/repo1.git", u))(t)
					doGitCheckoutWriteFileCommit(localGitAddCommitOptions{LocalRepoPath: work, CheckoutBranch: "master", TreeFilePath: "private-agit-ssh.txt", TreeFileContent: "SENSITIVE-agit-ssh"})(t)
					before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.CreatePullRequest})
					_, _, err := gitcmd.NewCommand("push", "origin", "HEAD:refs/for/master", "-o", "topic=shadow-agit-ssh").WithDir(work).RunStdString(t.Context())
					require.NoError(t, err)
					require.Equal(t, 4, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}).NumPulls)
					expected := before
					if enabled {
						expected++
					}
					require.Equal(t, expected, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.CreatePullRequest}))
					if enabled {
						record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{ActorID: 4, RepoID: 1, Action: authz.CreatePullRequest, RequestSource: "ssh", CandidateDecision: "deny", NativeOutcome: "success"})
						require.NotContains(t, record.SnapshotJSON, "private-agit")
						require.NotContains(t, record.SnapshotJSON, "SENSITIVE-agit")
					}
				})
			})
		})
	}
}
