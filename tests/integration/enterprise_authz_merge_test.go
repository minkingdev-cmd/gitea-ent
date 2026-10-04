// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"testing"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	pull_model "gitea.dev/models/pull"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzShadowMergePrechecks(t *testing.T) {
	for _, web := range []bool{false, true} {
		t.Run(fmt.Sprintf("web=%t", web), func(t *testing.T) {
			testShadowPullModes(t, func(t *testing.T, check shadowPullCheck) {
				session := loginUser(t, "user2")
				token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
				require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: 1, RuleName: "master", CanPush: true, EnableStatusCheck: true, StatusCheckContexts: []string{"missing-check"}, BlockAdminMergeOverride: true}))
				for _, force := range []bool{false, true} {
					req := NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/merge", map[string]any{"do": "merge", "force_merge": force}).AddTokenAuth(token)
					status := 405
					if web {
						req = NewRequestWithValues(t, "POST", "/user2/repo1/pulls/3/merge", map[string]string{"do": "merge", "force_merge": strconv.FormatBool(force)})
						status = 400
					}
					check(strconv.FormatBool(force), req, session, status, authz.MergePullRequest, "denied", 2, 1)
					pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
					require.False(t, pr.HasMerged)
				}
			})
		})
	}
}

func TestEnterpriseAuthzShadowMergeExistingNativeFlows(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("shadow=%t", enabled), func(t *testing.T) {
			defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, enabled)()
			defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
			for _, flow := range []struct {
				name, source string
				run          func(*testing.T)
				outcomes     []string
			}{
				{"web", "web", TestPullMerge, []string{"success"}},
				{"force", "api", TestPullForceMergeForBypassAllowlistUser, []string{"denied", "success"}},
				{"auto", "auto_merge", TestPullAutoMergeAfterCommitStatusSucceed, []string{"success"}},
			} {
				t.Run(flow.name, func(t *testing.T) {
					flow.run(t)
					var records []*authz_model.DecisionRecord
					require.NoError(t, db.GetEngine(t.Context()).Where("action = ?", authz.MergePullRequest).OrderBy("id").Find(&records))
					if !enabled {
						require.Empty(t, records)
						return
					}
					require.Len(t, records, len(flow.outcomes))
					for i, record := range records {
						require.Equal(t, flow.source, record.RequestSource)
						require.Equal(t, flow.outcomes[i], record.NativeOutcome)
						require.Equal(t, "allow", record.CandidateDecision)
						require.Equal(t, int64(1), record.RepoID)
						require.NotContains(t, record.SnapshotJSON, "Hello, World")
						unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, unittest.Cond("metadata LIKE ?", "%"+record.ObservationID+"%"))
					}
					if len(records) == 2 {
						require.NotEqual(t, records[0].OperationID, records[1].OperationID)
					}
				})
			}
		})
	}
}

func TestEnterpriseAuthzShadowMergeNativeWhitelist(t *testing.T) {
	testShadowPullModes(t, func(t *testing.T, check shadowPullCheck) {
		onGiteaRun(t, func(t *testing.T, _ *url.URL) {
			session := loginUser(t, "user4")
			token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
			require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: 1, RuleName: "master", CanPush: true, EnableMergeWhitelist: true, MergeWhitelistUserIDs: []int64{4}}))
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
			prUnit, err := repo.GetUnit(t.Context(), unit.TypePullRequests)
			require.NoError(t, err)
			prUnit.PullRequestsConfig().AllowManualMerge = true
			require.NoError(t, repo_model.UpdateRepoUnitConfig(t.Context(), prUnit))
			gitRepo, err := git.OpenRepository(t.Context(), repo)
			require.NoError(t, err)
			defer gitRepo.Close()
			commitID, err := gitRepo.GetBranchCommitID(t.Context(), "master")
			require.NoError(t, err)

			check("whitelisted-read-user", NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/merge", map[string]any{"do": "manually-merged", "merge_commit_id": commitID}).AddTokenAuth(token), session, 200, authz.MergePullRequest, "success", 4, 1)
			pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
			require.True(t, pr.HasMerged)
			require.Equal(t, int64(4), pr.MergerID)
			if setting.EnterpriseAuthz.Enabled {
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.MergePullRequest})
				require.Equal(t, "deny", record.CandidateDecision)
				event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}, unittest.Cond("metadata LIKE ?", "%"+record.ObservationID+"%"))
				require.Contains(t, event.Metadata, `"mismatch":true`)
			}
		})
	})
}

func TestEnterpriseAuthzShadowMergeSchedulingAndServiceFailure(t *testing.T) {
	testShadowPullModes(t, func(t *testing.T, check shadowPullCheck) {
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		const endpoint = "/api/v1/repos/user2/repo1/pulls/3/merge"
		check("invalid-style", NewRequestWithJSON(t, "POST", endpoint, map[string]any{"do": "invalid"}).AddTokenAuth(token), session, 422, authz.MergePullRequest, "failed", 2, 1)
		repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
		prUnit, err := repo.GetUnit(t.Context(), unit.TypePullRequests)
		require.NoError(t, err)
		prUnit.PullRequestsConfig().AllowMerge = false
		require.NoError(t, repo_model.UpdateRepoUnitConfig(t.Context(), prUnit))
		check("disabled-style", NewRequestWithJSON(t, "POST", endpoint, map[string]any{"do": "merge"}).AddTokenAuth(token), session, 405, authz.MergePullRequest, "failed", 2, 1)
		prUnit.PullRequestsConfig().AllowMerge = true
		require.NoError(t, repo_model.UpdateRepoUnitConfig(t.Context(), prUnit))

		require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: 1, RuleName: "master", CanPush: true, EnableStatusCheck: true, StatusCheckContexts: []string{"missing-check"}}))
		check("queued", NewRequestWithJSON(t, "POST", endpoint, map[string]any{"do": "merge", "merge_when_checks_succeed": true}).AddTokenAuth(token), session, 201, authz.MergePullRequest, "unknown", 2, 1)
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
		require.False(t, pr.HasMerged)
		unittest.AssertExistsAndLoadBean(t, &pull_model.AutoMerge{PullID: pr.ID, DoerID: 2})
	})
}

func TestEnterpriseAuthzShadowMergeEvidenceFaults(t *testing.T) {
	for _, denied := range []bool{false, true} {
		for _, table := range []string{"enterprise_subject_role_binding", "enterprise_authz_decision", "audit_event"} {
			t.Run(fmt.Sprintf("denied=%t/%s", denied, table), func(t *testing.T) {
				var baseline string
				for _, enabled := range []bool{false, true} {
					t.Run(fmt.Sprintf("shadow=%t", enabled), func(t *testing.T) {
						defer prepareShadowPullEnv(t)()
						defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled, enabled)()
						defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
						session := loginUser(t, "user2")
						token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
						repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
						prUnit, err := repo.GetUnit(t.Context(), unit.TypePullRequests)
						require.NoError(t, err)
						prUnit.PullRequestsConfig().AllowManualMerge = true
						require.NoError(t, repo_model.UpdateRepoUnitConfig(t.Context(), prUnit))
						gitRepo, err := git.OpenRepository(t.Context(), repo)
						require.NoError(t, err)
						commitID, err := gitRepo.GetBranchCommitID(t.Context(), "master")
						require.NoError(t, err)
						gitRepo.Close()
						style, status := "manually-merged", 200
						if denied {
							style, status = "merge", 405
							require.NoError(t, db.Insert(t.Context(), &git_model.ProtectedBranch{RepoID: 1, RuleName: "master", CanPush: true, EnableStatusCheck: true, StatusCheckContexts: []string{"missing-check"}, BlockAdminMergeOverride: true}))
						}
						before := unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.MergePullRequest})
						auditBefore := unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision})
						renamed := false
						restore := func() {
							if renamed {
								_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE authz_merge_fault RENAME TO "+table)
								require.NoError(t, err)
								renamed = false
							}
						}
						defer restore()
						if enabled {
							_, err := db.Exec(t.Context(), "ALTER TABLE "+table+" RENAME TO authz_merge_fault")
							require.NoError(t, err)
							renamed = true
						}
						response := session.MakeRequest(t, NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/merge", map[string]any{"do": style, "merge_commit_id": commitID, "merge_message_field": shadowPullPrivate}).AddTokenAuth(token), status)
						if !enabled {
							baseline = response.Body.String()
						} else {
							require.Equal(t, baseline, response.Body.String())
						}
						restore()
						pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
						require.Equal(t, !denied, pr.HasMerged)
						added := 0
						if enabled && table == "enterprise_subject_role_binding" {
							added = 1
							record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{Action: authz.MergePullRequest})
							require.Equal(t, "error", record.CandidateDecision)
							require.Equal(t, "policy_read_failed", record.Reason)
							require.NotContains(t, record.SnapshotJSON, shadowPullPrivate)
						}
						require.Equal(t, before+added, unittest.GetCount(t, &authz_model.DecisionRecord{Action: authz.MergePullRequest}))
						require.Equal(t, auditBefore+added, unittest.GetCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDecision}))
					})
				}
			})
		}
	}
}

func TestEnterpriseAuthzShadowMergeArchiveGuards(t *testing.T) {
	testShadowPullModes(t, func(t *testing.T, check shadowPullCheck) {
		session := loginUser(t, "user2")
		token := getTokenForLoggedInUser(t, session, auth_model.AccessTokenScopeWriteRepository)
		_, err := db.Exec(t.Context(), "UPDATE repository SET is_archived = ? WHERE id=1", true)
		require.NoError(t, err)
		check("api-archived", NewRequestWithJSON(t, "POST", "/api/v1/repos/user2/repo1/pulls/3/merge", map[string]any{"do": "merge"}).AddTokenAuth(token), session, 404, authz.MergePullRequest, "denied", 2, 1)
		check("web-archived", NewRequestWithValues(t, "POST", "/user2/repo1/pulls/3/merge", map[string]string{"do": "merge"}), session, 404, authz.MergePullRequest, "denied", 2, 1)
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
		require.False(t, pr.HasMerged)
	})
}
