// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"fmt"
	"net/http"
	"testing"

	auth_model "gitea.dev/models/auth"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/organization"
	"gitea.dev/models/perm"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	repo_service "gitea.dev/services/repository"
	"gitea.dev/tests"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIRepositoryDelete(t *testing.T) {
	defer tests.PrepareTestEnv(t)()

	defer test.MockVariableValue(&setting.EnterpriseAuthz.Enabled)()
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	for _, enabled := range []bool{false, true} {
		setting.EnterpriseAuthz.Enabled = enabled
		t.Run(fmt.Sprintf("AdminNoPermToDeleteRepo/%t", enabled), func(t *testing.T) {
			owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			org := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
			doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 28})
			teams, err := organization.GetUserOrgTeams(t.Context(), org.ID, doer.ID)
			require.NoError(t, err)
			require.Len(t, teams, 1)

			team := teams[0]
			assert.Equal(t, perm.AccessModeAdmin, team.AccessMode)
			assert.True(t, team.CanCreateOrgRepo)
			token := getUserToken(t, doer.Name, auth_model.AccessTokenScopeWriteRepository)

			unrelatedRepo, err := repo_service.CreateRepository(t.Context(), owner, org, repo_service.CreateRepoOptions{Name: fmt.Sprintf("unrelated-admin-team-%t", enabled)})
			require.NoError(t, err)

			targetRepo, err := repo_service.CreateRepository(t.Context(), owner, org, repo_service.CreateRepoOptions{Name: fmt.Sprintf("target-admin-team-%t", enabled)})
			require.NoError(t, err)
			require.NoError(t, repo_service.TeamAddRepository(t.Context(), team, targetRepo))

			req := NewRequest(t, "DELETE", "/api/v1/repos/"+unrelatedRepo.FullName()).AddTokenAuth(token)
			MakeRequest(t, req, http.StatusForbidden)
			unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: unrelatedRepo.ID})

			req = NewRequest(t, "DELETE", "/api/v1/repos/"+targetRepo.FullName()).AddTokenAuth(token)
			MakeRequest(t, req, http.StatusNoContent)
			unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: targetRepo.ID})
			if enabled {
				unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: unrelatedRepo.ID, ActorID: doer.ID, Action: authz.Delete, NativeOutcome: "denied", RequestSource: "api"})
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: targetRepo.ID, ActorID: doer.ID, Action: authz.Delete, NativeOutcome: "success", RequestSource: "api"})
				require.Equal(t, "deny", record.CandidateDecision)
			} else {
				unittest.AssertCount(t, &authz_model.DecisionRecord{RepoID: targetRepo.ID}, 0)
				unittest.AssertCount(t, &authz_model.DecisionRecord{RepoID: unrelatedRepo.ID}, 0)
			}
		})
	}
}
