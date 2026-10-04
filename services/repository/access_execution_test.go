// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/organization"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/services/audit"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func TestAccessTeamFingerprintIsCanonical(t *testing.T) {
	team := &organization.Team{Name: "canonical", OrgID: 3, AccessMode: perm.AccessModeRead, Units: []*organization.TeamUnit{{Type: unit.TypeIssues, AccessMode: perm.AccessModeWrite}, {Type: unit.TypeCode, AccessMode: perm.AccessModeRead}}}
	expected := accessIntent("team-state", struct {
		Name        string
		OrgID       int64
		Mode        int
		IncludesAll bool
		Units       []struct{ Type, Mode int }
	}{team.Name, team.OrgID, int(team.AccessMode), false, []struct{ Type, Mode int }{{int(unit.TypeCode), int(perm.AccessModeRead)}, {int(unit.TypeIssues), int(perm.AccessModeWrite)}}})
	require.Equal(t, expected, teamAccessFingerprint(team))
	team.Units[0], team.Units[1] = team.Units[1], team.Units[0]
	require.Equal(t, expected, teamAccessFingerprint(team))
	team.Units[0].AccessMode = perm.AccessModeWrite
	require.NotEqual(t, expected, teamAccessFingerprint(team))
	team.Units[0].AccessMode = perm.AccessModeRead
	team.Units = append([]*organization.TeamUnit{{Type: unit.TypeCode, AccessMode: perm.AccessModeWrite}}, team.Units...)
	require.Equal(t, expected, teamAccessFingerprint(team))
	team.Units = append(team.Units, &organization.TeamUnit{Type: unit.TypeCode, AccessMode: perm.AccessModeWrite})
	require.NotEqual(t, expected, teamAccessFingerprint(team))
}

func TestAccessCollaborationAdmission(t *testing.T) {
	for _, name := range []string{"disabled", "shadow", "admin-denied", "admin-granted", "owner", "reader-granted", "nil-actor", "remove-denied"} {
		t.Run(name, func(t *testing.T) {
			ctx := enforceLifecycle(t)
			repoID, actorID := int64(32), int64(15)
			if name == "owner" {
				repoID, actorID = 1, 2
			}
			if name == "reader-granted" {
				repoID, actorID = 1, 4
			}
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repoID})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: actorID})
			target := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
			if repoID == 32 {
				_, err := db.GetEngine(ctx).ID(7).Cols("authorize").Update(&organization.Team{AccessMode: perm.AccessModeAdmin})
				require.NoError(t, err)
				require.NoError(t, access_model.RecalculateTeamAccesses(ctx, repo, 0))
			}
			if name == "admin-granted" || name == "reader-granted" {
				grantLifecycleAction(ctx, t, repo, actorID, authz.ManageAccess)
			}
			if name != "nil-actor" {
				ctx = audit.WithDoer(ctx, actor)
			}
			if name == "disabled" {
				setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce = false, false
			}
			if name == "shadow" {
				setting.EnterpriseAuthz.Enforce = false
			}
			if name == "remove-denied" {
				require.NoError(t, db.Insert(ctx, &repo_model.Collaboration{RepoID: repoID, UserID: target.ID, Mode: perm.AccessModeRead}))
			}
			var err error
			if name == "remove-denied" {
				err = DeleteCollaboration(ctx, repo, target)
			} else {
				err = AddOrUpdateCollaborator(ctx, repo, target, perm.AccessModeWrite)
			}
			denied := name == "admin-denied" || name == "reader-granted" || name == "nil-actor" || name == "remove-denied"
			if denied {
				var rejection *authz_service.ExecutionError
				require.ErrorAs(t, err, &rejection)
				require.Equal(t, 403, rejection.Status)
				if name != "remove-denied" {
					unittest.AssertNotExistsBean(t, &repo_model.Collaboration{RepoID: repoID, UserID: target.ID})
				}
				if name == "remove-denied" {
					unittest.AssertExistsAndLoadBean(t, &repo_model.Collaboration{RepoID: repoID, UserID: target.ID})
				}
			} else {
				require.NoError(t, err)
				unittest.AssertExistsAndLoadBean(t, &repo_model.Collaboration{RepoID: repoID, UserID: target.ID, Mode: perm.AccessModeWrite})
			}
			if name == "shadow" {
				row := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repoID, Action: authz.ManageAccess})
				require.Equal(t, "shadow", row.DecisionMode)
				require.Equal(t, "not_enforced", row.AuthorizationDecision)
				require.Equal(t, "deny", row.CandidateDecision)
				require.Equal(t, "success", row.NativeOutcome)
			}
			if name == "admin-denied" || name == "remove-denied" {
				row := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repoID, Action: authz.ManageAccess})
				require.Equal(t, "deny", row.AuthorizationDecision)
				require.False(t, row.ExecutionStarted)
				require.Equal(t, "unknown", row.NativeOutcome)
			}
		})
	}
}

func TestAccessTeamBulkRejectsWithoutPartialWrites(t *testing.T) {
	ctx := enforceLifecycle(t)
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 15})
	ctx = audit.WithDoer(ctx, actor)
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	// 当前原生 Admin 有团队授权变更资格，但没有企业 manage_access。
	require.NoError(t, AddOrUpdateCollaborator(audit.WithDoer(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})), unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3}), actor, perm.AccessModeAdmin))
	_, err := db.GetEngine(ctx).ID(3).Cols("repo_admin_change_team_access").Update(&user_model.User{RepoAdminChangeTeamAccess: true})
	require.NoError(t, err)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	grantLifecycleAction(ctx, t, repo, actor.ID, authz.ManageAccess)
	for _, id := range []int64{5, 32} {
		require.NoError(t, db.Insert(ctx, &repo_model.Collaboration{RepoID: id, UserID: actor.ID, Mode: perm.AccessModeAdmin}))
		require.NoError(t, access_model.RecalculateUserAccess(ctx, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: id}), actor.ID))
	}
	before := unittest.GetCount(t, &organization.TeamRepo{TeamID: team.ID})
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, AddAllRepositoriesToTeam(ctx, team), &rejection)
	require.Equal(t, 403, rejection.Status)
	require.Equal(t, before, unittest.GetCount(t, &organization.TeamRepo{TeamID: team.ID}))
	require.Equal(t, 1, unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: team.ID}).NumRepos)
	rows := make([]authz_model.DecisionRecord, 0)
	require.NoError(t, db.GetEngine(ctx).Where("action = ? AND authorization_decision = ?", authz.ManageAccess, "deny").Find(&rows))
	require.GreaterOrEqual(t, len(rows), 2)
	for _, row := range rows {
		require.False(t, row.ExecutionStarted)
		require.Equal(t, "unknown", row.NativeOutcome)
	}
}

func TestAccessInitializationDoesNotRequireExistingRepoGrant(t *testing.T) {
	ctx := enforceLifecycle(t)
	creator := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 15})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	repo := &repo_model.Repository{OwnerID: owner.ID, OwnerName: owner.Name, Name: "access-initialization", LowerName: "access-initialization", IsPrivate: true}
	require.NoError(t, db.WithTx(ctx, func(tx context.Context) error { return createRepositoryInDB(tx, creator, owner, repo, false) }))
	unittest.AssertExistsAndLoadBean(t, &repo_model.Collaboration{RepoID: repo.ID, UserID: creator.ID, Mode: perm.AccessModeAdmin})
}

func TestAccessBlockedCleanupHasExactPairAndRequiredAudit(t *testing.T) {
	for _, name := range []string{"valid", "wrong-pair", "wrong-owner", "missing-block", "wrong-doer", "outside-transaction", "audit-failure"} {
		t.Run(name, func(t *testing.T) {
			ctx := enforceLifecycle(t)
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 22})
			collaborator := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 15})
			blockerID, blockeeID := repo.OwnerID, collaborator.ID
			doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: blockerID})
			if name == "wrong-doer" {
				doer = collaborator
			}
			if name == "wrong-owner" {
				repo.OwnerID++
			}
			if name == "wrong-pair" {
				blockeeID = 4
			}
			if name == "audit-failure" {
				_, err := db.Exec(ctx, "ALTER TABLE audit_event RENAME TO access_audit_unavailable")
				require.NoError(t, err)
				defer func() {
					_, err := db.Exec(ctx, "ALTER TABLE access_audit_unavailable RENAME TO audit_event")
					require.NoError(t, err)
				}()
			}
			mutate := func(tx context.Context) error {
				if name != "missing-block" {
					if err := db.Insert(tx, &user_model.Blocking{BlockerID: blockerID, BlockeeID: blockeeID}); err != nil {
						return err
					}
				}
				return DeleteCollaborationBlockedUser(tx, repo, collaborator, doer, blockerID, blockeeID)
			}
			var err error
			if name == "outside-transaction" {
				err = mutate(ctx)
			} else {
				err = db.WithTx(ctx, mutate)
			}
			if name == "valid" {
				require.NoError(t, err)
				unittest.AssertNotExistsBean(t, &repo_model.Collaboration{RepoID: repo.ID, UserID: collaborator.ID})
			} else {
				require.Error(t, err)
				unittest.AssertExistsAndLoadBean(t, &repo_model.Collaboration{RepoID: repo.ID, UserID: collaborator.ID})
			}
		})
	}
}

func TestAccessTeamPreparedScopeCannotBeReused(t *testing.T) {
	ctx := enforceLifecycle(t)
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	ctx = audit.WithDoer(ctx, actor)
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	ctx, finish, err := BeginTeamAccessMutation(ctx, team, "add-all")
	require.NoError(t, err)
	defer finish(nil)
	require.NoError(t, ValidateTeamAccessMutation(ctx, team))
	changed := *team
	changed.Name = "different-team"
	require.Error(t, ValidateTeamAccessMutation(ctx, &changed))
	changed = *team
	changed.AccessMode = perm.AccessModeAdmin
	require.Error(t, ValidateTeamAccessMutation(ctx, &changed))
	changed = *team
	changed.OrgID = 17
	require.Error(t, ValidateTeamAccessMutation(ctx, &changed))
	added := &repo_model.Repository{OwnerID: 3, Name: "concurrent-access", LowerName: "concurrent-access"}
	require.NoError(t, db.Insert(ctx, added))
	require.Error(t, ValidateTeamAccessMutation(ctx, team))
}

func TestAccessFaultsRemainSafeAndEvidenceSurvivesRollback(t *testing.T) {
	for _, name := range []string{"policy-closed", "policy-open", "evidence-closed", "business-failed", "target-read-open"} {
		t.Run(name, func(t *testing.T) {
			ctx := enforceLifecycle(t)
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			target := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
			ctx = audit.WithDoer(ctx, actor)
			setting.EnterpriseAuthz.FailClosedOnError = name != "policy-open" && name != "target-read-open"
			table := "enterprise_subject_role_binding"
			if name == "evidence-closed" {
				table = "audit_event"
			}

			if name == "target-read-open" {
				table = "repository"
			}
			var err error
			if name == "business-failed" {
				_, err = db.Exec(ctx, "CREATE TRIGGER access_insert_failure BEFORE INSERT ON collaboration BEGIN SELECT RAISE(ABORT, 'SENSITIVE-business-error'); END")
				require.NoError(t, err)
				defer func() { _, err := db.Exec(ctx, "DROP TRIGGER access_insert_failure"); require.NoError(t, err) }()
			} else {
				_, err = db.Exec(ctx, "ALTER TABLE "+table+" RENAME TO access_fault_table")
				require.NoError(t, err)
				defer func() {
					_, err := db.Exec(ctx, "ALTER TABLE access_fault_table RENAME TO "+table)
					require.NoError(t, err)
				}()
			}
			err = AddOrUpdateCollaborator(ctx, repo, target, perm.AccessModeRead)
			if name == "policy-open" {
				require.NoError(t, err)
				row := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repo.ID, Action: authz.ManageAccess})
				require.Equal(t, "fallback", row.AuthorizationDecision)
				require.True(t, row.ExecutionStarted)
				require.Equal(t, "success", row.NativeOutcome)
			} else {
				require.Error(t, err)
				if name == "business-failed" {
					row := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repo.ID, Action: authz.ManageAccess})
					require.Equal(t, "allow", row.AuthorizationDecision)
					require.True(t, row.ExecutionStarted)
					require.Equal(t, "failed", row.NativeOutcome)
				} else {
					var rejection *authz_service.ExecutionError
					require.ErrorAs(t, err, &rejection)
					require.Equal(t, 503, rejection.Status)
					unittest.AssertNotExistsBean(t, &repo_model.Collaboration{RepoID: repo.ID, UserID: target.ID})
				}
			}
		})
	}
}

func TestAccessTeamRepositoryLimitIsComplete(t *testing.T) {
	ctx := enforceLifecycle(t)
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	ctx = audit.WithDoer(ctx, actor)
	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	repos := make([]*repo_model.Repository, 1001)
	for i := range repos {
		name := fmt.Sprintf("access-limit-%d", i)
		repos[i] = &repo_model.Repository{OwnerID: 3, Name: name, LowerName: name}
	}
	for start := 0; start < len(repos); start += 25 {
		require.NoError(t, db.Insert(ctx, repos[start:min(start+25, len(repos))]))
	}
	before := unittest.GetCount(t, &organization.TeamRepo{TeamID: team.ID})
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, AddAllRepositoriesToTeam(ctx, team), &rejection)
	require.Equal(t, "context_limit_exceeded", rejection.Reason)
	require.Equal(t, before, unittest.GetCount(t, &organization.TeamRepo{TeamID: team.ID}))
}

func TestAccessCollaborationPreparedScopeCannotBeReused(t *testing.T) {
	for _, change := range []string{"intent", "owner", "actor"} {
		t.Run(change, func(t *testing.T) {
			ctx := enforceLifecycle(t)
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			target := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
			ctx = audit.WithDoer(ctx, actor)
			prepared, finish, err := beginCollaborationMutation(ctx, repo, target.ID, int(perm.AccessModeWrite), false)
			require.NoError(t, err)
			defer finish(errors.New("scope changed"))
			mode := perm.AccessModeWrite
			switch change {
			case "intent":
				mode = perm.AccessModeAdmin
			case "owner":
				_, err = db.GetEngine(ctx).ID(repo.ID).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 4})
				require.NoError(t, err)
			case "actor":
				prepared = audit.WithDoer(prepared, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1}))
			}
			err = AddOrUpdateCollaborator(prepared, repo, target, mode)
			var rejection *authz_service.ExecutionError
			require.ErrorAs(t, err, &rejection)
			unittest.AssertNotExistsBean(t, &repo_model.Collaboration{RepoID: repo.ID, UserID: target.ID})
		})
	}
}

func TestAccessEmptyTeamScopeRemainsExact(t *testing.T) {
	ctx := enforceLifecycle(t)
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	ctx = audit.WithDoer(ctx, actor)
	team := &organization.Team{OrgID: 6, Name: "empty-access", AccessMode: perm.AccessModeRead, IncludesAllRepositories: true}
	prepared, finish, err := BeginTeamAccessMutation(ctx, team, "create")
	require.NoError(t, err)
	defer finish(nil)
	require.NoError(t, ValidateTeamAccessMutation(prepared, team))
	changed := audit.WithDoer(prepared, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}))
	require.Error(t, ValidateTeamAccessMutation(changed, team))
	require.NoError(t, db.Insert(ctx, &repo_model.Repository{OwnerID: 6, Name: "new-after-admission", LowerName: "new-after-admission"}))
	require.Error(t, ValidateTeamAccessMutation(prepared, team))
	unittest.AssertNotExistsBean(t, &authz_model.DecisionRecord{Action: authz.ManageAccess})
}

func TestAccessCompleteTargetTimeoutCannotFailOpen(t *testing.T) {
	ctx := enforceLifecycle(t)
	setting.EnterpriseAuthz.FailClosedOnError = false
	ctx = audit.WithDoer(ctx, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2}))
	_, _, err := beginAccessMutation(ctx, 0, "access-complete-targets", func(bounded context.Context) ([]*repo_model.Repository, error) {
		<-bounded.Done()
		return nil, bounded.Err()
	}, false)
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, 503, rejection.Status)
	require.Equal(t, "execution_timeout", rejection.Reason)
	unittest.AssertNotExistsBean(t, &authz_model.DecisionRecord{Action: authz.ManageAccess})
}
