// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"
	"testing"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/organization"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/audit"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func enforceLifecycle(t *testing.T) context.Context {
	t.Helper()
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	return audit.WithOrigin(t.Context(), audit_model.OriginAPI)
}

func TestLifecycleRejectsBeforeMutation(t *testing.T) {
	for _, name := range []string{"archive", "delete", "start", "accept", "reject", "cancel"} {
		t.Run(name, func(t *testing.T) {
			ctx := enforceLifecycle(t)
			repoID, actorID := int64(21), int64(10)
			if name == "archive" || name == "delete" || name == "start" {
				repoID, actorID = 32, 15
			}
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repoID})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: actorID})
			if name == "archive" || name == "delete" || name == "start" {
				_, e := db.GetEngine(ctx).ID(7).Cols("authorize").Update(&organization.Team{AccessMode: perm.AccessModeAdmin})
				require.NoError(t, e)
				require.NoError(t, access_model.RecalculateTeamAccesses(ctx, repo, 0))
				permission, e := access_model.GetDoerRepoPermission(ctx, repo, actor)
				require.NoError(t, e)
				require.True(t, permission.IsAdmin())
				require.False(t, permission.IsOwner())
			}

			if name == "start" {
				repo.Status = repo_model.RepositoryReady
				_, e := db.GetEngine(ctx).ID(repo.ID).Cols("status").Update(repo)
				require.NoError(t, e)
			}
			before := *repo
			var err error
			action := authz.Transfer
			switch name {
			case "start":
				recipient := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 10})
				err = StartRepositoryTransfer(ctx, actor, recipient, repo, nil)
			case "archive":
				action = authz.Archive
				err = SetArchiveRepoState(ctx, actor, repo, true)
			case "delete":
				action = authz.Delete
				err = DeleteRepository(ctx, actor, repo, true)
			case "accept":
				err = AcceptTransferOwnership(ctx, repo, actor)
			case "reject":
				err = RejectRepositoryTransfer(ctx, repo, actor)
			case "cancel":
				transfer := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoTransfer{RepoID: repoID})
				transfer.DoerID = actorID
				_, e := db.GetEngine(ctx).ID(transfer.ID).Cols("doer_id").Update(transfer)
				require.NoError(t, e)
				err = CancelRepositoryTransfer(ctx, transfer, actor)
			}
			var rejection *authz_service.ExecutionError
			require.ErrorAs(t, err, &rejection)
			require.Equal(t, 403, rejection.Status)
			stored := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repoID})
			require.Equal(t, before.OwnerID, stored.OwnerID)
			require.Equal(t, before.Status, stored.Status)
			require.Equal(t, before.IsArchived, stored.IsArchived)
			row := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repoID, Action: action})
			require.Equal(t, "deny", row.AuthorizationDecision)
			require.False(t, row.ExecutionStarted)
		})
	}
}

func TestLifecycleDirectDeleteDoesNotTrustSystemOrigin(t *testing.T) {
	ctx := enforceLifecycle(t)
	ctx = audit.WithOrigin(ctx, audit_model.OriginSystem)
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, DeleteRepositoryDirectly(ctx, 1), &rejection)
	unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
}

func TestLifecycleArchiveNativeAndPolicyIntersection(t *testing.T) {
	for _, name := range []string{"owner", "role-admin", "role-reader", "mirror", "inactive", "scope"} {
		t.Run(name, func(t *testing.T) {
			ctx := enforceLifecycle(t)
			repoID, actorID := int64(1), int64(2)
			if name == "role-admin" {
				repoID, actorID = 32, 15
			}
			if name == "role-reader" {
				actorID = 4
			}
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repoID})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: actorID})
			if name == "role-admin" {
				_, err := db.GetEngine(ctx).ID(7).Cols("authorize").Update(&organization.Team{AccessMode: perm.AccessModeAdmin})
				require.NoError(t, err)
				require.NoError(t, access_model.RecalculateTeamAccesses(ctx, repo, 0))
			}
			if name == "role-admin" || name == "role-reader" {
				grantLifecycleAction(ctx, t, repo, actorID, authz.Archive)
			}
			if name == "mirror" {
				_, err := db.GetEngine(ctx).ID(repo.ID).Cols("is_mirror").Update(&repo_model.Repository{IsMirror: true})
				require.NoError(t, err)
			}
			if name == "inactive" {
				_, err := db.GetEngine(ctx).ID(actor.ID).Cols("is_active").Update(&user_model.User{IsActive: false})
				require.NoError(t, err)
			}
			if name == "scope" {
				request := reqctx.NewRequestContextForTest(t)
				request.GetData()["ApiTokenScope"] = auth_model.AccessTokenScopeReadRepository
				ctx = audit.WithOrigin(request, audit_model.OriginAPI)
			}
			err := SetArchiveRepoState(ctx, actor, repo, true)
			if name == "owner" || name == "role-admin" {
				require.NoError(t, err)
				unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repoID, Action: authz.Archive, ExecutionStarted: true, NativeOutcome: "success"})
				require.NoError(t, SetArchiveRepoState(ctx, actor, repo, false))
			} else {
				require.Error(t, err)
			}
			stored := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repoID})
			require.False(t, stored.IsArchived)
		})
	}
}

func grantLifecycleAction(ctx context.Context, t *testing.T, repo *repo_model.Repository, actorID int64, action authz.Action) {
	t.Helper()
	role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: repo.ID, Name: "Lifecycle role", LowerName: "lifecycle-role", Revision: 1, CreatedBy: repo.OwnerID}
	require.NoError(t, db.Insert(ctx, role))
	_, condition, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	require.NoError(t, db.Insert(ctx, &authz_model.RolePermission{RoleID: role.ID, Action: action, Effect: "allow", ConditionJSON: condition, ConditionHash: hash}))
	require.NoError(t, db.Insert(ctx, &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: actorID, ScopeType: authz_model.ScopeRepo, ScopeID: repo.ID, ScopeOwnerID: repo.OwnerID, RoleID: role.ID}))
}

func TestLifecycleMaintenanceExactTargetsAndConditions(t *testing.T) {
	ctx := enforceLifecycle(t)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	for _, marker := range []repositoryDeleteMaintenance{{repo.ID + 1, repo.OwnerID, "failed-creation"}, {repo.ID, repo.OwnerID + 1, "failed-creation"}, {repo.ID, repo.OwnerID, "unknown"}, {repo.ID, repo.OwnerID, "orphan-cleanup"}, {repo.ID, repo.OwnerID, "failed-migration"}} {
		require.Error(t, requireRepositoryDelete(context.WithValue(ctx, repositoryDeleteMaintenanceKey{}, marker), repo))
	}
	require.Error(t, DeleteOrphanedRepository(ctx, repo.ID))
	require.Error(t, DeleteFailedMigrationRepository(ctx, repo.ID))
	unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID})
}

func TestLifecycleTransferRecipientUsesCurrentPolicy(t *testing.T) {
	for _, operation := range []string{"reject", "cancel"} {
		t.Run(operation, func(t *testing.T) {
			ctx := enforceLifecycle(t)
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 21})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 10})
			grantLifecycleAction(ctx, t, repo, actor.ID, authz.Transfer)
			pending := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoTransfer{RepoID: repo.ID})
			if operation == "cancel" {
				pending.DoerID = actor.ID
				_, err := db.GetEngine(ctx).ID(pending.ID).Cols("doer_id").Update(pending)
				require.NoError(t, err)
			}
			var err error
			if operation == "reject" {
				err = RejectRepositoryTransfer(ctx, repo, actor)
			} else {
				err = CancelRepositoryTransfer(ctx, pending, actor)
			}
			require.NoError(t, err)
			unittest.AssertNotExistsBean(t, &repo_model.RepoTransfer{RepoID: repo.ID})
			unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repo.ID, ActorID: actor.ID, Action: authz.Transfer, ExecutionStarted: true, NativeOutcome: "success"})
		})
	}
}

func TestLifecycleOrphanCleanupAuditAndScope(t *testing.T) {
	ctx := enforceLifecycle(t)
	repo := &repo_model.Repository{OwnerID: 99999, Name: "orphan-maintenance", LowerName: "orphan-maintenance"}
	require.NoError(t, db.Insert(ctx, repo))
	require.NoError(t, DeleteOrphanedRepository(ctx, repo.ID))
	unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: repo.ID})
	unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.RepositoryDelete, Origin: audit_model.OriginSystem, ScopeID: repo.ID})
	unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
}

func TestLifecycleBlockedCleanupRequiresRealRelationship(t *testing.T) {
	ctx := enforceLifecycle(t)
	pending := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoTransfer{RepoID: 21})
	doer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 16})
	recipient := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 10})
	require.Error(t, CancelBlockedRepositoryTransfer(ctx, pending, doer, doer, recipient))
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoTransfer{RepoID: 21})
}

func TestLifecycleTransferNativePreconditionsRemain(t *testing.T) {
	for _, name := range []string{"quota", "recipient-team", "not-ready"} {
		t.Run(name, func(t *testing.T) {
			ctx := enforceLifecycle(t)
			repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			recipient := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 10})
			var teams []*organization.Team
			switch name {
			case "quota":
				t.Cleanup(test.MockVariableValue(&setting.Repository.AllowForkWithoutMaximumLimit, false))
				_, err := db.GetEngine(ctx).ID(recipient.ID).Cols("max_repo_creation").Update(&user_model.User{MaxRepoCreation: 0})
				require.NoError(t, err)
			case "recipient-team":
				teams = []*organization.Team{{ID: 1}}
			case "not-ready":
				_, err := db.GetEngine(ctx).ID(repo.ID).Cols("status").Update(&repo_model.Repository{Status: repo_model.RepositoryBeingMigrated})
				require.NoError(t, err)
			}
			err := StartRepositoryTransfer(ctx, actor, recipient, repo, teams)
			require.Error(t, err)
			unittest.AssertNotExistsBean(t, &repo_model.RepoTransfer{RepoID: repo.ID})
			unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID, OwnerID: 2})
			if name == "quota" {
				require.True(t, IsRepositoryLimitReached(err))
			}
		})
	}
}

func TestLifecycleBatchDeleteRejectsBeforeAnyDeletion(t *testing.T) {
	ctx := enforceLifecycle(t)
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 15})
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 32})
	_, err := db.GetEngine(ctx).ID(7).Cols("authorize").Update(&organization.Team{AccessMode: perm.AccessModeAdmin})
	require.NoError(t, err)
	require.NoError(t, access_model.RecalculateTeamAccesses(ctx, repo, 0))
	_, admission, err := PrepareOrganizationRepositoryDeletion(ctx, actor, repo.OwnerID, []int64{repo.ID})
	require.Error(t, err)
	require.Nil(t, admission)
	unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID})
	var rejection *authz_service.ExecutionError
	require.ErrorAs(t, err, &rejection)
	require.Equal(t, 403, rejection.Status)
}

func TestLifecycleDeleteBusinessRollbackPreservesLiveScope(t *testing.T) {
	ctx := enforceLifecycle(t)
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repo := &repo_model.Repository{OwnerID: actor.ID, OwnerName: actor.Name, Name: "delete-rollback", LowerName: "delete-rollback"}
	require.NoError(t, db.Insert(ctx, repo))
	grantLifecycleAction(ctx, t, repo, 4, authz.Delete)
	_, err := db.Exec(ctx, "ALTER TABLE action_artifact RENAME TO lifecycle_delete_business_fault")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.Exec(context.WithoutCancel(ctx), "ALTER TABLE lifecycle_delete_business_fault RENAME TO action_artifact")
		require.NoError(t, err)
	})
	require.Error(t, DeleteRepository(ctx, actor, repo, false))
	unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID})
	unittest.AssertExistsAndLoadBean(t, &authz_model.SubjectRoleBinding{ScopeID: repo.ID, SubjectID: 4})
	unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: repo.ID, Action: authz.Delete, AuthorizationDecision: "allow", ExecutionStarted: true, NativeOutcome: "failed"})
}

func TestLifecycleBatchDeleteSuccessSharesOperation(t *testing.T) {
	ctx := enforceLifecycle(t)
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	repos := []*repo_model.Repository{{OwnerID: owner.ID, OwnerName: owner.Name, Name: "batch-one", LowerName: "batch-one"}, {OwnerID: owner.ID, OwnerName: owner.Name, Name: "batch-two", LowerName: "batch-two"}}
	ids := make([]int64, 0, len(repos))
	for _, repo := range repos {
		require.NoError(t, db.Insert(ctx, repo))
		ids = append(ids, repo.ID)
		require.NoError(t, db.Insert(ctx, &organization.TeamRepo{OrgID: owner.ID, TeamID: 1, RepoID: repo.ID}))
		require.NoError(t, access_model.RecalculateTeamAccesses(ctx, repo, 0))
	}
	ctx, admission, err := PrepareOrganizationRepositoryDeletion(ctx, actor, owner.ID, ids)
	require.NoError(t, err)
	for _, repo := range repos {
		require.NoError(t, DeleteRepository(ctx, actor, repo, false))
		unittest.AssertNotExistsBean(t, &repo_model.Repository{ID: repo.ID})
	}
	admission.Finish(ctx, authz_service.NativeSuccess, authz_service.StageOperation)
	first := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: ids[0], Action: authz.Delete, ExecutionStarted: true, NativeOutcome: "success"})
	second := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: ids[1], Action: authz.Delete, ExecutionStarted: true, NativeOutcome: "success"})
	require.Equal(t, first.OperationID, second.OperationID)
}

func TestLifecyclePendingRecipientMembershipIsRechecked(t *testing.T) {
	ctx := enforceLifecycle(t)
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 21})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	pending := unittest.AssertExistsAndLoadBean(t, &repo_model.RepoTransfer{RepoID: repo.ID})
	pending.RecipientID = 3
	_, err := db.GetEngine(ctx).ID(pending.ID).Cols("recipient_id").Update(pending)
	require.NoError(t, err)
	require.True(t, pending.CanUserAcceptOrRejectTransfer(ctx, actor))
	grantLifecycleAction(ctx, t, repo, actor.ID, authz.Transfer)
	_, err = db.GetEngine(ctx).Where("org_id = ? AND uid = ?", 3, actor.ID).Delete(&organization.TeamUser{})
	require.NoError(t, err)
	_, err = db.GetEngine(ctx).Where("org_id = ? AND uid = ?", 3, actor.ID).Delete(&organization.OrgUser{})
	require.NoError(t, err)
	require.False(t, pending.CanUserAcceptOrRejectTransfer(ctx, actor))
	require.Error(t, RejectRepositoryTransfer(ctx, repo, actor))
	unittest.AssertExistsAndLoadBean(t, &repo_model.RepoTransfer{RepoID: repo.ID})
}
