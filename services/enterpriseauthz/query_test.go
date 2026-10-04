// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"crypto/rand"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/timeutil"
	"gitea.dev/modules/util"

	"github.com/stretchr/testify/require"
)

func prepareDecisionQuery(t *testing.T) {
	t.Helper()
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
}

func insertQueryDecision(t *testing.T, repoID, ownerID, actorID int64, action authz.Action, decision string, created timeutil.TimeStamp) authz_model.DecisionRecord {
	t.Helper()
	snapshot, err := json.Marshal(roleSnapshot{CatalogVersion: 1, RepoID: repoID, OwnerID: ownerID, ActorID: actorID})
	require.NoError(t, err)
	record := authz_model.DecisionRecord{ObservationID: rand.Text(), OperationID: "operation-1", ActorID: actorID, RepoID: repoID, OwnerID: ownerID, Action: action, RequestSource: "api", CandidateDecision: decision, Reason: "missing_action", MissingActions: `[]`, NativeOutcome: "denied", NativeStage: "authorization", SnapshotJSON: string(snapshot), CreatedUnix: created}
	_, err = db.GetEngine(t.Context()).NoAutoTime().Insert(&record)
	require.NoError(t, err)
	return record
}

func decisionQueryIDs(records []authz_model.DecisionRecord) []int64 {
	ids := make([]int64, 0, len(records))
	for _, record := range records {
		ids = append(ids, record.ID)
	}
	return ids
}

func TestDecisionQueryScopesUseCurrentRepositories(t *testing.T) {
	prepareDecisionQuery(t)
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repo := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	org := authz_model.Scope{Type: authz_model.ScopeOrg, ID: 3}
	system := authz_model.Scope{Type: authz_model.ScopeSystem}
	personal := insertQueryDecision(t, 1, 2, 2, authz.ReadCode, "allow", 100)
	orgRecord := insertQueryDecision(t, 3, 2, 4, authz.Clone, "deny", 200)
	unrelated := insertQueryDecision(t, 4, 3, 5, authz.Clone, "deny", 200)
	deleted := insertQueryDecision(t, 99999, 3, 5, authz.Delete, "error", 300)
	for _, tt := range []struct {
		name  string
		actor *user_model.User
		scope authz_model.Scope
		want  []int64
	}{
		{"repo", owner, repo, []int64{personal.ID}},
		{"org current owner not historical owner", owner, org, []int64{orgRecord.ID}},
		{"system includes deleted", admin, system, []int64{deleted.ID, unrelated.ID, orgRecord.ID, personal.ID}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			records, total, err := ListDecisions(t.Context(), tt.actor, tt.scope, DecisionListOptions{})
			require.NoError(t, err)
			require.EqualValues(t, len(tt.want), total)
			require.Equal(t, tt.want, decisionQueryIDs(records))
			for _, id := range tt.want {
				record, err := GetDecision(t.Context(), tt.actor, tt.scope, id)
				require.NoError(t, err)
				require.Equal(t, id, record.ID)
			}
		})
	}
	for _, tt := range []struct {
		scope authz_model.Scope
		id    int64
	}{
		{repo, orgRecord.ID}, {repo, deleted.ID}, {org, personal.ID}, {org, unrelated.ID}, {org, deleted.ID},
	} {
		record, err := GetDecision(t.Context(), owner, tt.scope, tt.id)
		require.ErrorIs(t, err, util.ErrNotExist)
		require.Nil(t, record)
	}
	for _, scope := range []authz_model.Scope{repo, org} {
		records, total, err := ListDecisions(t.Context(), owner, scope, DecisionListOptions{RepoID: 4})
		require.ErrorIs(t, err, util.ErrNotExist)
		require.Nil(t, records)
		require.Zero(t, total)
	}
	records, total, err := ListDecisions(t.Context(), admin, system, DecisionListOptions{RepoID: deleted.RepoID})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Equal(t, []int64{deleted.ID}, decisionQueryIDs(records))
}

func TestDecisionQueryTransferAndDeletionFollowNativeAuthority(t *testing.T) {
	prepareDecisionQuery(t)
	oldOwner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	newOwner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	org := authz_model.Scope{Type: authz_model.ScopeOrg, ID: 3}
	repo := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 3}
	system := authz_model.Scope{Type: authz_model.ScopeSystem}
	record := insertQueryDecision(t, 3, 3, 2, authz.Transfer, "allow", 100)
	_, err := db.GetEngine(t.Context()).ID(3).Cols("owner_id").Update(&repo_model.Repository{OwnerID: newOwner.ID})
	require.NoError(t, err)
	records, total, err := ListDecisions(t.Context(), oldOwner, org, DecisionListOptions{})
	require.NoError(t, err)
	require.Empty(t, records)
	require.Zero(t, total)
	_, err = GetDecision(t.Context(), oldOwner, org, record.ID)
	require.ErrorIs(t, err, util.ErrNotExist)
	_, _, err = ListDecisions(t.Context(), oldOwner, org, DecisionListOptions{RepoID: 3})
	require.ErrorIs(t, err, util.ErrNotExist)
	found, err := GetDecision(t.Context(), newOwner, repo, record.ID)
	require.NoError(t, err)
	require.Equal(t, record.OwnerID, found.OwnerID)
	setting.EnterpriseWeCom = setting.EnterpriseWeComConfig{Enabled: true}
	_, err = GetDecision(t.Context(), oldOwner, repo, record.ID)
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	setting.EnterpriseWeCom.Enabled = false
	_, err = db.GetEngine(t.Context()).ID(3).Delete(new(repo_model.Repository))
	require.NoError(t, err)
	_, err = GetDecision(t.Context(), newOwner, repo, record.ID)
	require.ErrorIs(t, err, util.ErrNotExist)
	_, err = GetDecision(t.Context(), oldOwner, org, record.ID)
	require.ErrorIs(t, err, util.ErrNotExist)
	found, err = GetDecision(t.Context(), admin, system, record.ID)
	require.NoError(t, err)
	require.Equal(t, record.SnapshotJSON, found.SnapshotJSON)
}

func TestDecisionQueryFiltersPaginationAndValidation(t *testing.T) {
	prepareDecisionQuery(t)
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	system := authz_model.Scope{Type: authz_model.ScopeSystem}
	first := insertQueryDecision(t, 1, 2, 2, authz.ReadCode, "allow", 100)
	second := insertQueryDecision(t, 1, 2, 2, authz.Clone, "deny", 200)
	third := insertQueryDecision(t, 3, 3, 4, authz.Clone, "error", 300)
	for _, actorID := range []int64{0, user_model.GhostUserID, user_model.ActionsUserID, user_model.DeployKeyUserID, user_model.CliUserID, user_model.AuthSourceUserID} {
		record := insertQueryDecision(t, 1, 2, actorID, authz.Clone, "allow", 400)
		records, total, err := ListDecisions(t.Context(), admin, system, DecisionListOptions{ActorID: &actorID})
		require.NoError(t, err)
		require.EqualValues(t, 1, total)
		require.Equal(t, []int64{record.ID}, decisionQueryIDs(records))
	}
	actorID := int64(2)
	for _, tt := range []struct {
		name    string
		options DecisionListOptions
		want    []int64
		total   int64
	}{
		{"actor and page", DecisionListOptions{PolicyListOptions: PolicyListOptions{Page: 2, Limit: 1}, ActorID: &actorID}, []int64{first.ID}, 2},
		{"all filters", DecisionListOptions{ActorID: &actorID, RepoID: 1, Action: authz.Clone, CandidateDecision: "deny", Since: 200, Until: 200}, []int64{second.ID}, 1},
		{"error", DecisionListOptions{CandidateDecision: "error", Since: 300}, []int64{third.ID}, 1},
		{"no match", DecisionListOptions{Action: authz.Delete}, []int64{}, 0},
		{"past final page", DecisionListOptions{PolicyListOptions: PolicyListOptions{Page: 100, Limit: 100}}, []int64{}, 9},
	} {
		t.Run(tt.name, func(t *testing.T) {
			records, total, err := ListDecisions(t.Context(), admin, system, tt.options)
			require.NoError(t, err)
			require.Equal(t, tt.total, total)
			require.Equal(t, tt.want, decisionQueryIDs(records))
		})
	}
	invalidActor := int64(-999)
	for _, options := range []DecisionListOptions{
		{PolicyListOptions: PolicyListOptions{Limit: 101}},
		{PolicyListOptions: PolicyListOptions{Limit: -1}},
		{PolicyListOptions: PolicyListOptions{Page: -1}},
		{PolicyListOptions: PolicyListOptions{Page: int(^uint(0) >> 1), Limit: 100}},
		{RepoID: -1},
		{ActorID: &invalidActor},
		{Action: "repo.unknown"},
		{CandidateDecision: "ALLOW"},
		{Since: -1},
		{Until: -1},
		{Since: 300, Until: 100},
	} {
		records, total, err := ListDecisions(t.Context(), admin, system, options)
		require.ErrorIs(t, err, ErrInvalidPolicy)
		require.Nil(t, records)
		require.Zero(t, total)
	}
	for _, id := range []int64{0, -1} {
		_, err := GetDecision(t.Context(), admin, system, id)
		require.ErrorIs(t, err, ErrInvalidPolicy)
	}
	_, err := GetDecision(t.Context(), admin, system, 99999)
	require.ErrorIs(t, err, util.ErrNotExist)
}

func TestDecisionQueryAuthorityAndDisabledPrecedeValidation(t *testing.T) {
	prepareDecisionQuery(t)
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	member := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	system := authz_model.Scope{Type: authz_model.ScopeSystem}
	org := authz_model.Scope{Type: authz_model.ScopeOrg, ID: 3}
	repo := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 3}
	key := "platform-admin"
	role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeSystem, Name: "Platform Admin", LowerName: "platform admin", BuiltinKey: &key, Revision: 1}
	require.NoError(t, db.Insert(t.Context(), role))
	require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: member.ID, ScopeType: authz_model.ScopeSystem, RoleID: role.ID}))
	member.IsAdmin = true
	for _, actor := range []*user_model.User{nil, member, user_model.NewActionsUserWithTaskID(1)} {
		for _, scope := range []authz_model.Scope{system, org, repo} {
			_, _, err := ListDecisions(t.Context(), actor, scope, DecisionListOptions{Action: "invalid"})
			require.ErrorIs(t, err, util.ErrPermissionDenied)
			_, err = GetDecision(t.Context(), actor, scope, 0)
			require.ErrorIs(t, err, util.ErrPermissionDenied)
		}
	}
	setting.EnterpriseAuthz.Enabled = false
	_, err := db.GetEngine(t.Context()).Exec("ALTER TABLE enterprise_authz_decision RENAME TO authz_query_hidden_decisions")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.GetEngine(context.WithoutCancel(t.Context())).Exec("ALTER TABLE authz_query_hidden_decisions RENAME TO enterprise_authz_decision")
		require.NoError(t, err)
	})
	for _, tt := range []struct {
		actor *user_model.User
		scope authz_model.Scope
	}{
		{admin, system}, {owner, org}, {owner, repo},
	} {
		_, _, err := ListDecisions(t.Context(), tt.actor, tt.scope, DecisionListOptions{Action: "invalid"})
		require.ErrorIs(t, err, util.ErrNotExist)
		_, err = GetDecision(t.Context(), tt.actor, tt.scope, 0)
		require.ErrorIs(t, err, util.ErrNotExist)
	}
	_, _, err = ListDecisions(t.Context(), member, system, DecisionListOptions{})
	require.ErrorIs(t, err, util.ErrPermissionDenied)
}

func TestDecisionQueryPaginationDefaultsAndMaximum(t *testing.T) {
	prepareDecisionQuery(t)
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	ids := make([]int64, 105)
	for i := range ids {
		ids[i] = insertQueryDecision(t, 1, 2, 2, authz.ReadCode, "allow", 100).ID
	}
	for _, tt := range []struct {
		options PolicyListOptions
		length  int
		firstID int64
		lastID  int64
	}{
		{PolicyListOptions{}, 20, ids[104], ids[85]},
		{PolicyListOptions{Limit: 100}, 100, ids[104], ids[5]},
		{PolicyListOptions{Limit: 100, Page: 2}, 5, ids[4], ids[0]},
	} {
		records, total, err := ListDecisions(t.Context(), owner, scope, DecisionListOptions{PolicyListOptions: tt.options})
		require.NoError(t, err)
		require.EqualValues(t, 105, total)
		require.Len(t, records, tt.length)
		require.Equal(t, tt.firstID, records[0].ID)
		require.Equal(t, tt.lastID, records[len(records)-1].ID)
	}
}

func TestDecisionQueryWeComUsesBoundAuthorityAndNativeOwners(t *testing.T) {
	prepareDecisionQuery(t)
	setting.EnterpriseWeCom = setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-query", AgentID: "1000002"}
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	creator := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 5})
	system := authz_model.Scope{Type: authz_model.ScopeSystem}
	org := authz_model.Scope{Type: authz_model.ScopeOrg, ID: 3}
	repo := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 3}
	for _, scope := range []authz_model.Scope{system, org, repo} {
		_, _, err := ListDecisions(t.Context(), admin, scope, DecisionListOptions{})
		require.ErrorIs(t, err, util.ErrPermissionDenied)
	}
	for _, scope := range []authz_model.Scope{org, repo} {
		_, _, err := ListDecisions(t.Context(), owner, scope, DecisionListOptions{})
		require.NoError(t, err)
	}
	require.NoError(t, db.Insert(t.Context(), &wecom_model.RepositoryGovernance{RepoID: 3, CreatorID: creator.ID}))
	_, _, err := ListDecisions(t.Context(), creator, repo, DecisionListOptions{})
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	require.NoError(t, db.Insert(t.Context(), &access_model.Access{UserID: creator.ID, RepoID: repo.ID, Mode: perm.AccessModeRead}))
	_, _, err = ListDecisions(t.Context(), creator, repo, DecisionListOptions{})
	require.NoError(t, err)
	_, _, err = ListDecisions(t.Context(), creator, org, DecisionListOptions{})
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	require.NoError(t, db.Insert(t.Context(), &wecom_model.AdminAuthority{CorpID: "corp-query", AgentID: "1000002", WeComUserID: "query.super", IsManagement: true, IsActive: true}))
	_, _, err = wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: admin.ID, CorpID: "corp-query", WeComUserID: "query.super", Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	for _, scope := range []authz_model.Scope{system, org, repo} {
		_, _, err := ListDecisions(t.Context(), admin, scope, DecisionListOptions{})
		require.NoError(t, err)
	}
	_, err = db.GetEngine(t.Context()).Where("corp_id = ?", "corp-query").Cols("is_active").Update(&wecom_model.AdminAuthority{IsActive: false})
	require.NoError(t, err)
	_, _, err = ListDecisions(t.Context(), admin, system, DecisionListOptions{})
	require.ErrorIs(t, err, util.ErrPermissionDenied)
}

func TestDecisionQueryHistoryDoesNotReadCurrentRoles(t *testing.T) {
	prepareDecisionQuery(t)
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	role, err := CreateRole(t.Context(), owner, scope, CreateRoleInput{Name: "History", Permissions: &[]PermissionInput{{Action: authz.Delete, Effect: "allow"}}})
	require.NoError(t, err)
	binding, _, err := PutBinding(t.Context(), owner, scope, BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: owner.ID, RoleID: role.Definition.ID})
	require.NoError(t, err)
	ctx, observation := BeginObservation(t.Context(), observationInput(t))
	observation.Finish(ctx, NativeDenied, StageOperation)
	record := unittest.AssertExistsAndLoadBean(t, &authz_model.DecisionRecord{RepoID: 1})
	require.Contains(t, record.SnapshotJSON, `"revision":1`)
	_, err = UpdateRole(t.Context(), owner, scope, role.Definition.ID, UpdateRoleInput{ExpectedRevision: 1, Permissions: &[]PermissionInput{}})
	require.NoError(t, err)
	require.NoError(t, DeleteBinding(t.Context(), owner, scope, binding.ID))
	require.NoError(t, DeleteRole(t.Context(), owner, scope, role.Definition.ID, 2))
	_, err = db.GetEngine(t.Context()).Exec("ALTER TABLE enterprise_role_definition RENAME TO authz_query_hidden_roles")
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.GetEngine(context.WithoutCancel(t.Context())).Exec("ALTER TABLE authz_query_hidden_roles RENAME TO enterprise_role_definition")
		require.NoError(t, err)
	})
	found, err := GetDecision(t.Context(), owner, scope, record.ID)
	require.NoError(t, err)
	require.Equal(t, record.SnapshotJSON, found.SnapshotJSON)
	require.Equal(t, "allow", found.CandidateDecision)
	records, total, err := ListDecisions(t.Context(), owner, scope, DecisionListOptions{})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Equal(t, record.SnapshotJSON, records[0].SnapshotJSON)
}

func TestDecisionQueryStorageErrorsAreSafeAndRejectBusinessTransactions(t *testing.T) {
	prepareDecisionQuery(t)
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	require.NoError(t, db.WithTx(t.Context(), func(tx context.Context) error {
		records, total, err := ListDecisions(tx, owner, scope, DecisionListOptions{})
		require.ErrorIs(t, err, ErrPolicyStorage)
		require.Nil(t, records)
		require.Zero(t, total)
		found, err := GetDecision(tx, owner, scope, 1)
		require.ErrorIs(t, err, ErrPolicyStorage)
		require.Nil(t, found)
		return nil
	}))
	_, err := db.GetEngine(t.Context()).Exec("ALTER TABLE enterprise_authz_decision RENAME TO authz_query_hidden_decisions")
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Exec(`CREATE VIEW enterprise_authz_decision AS SELECT * FROM "TOPSECRET token=TOPTOKEN code=OAUTH private/path"`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.GetEngine(context.WithoutCancel(t.Context())).Exec("DROP VIEW enterprise_authz_decision")
		require.NoError(t, err)
		_, err = db.GetEngine(context.WithoutCancel(t.Context())).Exec("ALTER TABLE authz_query_hidden_decisions RENAME TO enterprise_authz_decision")
		require.NoError(t, err)
	})
	records, total, err := ListDecisions(t.Context(), owner, scope, DecisionListOptions{})
	require.ErrorIs(t, err, ErrPolicyStorage)
	require.EqualError(t, err, "policy_storage_failed")
	require.Nil(t, records)
	require.Zero(t, total)
	found, err := GetDecision(t.Context(), owner, scope, 1)
	require.EqualError(t, err, "policy_storage_failed")
	require.Nil(t, found)
}

func TestDecisionQueryAuthorityReadErrorsAreSafe(t *testing.T) {
	prepareDecisionQuery(t)
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	_, err := db.GetEngine(t.Context()).Exec("ALTER TABLE user RENAME TO authz_query_hidden_users")
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).Exec(`CREATE VIEW user AS SELECT * FROM "secret=TOPSECRET token=TOPTOKEN code=OAUTH private/path"`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.GetEngine(context.WithoutCancel(t.Context())).Exec("DROP VIEW user")
		require.NoError(t, err)
		_, err = db.GetEngine(context.WithoutCancel(t.Context())).Exec("ALTER TABLE authz_query_hidden_users RENAME TO user")
		require.NoError(t, err)
	})
	records, total, err := ListDecisions(t.Context(), owner, scope, DecisionListOptions{})
	require.EqualError(t, err, "policy_storage_failed")
	require.Nil(t, records)
	require.Zero(t, total)
	record, err := GetDecision(t.Context(), owner, scope, 1)
	require.EqualError(t, err, "policy_storage_failed")
	require.Nil(t, record)
}
