// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"fmt"
	"strings"
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
	"gitea.dev/modules/util"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

func enableMergeGate(t *testing.T) {
	t.Helper()
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
}

func TestProtectedPathAdminRequiresDelegationAndRoleReferencesSurviveDisabled(t *testing.T) {
	enableMergeGate(t)
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	require.NoError(t, db.Insert(t.Context(), &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeAdmin}))
	role, err := CreateRole(t.Context(), owner, scope, CreateRoleInput{Name: "Delegated gate manager", Permissions: &[]PermissionInput{{Action: authz.ManageSensitivePaths, Effect: "allow"}}})
	require.NoError(t, err)
	raw := []byte(fmt.Sprintf(`{"path_pattern":"k8s/**","required_role_id":%d}`, role.Definition.ID))
	_, err = PutProtectedPathRule(t.Context(), actor, scope, 0, ProtectedPathRuleInput{Config: raw})
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	binding, _, err := PutBinding(t.Context(), owner, scope, BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: actor.ID, RoleID: role.Definition.ID})
	require.NoError(t, err)
	rule, err := PutProtectedPathRule(t.Context(), actor, scope, 0, ProtectedPathRuleInput{Config: raw})
	require.NoError(t, err)
	require.NoError(t, DeleteBinding(t.Context(), owner, scope, binding.ID))
	setting.EnterpriseMergeGate.Enabled = false
	require.ErrorIs(t, DeleteRole(t.Context(), owner, scope, role.Definition.ID, 1), ErrRoleReferenced)
	setting.EnterpriseMergeGate.Enabled = true
	require.NoError(t, DeleteProtectedPathRule(t.Context(), owner, scope, rule.ID, 1))
	require.NoError(t, DeleteRole(t.Context(), owner, scope, role.Definition.ID, 1))
}

func TestProtectedPathManagement(t *testing.T) {
	enableMergeGate(t)
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	reader := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	role, err := CreateRole(t.Context(), owner, scope, CreateRoleInput{Name: "Sensitive reviewer"})
	require.NoError(t, err)
	raw := []byte(fmt.Sprintf(`{"path_pattern":"k8s/**","required_role_id":%d,"check_contexts":["security/a"]}`, role.Definition.ID))
	_, err = PutProtectedPathRule(t.Context(), reader, scope, 0, ProtectedPathRuleInput{Config: raw})
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	ctx := reqctx.NewRequestContextForTest(t)
	ctx.GetData()["ApiTokenScope"] = auth_model.AccessTokenScopeReadRepository
	_, err = PutProtectedPathRule(ctx, owner, scope, 0, ProtectedPathRuleInput{Config: raw})
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	rule, err := PutProtectedPathRule(t.Context(), owner, scope, 0, ProtectedPathRuleInput{Config: raw})
	require.NoError(t, err)
	require.EqualValues(t, 1, rule.Revision)
	_, err = PutProtectedPathRule(t.Context(), owner, scope, rule.ID, ProtectedPathRuleInput{Config: raw})
	require.ErrorIs(t, err, ErrRevisionConflict)
	_, err = PutProtectedPathRule(t.Context(), owner, scope, rule.ID, ProtectedPathRuleInput{Config: raw, ExpectedRevision: 1})
	require.NoError(t, err)
	rules, total, err := ListProtectedPathRules(t.Context(), owner, scope, PolicyListOptions{})
	require.NoError(t, err)
	require.EqualValues(t, 1, total)
	require.Len(t, rules, 1)
	require.ErrorIs(t, DeleteRole(t.Context(), owner, scope, role.Definition.ID, 1), ErrRoleReferenced)
	setting.Audit.RecordOutput = setting.AuditRecordOutputDisabled
	require.ErrorIs(t, DeleteProtectedPathRule(t.Context(), owner, scope, rule.ID, 1), ErrPolicyStorage)
	stored := unittest.AssertExistsAndLoadBean(t, &authz_model.ProtectedPathRule{ID: rule.ID})
	require.False(t, stored.Deleted)
	setting.Audit.RecordOutput = setting.AuditRecordOutputDatabase
	require.NoError(t, DeleteProtectedPathRule(t.Context(), owner, scope, rule.ID, 1))
	require.ErrorIs(t, DeleteProtectedPathRule(t.Context(), owner, scope, rule.ID, 1), ErrRevisionConflict)
	require.NoError(t, DeleteRole(t.Context(), owner, scope, role.Definition.ID, 1))
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseProtectedPathCreate}, 1)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseProtectedPathDelete}, 1)
}

func TestProtectedPathCumulativeAndTransfer(t *testing.T) {
	enableMergeGate(t)
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	global := authz_model.Scope{Type: authz_model.ScopeSystem}
	org := authz_model.Scope{Type: authz_model.ScopeOrg, ID: 3}
	repo := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 3}
	role, err := CreateRole(t.Context(), admin, global, CreateRoleInput{Name: "Gate reviewer"})
	require.NoError(t, err)
	raw := []byte(fmt.Sprintf(`{"path_pattern":"k8s/**","required_role_id":%d}`, role.Definition.ID))
	for _, scope := range []authz_model.Scope{global, org, repo} {
		_, err = PutProtectedPathRule(t.Context(), admin, scope, 0, ProtectedPathRuleInput{Config: raw})
		require.NoError(t, err)
	}
	policies, err := EffectiveProtectedPathRules(t.Context(), 3)
	require.NoError(t, err)
	require.Len(t, policies, 3)
	_, err = db.GetEngine(t.Context()).ID(3).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 2})
	require.NoError(t, err)
	policies, err = EffectiveProtectedPathRules(t.Context(), 3)
	require.NoError(t, err)
	require.Len(t, policies, 2)
	require.True(t, policies[1].Unresolved)
	_, err = PutProtectedPathRule(t.Context(), owner, repo, policies[1].Rule.ID, ProtectedPathRuleInput{Config: raw, ExpectedRevision: 1})
	require.NoError(t, err)
	policies, err = EffectiveProtectedPathRules(t.Context(), 3)
	require.NoError(t, err)
	require.False(t, policies[1].Unresolved)
	setting.EnterpriseMergeGate.Enabled = false
	_, _, err = ListProtectedPathRules(t.Context(), owner, repo, PolicyListOptions{})
	require.ErrorIs(t, err, util.ErrNotExist)
}

func TestProtectedPathAtomicAuditAndTransactionalRead(t *testing.T) {
	enableMergeGate(t)
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	role, err := CreateRole(t.Context(), owner, scope, CreateRoleInput{Name: "Atomic reviewer"})
	require.NoError(t, err)
	raw := []byte(fmt.Sprintf(`{"path_pattern":"k8s/**","required_role_id":%d}`, role.Definition.ID))
	hook := &featureAuditFailure{enabled: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	t.Cleanup(func() { hook.enabled = false })
	_, err = PutProtectedPathRule(t.Context(), owner, scope, 0, ProtectedPathRuleInput{Config: raw})
	require.ErrorIs(t, err, ErrPolicyStorage)
	require.True(t, hook.fired)
	unittest.AssertCount(t, &authz_model.ProtectedPathRule{}, 0)
	hook.enabled = false
	_, err = PutProtectedPathRule(t.Context(), owner, scope, 0, ProtectedPathRuleInput{Config: raw})
	require.NoError(t, err)
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		policies, err := EffectiveProtectedPathRules(ctx, 1)
		require.NoError(t, err)
		require.Len(t, policies, 1)
		return nil
	}))
}

func TestProtectedPathRuleLimitAndDisabledZeroReads(t *testing.T) {
	enableMergeGate(t)
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	role, err := CreateRole(t.Context(), owner, scope, CreateRoleInput{Name: "Limit reviewer"})
	require.NoError(t, err)
	_, canonical, err := authz.ParseProtectedPathConfig([]byte(fmt.Sprintf(`{"path_pattern":"**","required_role_id":%d}`, role.Definition.ID)))
	require.NoError(t, err)
	for range authz.MaxProtectedPathRules + 1 {
		require.NoError(t, db.Insert(t.Context(), &authz_model.ProtectedPathRule{ScopeType: scope.Type, ScopeID: scope.ID, OwnerID: owner.ID, RequiredRoleID: role.Definition.ID, ConfigJSON: canonical, Enabled: true, Revision: 1, CreatedBy: owner.ID, UpdatedBy: owner.ID}))
	}
	page, count, err := ListProtectedPathRules(t.Context(), owner, scope, PolicyListOptions{Page: 2, Limit: 2})
	require.NoError(t, err)
	require.EqualValues(t, authz.MaxProtectedPathRules+1, count)
	require.Len(t, page, 2)
	previous, _, err := ListProtectedPathRules(t.Context(), owner, scope, PolicyListOptions{Page: 1, Limit: 2})
	require.NoError(t, err)
	require.Less(t, previous[1].ID, page[0].ID)
	policies, err := EffectiveProtectedPathRules(t.Context(), 1)
	require.ErrorIs(t, err, ErrMergeGateRuleLimit)
	require.Nil(t, policies)
	setting.EnterpriseMergeGate.Enabled = false
	hook := &disabledMergeGateReads{enabled: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	defer func() { hook.enabled = false }()
	policies, err = EffectiveProtectedPathRules(t.Context(), 1)
	require.NoError(t, err)
	require.Nil(t, policies)
	require.Zero(t, hook.count)
}

type disabledMergeGateReads struct {
	enabled bool
	count   int
}

func (h *disabledMergeGateReads) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.enabled && (strings.HasPrefix(c.SQL, "SELECT") || strings.HasPrefix(c.SQL, "INSERT")) {
		h.count++
	}
	return c.Ctx, nil
}
func (*disabledMergeGateReads) AfterProcess(*contexts.ContextHook) error { return nil }

func TestProtectedPathRoleScopeAndRevisionIntegrity(t *testing.T) {
	enableMergeGate(t)
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	global := authz_model.Scope{Type: authz_model.ScopeSystem}
	repo := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	localRole, err := CreateRole(t.Context(), admin, repo, CreateRoleInput{Name: "Local reviewer"})
	require.NoError(t, err)
	localConfig := []byte(fmt.Sprintf(`{"path_pattern":"**","required_role_id":%d}`, localRole.Definition.ID))
	_, err = PutProtectedPathRule(t.Context(), admin, global, 0, ProtectedPathRuleInput{Config: localConfig})
	require.ErrorIs(t, err, ErrInvalidPolicy)
	globalRole, err := CreateRole(t.Context(), admin, global, CreateRoleInput{Name: "Global reviewer"})
	require.NoError(t, err)
	globalConfig := []byte(fmt.Sprintf(`{"path_pattern":"**","required_role_id":%d}`, globalRole.Definition.ID))
	rule, err := PutProtectedPathRule(t.Context(), admin, global, 0, ProtectedPathRuleInput{Config: globalConfig})
	require.NoError(t, err)
	_, canonical, err := authz.ParseProtectedPathConfig(localConfig)
	require.NoError(t, err)
	_, err = db.GetEngine(t.Context()).ID(rule.ID).Cols("required_role_id", "config_json").Update(&authz_model.ProtectedPathRule{RequiredRoleID: localRole.Definition.ID, ConfigJSON: canonical})
	require.NoError(t, err)
	policies, err := EffectiveProtectedPathRules(t.Context(), 1)
	require.NoError(t, err)
	require.Len(t, policies, 1)
	require.True(t, policies[0].Unresolved)
	_, err = db.GetEngine(t.Context()).ID(localRole.Definition.ID).Cols("scope_type", "scope_id", "revision").Update(&authz_model.RoleDefinition{ScopeType: authz_model.ScopeSystem, Revision: 0})
	require.NoError(t, err)
	_, err = EffectiveProtectedPathRules(t.Context(), 1)
	require.ErrorIs(t, err, ErrPolicyStorage)
}

func TestMergeGateReviewerUsesCurrentRoleIdentity(t *testing.T) {
	enableMergeGate(t)
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	reviewer := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	role, err := CreateRole(t.Context(), owner, scope, CreateRoleInput{Name: "Gate approver"})
	require.NoError(t, err)
	binding, _, err := PutBinding(t.Context(), owner, scope, BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: reviewer.ID, RoleID: role.Definition.ID})
	require.NoError(t, err)
	ids, err := MergeGateReviewerRoles(t.Context(), reviewer.ID, repo)
	require.NoError(t, err)
	require.Equal(t, []int64{role.Definition.ID}, ids)
	name := "Renamed approver"
	_, err = UpdateRole(t.Context(), owner, scope, role.Definition.ID, UpdateRoleInput{ExpectedRevision: 1, Name: &name})
	require.NoError(t, err)
	ids, err = MergeGateReviewerRoles(t.Context(), reviewer.ID, repo)
	require.NoError(t, err)
	require.Equal(t, []int64{role.Definition.ID}, ids)
	require.NoError(t, DeleteBinding(t.Context(), owner, scope, binding.ID))
	ids, err = MergeGateReviewerRoles(t.Context(), reviewer.ID, repo)
	require.NoError(t, err)
	require.Empty(t, ids)
	repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	scope = authz_model.Scope{Type: authz_model.ScopeOrg, ID: repo.OwnerID}
	role, err = CreateRole(t.Context(), owner, scope, CreateRoleInput{Name: "Organization gate reviewer"})
	require.NoError(t, err)
	for _, subject := range []struct {
		kind authz_model.SubjectType
		id   int64
	}{
		{authz_model.SubjectTeam, 2},
		{authz_model.SubjectOrg, repo.OwnerID},
	} {
		binding, _, err = PutBinding(t.Context(), owner, scope, BindingInput{SubjectType: subject.kind, SubjectID: subject.id, RoleID: role.Definition.ID})
		require.NoError(t, err)
		ids, err = MergeGateReviewerRoles(t.Context(), reviewer.ID, repo)
		require.NoError(t, err)
		require.Equal(t, []int64{role.Definition.ID}, ids)
		if subject.kind == authz_model.SubjectTeam {
			_, err = db.GetEngine(t.Context()).Where("uid=? AND team_id=?", reviewer.ID, subject.id).Delete(new(organization.TeamUser))
		} else {
			_, err = db.GetEngine(t.Context()).Where("uid=? AND org_id=?", reviewer.ID, subject.id).Delete(new(organization.OrgUser))
		}
		require.NoError(t, err)
		ids, err = MergeGateReviewerRoles(t.Context(), reviewer.ID, repo)
		require.NoError(t, err)
		require.Empty(t, ids, "membership revocation must invalidate a role binding")
		require.NoError(t, DeleteBinding(t.Context(), owner, scope, binding.ID))
	}
}
