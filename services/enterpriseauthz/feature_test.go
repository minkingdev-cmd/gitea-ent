// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
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

func TestFeatureManagementAndReset(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	reader := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	global := authz_model.Scope{Type: authz_model.ScopeSystem}
	repo := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	policy, err := PutFeatureGrant(t.Context(), admin, global, authz.FeatureWiki, FeatureGrantInput{State: authz.FeatureRequired, Config: []byte(`{}`)})
	require.NoError(t, err)
	require.EqualValues(t, 1, policy.Grant.Revision)
	_, err = PutFeatureGrant(t.Context(), reader, repo, authz.FeatureWiki, FeatureGrantInput{State: authz.FeatureEnabled, Config: []byte(`{}`)})
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	_, err = PutFeatureGrant(t.Context(), owner, repo, authz.FeatureWiki, FeatureGrantInput{State: authz.FeatureDisabled, Config: []byte(`{}`)})
	require.ErrorIs(t, err, ErrFeatureParentLocked)
	_, err = PutFeatureGrant(t.Context(), admin, global, authz.FeatureWiki, FeatureGrantInput{State: authz.FeatureEnabled, Config: []byte(`{}`)})
	require.ErrorIs(t, err, ErrRevisionConflict)
	require.NoError(t, ResetFeatureGrant(t.Context(), admin, global, authz.FeatureWiki, 1))
	policy, err = GetFeaturePolicy(t.Context(), authz.FeatureWiki, global)
	require.NoError(t, err)
	require.EqualValues(t, 2, policy.Grant.Revision)
	require.Equal(t, authz.FeatureInherited, policy.Grant.State)
	_, err = PutFeatureGrant(t.Context(), admin, global, authz.FeatureWiki, FeatureGrantInput{State: authz.FeatureDisabled, Config: []byte(`{}`)})
	require.ErrorIs(t, err, ErrRevisionConflict)
	count, err := db.GetEngine(t.Context()).Where("action LIKE ?", "enterprise:feature:grant:%").Count(new(audit_model.Event))
	require.NoError(t, err)
	require.EqualValues(t, 2, count)
	require.NoError(t, ResetFeatureGrant(t.Context(), admin, global, authz.FeatureWiki, 2))
	policy, err = GetFeaturePolicy(t.Context(), authz.FeatureWiki, global)
	require.NoError(t, err)
	require.EqualValues(t, 2, policy.Grant.Revision)
}

func TestFeatureGuardModes(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	_, err := PutFeatureGrant(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeSystem}, authz.FeatureWiki, FeatureGrantInput{State: authz.FeatureDisabled, Config: []byte(`{}`)})
	require.NoError(t, err)
	setting.EnterpriseAuthz.Enforce = false
	require.NoError(t, RequireRepoFeature(t.Context(), 1, authz.FeatureWiki))
	setting.EnterpriseAuthz.Enforce = true
	require.ErrorContains(t, RequireRepoFeature(t.Context(), 1, authz.FeatureWiki), "feature_disabled")
	setting.EnterpriseAuthz.FailClosedOnError = false
	require.ErrorContains(t, RequireRepoFeature(t.Context(), 1, authz.FeatureWiki), "feature_disabled")
	setting.EnterpriseAuthz.Enabled = false
	require.NoError(t, RequireRepoFeature(t.Context(), -1, "unknown"))
}

func TestFeatureIntentAndRollback(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	scope := authz_model.Scope{Type: authz_model.ScopeSystem}
	_, err := PutFeatureGrant(t.Context(), admin, scope, authz.FeatureIssues, FeatureGrantInput{State: authz.FeatureRequired, Config: []byte(`{}`)})
	require.NoError(t, err)
	setting.EnterpriseAuthz.Enforce = true
	require.ErrorContains(t, CheckRepoFeatureIntent(t.Context(), 1, authz.FeatureIssues, true, false), "feature_required")
	require.NoError(t, CheckRepoFeatureIntent(t.Context(), 1, authz.FeatureIssues, true, true))
	require.NoError(t, CheckRepoFeatureIntent(t.Context(), 1, authz.FeatureIssues, false, false))
	setting.EnterpriseAuthz.Enforce = false
	require.NoError(t, CheckRepoFeatureIntent(t.Context(), 1, authz.FeatureIssues, true, false))
	setting.Audit.RecordOutput = setting.AuditRecordOutputDisabled
	_, err = PutFeatureGrant(t.Context(), admin, scope, authz.FeatureIssues, FeatureGrantInput{State: authz.FeatureDisabled, Config: []byte(`{}`), ExpectedRevision: 1})
	require.ErrorIs(t, err, ErrPolicyStorage)
	policy, err := GetFeaturePolicy(t.Context(), authz.FeatureIssues, scope)
	require.NoError(t, err)
	require.EqualValues(t, 1, policy.Grant.Revision)
	require.EqualValues(t, 2, policy.PolicyRevision)
}

func TestFeatureCurrentOwnerAndHash(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	global := authz_model.Scope{Type: authz_model.ScopeSystem}
	_, err := PutFeatureGrant(t.Context(), admin, global, authz.FeatureGitleaksScan, FeatureGrantInput{State: authz.FeatureRequired, Config: []byte(`{"check_contexts":["ci/global"]}`)})
	require.NoError(t, err)
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 3}
	first, err := GetFeaturePolicy(t.Context(), authz.FeatureGitleaksScan, scope)
	require.NoError(t, err)
	second, err := GetFeaturePolicy(t.Context(), authz.FeatureGitleaksScan, scope)
	require.NoError(t, err)
	require.Equal(t, first.Hash, second.Hash)
	require.True(t, first.Pending)
	_, err = PutFeatureGrant(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeOrg, ID: 3}, authz.FeatureGitleaksScan, FeatureGrantInput{State: authz.FeatureRequired, Config: []byte(`{"check_contexts":["ci/org"]}`)})
	require.NoError(t, err)
	second, err = GetFeaturePolicy(t.Context(), authz.FeatureGitleaksScan, scope)
	require.NoError(t, err)
	require.Equal(t, []string{"ci/global", "ci/org"}, second.Effective.Config.CheckContexts)
	require.NotEqual(t, first.Hash, second.Hash)
	_, err = db.GetEngine(t.Context()).ID(3).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 2})
	require.NoError(t, err)
	transferred, err := GetFeaturePolicy(t.Context(), authz.FeatureGitleaksScan, scope)
	require.NoError(t, err)
	require.Equal(t, []string{"ci/global"}, transferred.Effective.Config.CheckContexts)
	require.NotEqual(t, second.Hash, transferred.Hash)
	require.EqualValues(t, 2, transferred.OwnerID)
}

func TestFeatureNativeFailureMatrix(t *testing.T) {
	enableObservation(t)
	for _, key := range []authz.FeatureKey{authz.FeatureIssues, authz.FeaturePullRequests, authz.FeatureWiki, authz.FeaturePackages, authz.FeatureWebhooks, authz.FeatureCISecretManagement, authz.FeatureRequiredStatusChecks} {
		setting.EnterpriseAuthz.Enforce = true
		setting.EnterpriseAuthz.FailClosedOnError = true
		require.NoError(t, RequireRepoFeature(t.Context(), 1, key))
		_, err := db.GetEngine(t.Context()).Where("`key` = ?", key).Cols("catalog_version").Update(&authz_model.FeatureDefinition{CatalogVersion: 99})
		require.NoError(t, err)
		require.ErrorContains(t, RequireRepoFeature(t.Context(), 1, key), "feature_policy_unavailable")
		setting.EnterpriseAuthz.Enforce = false
		require.NoError(t, RequireRepoFeature(t.Context(), 1, key))
		setting.EnterpriseAuthz.Enforce = true
		setting.EnterpriseAuthz.FailClosedOnError = false
		require.NoError(t, RequireRepoFeature(t.Context(), 1, key))
		_, err = db.GetEngine(t.Context()).Where("`key` = ?", key).Cols("catalog_version").Update(&authz_model.FeatureDefinition{CatalogVersion: authz.FeatureCatalogVersion})
		require.NoError(t, err)
	}
	for _, key := range []authz.FeatureKey{authz.FeatureIssues, authz.FeaturePullRequests, authz.FeatureWiki, authz.FeaturePackages, authz.FeatureWebhooks, authz.FeatureCISecretManagement, authz.FeatureRequiredStatusChecks} {
		setting.EnterpriseAuthz.Enforce = true
		setting.EnterpriseAuthz.FailClosedOnError = true
		setting.Audit.RecordOutput = setting.AuditRecordOutputDisabled
		require.ErrorContains(t, RequireRepoFeature(t.Context(), 1, key), "feature_policy_unavailable", key)
		setting.EnterpriseAuthz.Enforce = false
		require.NoError(t, RequireRepoFeature(t.Context(), 1, key), key)
		setting.EnterpriseAuthz.Enforce = true
		setting.EnterpriseAuthz.FailClosedOnError = false
		require.NoError(t, RequireRepoFeature(t.Context(), 1, key), key)
		setting.Audit.RecordOutput = setting.AuditRecordOutputDatabase
		setting.EnterpriseAuthz.FailClosedOnError = true
		expired, expire := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		require.ErrorContains(t, RequireRepoFeature(expired, 1, key), "feature_policy_unavailable", key)
		setting.EnterpriseAuthz.Enforce = false
		require.NoError(t, RequireRepoFeature(expired, 1, key), key)
		expire()
		setting.EnterpriseAuthz.Enforce = true
		canceled, cancel := context.WithCancel(t.Context())
		cancel()
		setting.EnterpriseAuthz.FailClosedOnError = false
		require.ErrorContains(t, RequireRepoFeature(canceled, 1, key), "invalid_feature_context", key)
		setting.EnterpriseAuthz.Enforce = false
		require.NoError(t, RequireRepoFeature(canceled, 1, key), key)
		setting.EnterpriseAuthz.Enabled = false
		require.NoError(t, RequireRepoFeature(expired, 1, key), key)
		setting.EnterpriseAuthz.Enabled = true
	}
}

func TestFeatureManagementAuthorityAndCeiling(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	require.NoError(t, db.Insert(t.Context(), &repo_model.Collaboration{RepoID: 1, UserID: 4, Mode: perm.AccessModeAdmin}))
	require.NoError(t, db.Insert(t.Context(), &access_model.Access{RepoID: 1, UserID: 4, Mode: perm.AccessModeAdmin}))
	input := FeatureGrantInput{State: authz.FeatureEnabled, Config: []byte(`{}`)}
	_, err := PutFeatureGrant(t.Context(), actor, scope, authz.FeatureWiki, input)
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	role, err := CreateRole(t.Context(), owner, scope, CreateRoleInput{Name: "Feature manager", Permissions: &[]PermissionInput{{Action: authz.ManageFeatureGrant, Effect: "allow"}}})
	require.NoError(t, err)
	_, _, err = PutBinding(t.Context(), owner, scope, BindingInput{SubjectType: authz_model.SubjectUser, SubjectID: 4, RoleID: role.Definition.ID})
	require.NoError(t, err)
	_, err = PutFeatureGrant(t.Context(), actor, scope, authz.FeatureWiki, input)
	require.NoError(t, err)
	ctx := reqctx.NewRequestContextForTest(t)
	ctx.GetData()["ApiTokenScope"] = auth_model.AccessTokenScopeReadRepository
	_, err = PutFeatureGrant(ctx, owner, scope, authz.FeatureIssues, input)
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	ctx.GetData()["ApiTokenScope"] = auth_model.AccessTokenScope("public-only,write:repository")
	_, err = PutFeatureGrant(ctx, owner, scope, authz.FeatureIssues, input)
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	_, err = PutFeatureGrant(t.Context(), actor, authz_model.Scope{Type: authz_model.ScopeSystem}, authz.FeatureIssues, input)
	require.ErrorIs(t, err, util.ErrPermissionDenied)
	_, err = db.GetEngine(t.Context()).ID(actor.ID).Cols("is_active").Update(&user_model.User{IsActive: false})
	require.NoError(t, err)
	_, err = PutFeatureGrant(t.Context(), actor, scope, authz.FeatureIssues, input)
	require.ErrorIs(t, err, util.ErrPermissionDenied)
}

func TestFeatureRequiredNeverCreatesNativeUnits(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	_, err := db.GetEngine(t.Context()).Where("repo_id = ? AND type = ?", 1, unit.TypeWiki).Delete(new(repo_model.RepoUnit))
	require.NoError(t, err)
	_, err = PutFeatureGrant(t.Context(), actor, authz_model.Scope{Type: authz_model.ScopeSystem}, authz.FeatureWiki, FeatureGrantInput{State: authz.FeatureRequired, Config: []byte(`{}`)})
	require.NoError(t, err)
	policy, err := GetFeaturePolicy(t.Context(), authz.FeatureWiki, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1})
	require.NoError(t, err)
	require.True(t, policy.Pending)
	require.False(t, policy.NativeAvailable)
	unittest.AssertCount(t, &repo_model.RepoUnit{RepoID: 1, Type: unit.TypeWiki}, 0)
}

func TestFeatureAuditFailureRollsBackRevision(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	scope := authz_model.Scope{Type: authz_model.ScopeSystem}
	_, err := PutFeatureGrant(t.Context(), actor, scope, authz.FeatureWiki, FeatureGrantInput{State: authz.FeatureEnabled, Config: []byte(`{}`)})
	require.NoError(t, err)
	hook := &featureAuditFailure{enabled: true}
	x := db.GetXORMEngineForTesting()
	x.AddHook(hook)
	t.Cleanup(func() { hook.enabled = false })
	_, err = PutFeatureGrant(t.Context(), actor, scope, authz.FeatureWiki, FeatureGrantInput{State: authz.FeatureDisabled, Config: []byte(`{}`), ExpectedRevision: 1})
	require.ErrorIs(t, err, ErrPolicyStorage)
	require.True(t, hook.fired)
	hook.enabled = false
	policy, err := GetFeaturePolicy(t.Context(), authz.FeatureWiki, scope)
	require.NoError(t, err)
	require.EqualValues(t, 1, policy.Grant.Revision)
	require.EqualValues(t, 2, policy.PolicyRevision)
	require.Equal(t, authz.FeatureEnabled, policy.Grant.State)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseFeatureGrantUpdate}, 1)
}

type featureAuditFailure struct{ enabled, fired bool }

func (h *featureAuditFailure) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.enabled && strings.HasPrefix(c.SQL, "INSERT INTO") && strings.Contains(c.SQL, "audit_event") {
		h.fired = true
		return c.Ctx, errors.New("injected_audit_failure")
	}
	return c.Ctx, nil
}
func (*featureAuditFailure) AfterProcess(*contexts.ContextHook) error { return nil }

func TestFeatureRequiredPendingUsesNativeConfiguration(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	for _, key := range []authz.FeatureKey{authz.FeatureCISecretManagement, authz.FeatureWebhooks, authz.FeatureRequiredStatusChecks} {
		_, err := PutFeatureGrant(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeSystem}, key, FeatureGrantInput{State: authz.FeatureRequired, Config: []byte(`{}`)})
		require.NoError(t, err)
	}
	_, err := db.Exec(t.Context(), "DELETE FROM secret WHERE repo_id=?", 1)
	require.NoError(t, err)
	_, err = db.Exec(t.Context(), "DELETE FROM webhook WHERE repo_id=?", 1)
	require.NoError(t, err)
	_, err = db.Exec(t.Context(), "DELETE FROM protected_branch WHERE repo_id=?", 1)
	require.NoError(t, err)
	for _, key := range []authz.FeatureKey{authz.FeatureCISecretManagement, authz.FeatureWebhooks, authz.FeatureRequiredStatusChecks} {
		p, err := GetFeaturePolicy(t.Context(), key, scope)
		require.NoError(t, err)
		require.False(t, p.NativeAvailable, "%s", key)
		require.True(t, p.Pending, "%s", key)
	}
	_, err = db.GetEngine(t.Context()).Where("repo_id=? AND type=?", 1, unit.TypeWiki).Delete(new(repo_model.RepoUnit))
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &repo_model.RepoUnit{RepoID: 1, Type: unit.TypeExternalWiki, Config: &repo_model.ExternalWikiConfig{ExternalWikiURL: "https://example.com/wiki"}}))
	p, err := GetFeaturePolicy(t.Context(), authz.FeatureWiki, scope)
	require.NoError(t, err)
	require.True(t, p.NativeAvailable)
}

func TestFeatureIntentDenySurvivesBusinessRollback(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	setting.EnterpriseAuthz.Enforce = true
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	_, err := PutFeatureGrant(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeSystem}, authz.FeatureWiki, FeatureGrantInput{State: authz.FeatureRequired, Config: []byte(`{}`)})
	require.NoError(t, err)
	require.ErrorContains(t, db.WithTx(t.Context(), func(tx context.Context) error { return CheckRepoFeatureIntent(tx, 1, authz.FeatureWiki, true, false) }), "feature_required")
	var events []*audit_model.Event
	err = db.GetEngine(t.Context()).Where("action=?", audit_model.EnterpriseFeatureDecision).Find(&events)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Contains(t, events[0].Metadata, `"outcome":"denied"`)
	require.Contains(t, events[0].Metadata, `"phase":"terminal"`)
}

func TestFeatureShadowUnitIntentObservesWithoutChangingNative(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	_, err := PutFeatureGrant(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeSystem}, authz.FeatureIssues, FeatureGrantInput{State: authz.FeatureRequired, Config: []byte(`{}`)})
	require.NoError(t, err)
	applied := false
	require.NoError(t, WithRepoFeatureConfiguration(t.Context(), 1, nil, []unit.Type{unit.TypeIssues}, func(context.Context) error {
		applied = true
		return nil
	}))
	require.True(t, applied)
	var events []audit_model.Event
	require.NoError(t, db.GetEngine(t.Context()).Where("action=? AND scope_type=? AND scope_id=?", audit_model.EnterpriseFeatureDecision, audit_model.ScopeRepository, 1).Find(&events))
	require.Len(t, events, 1)
	require.Contains(t, events[0].Metadata, `"candidate_decision":"deny"`)
	require.Contains(t, events[0].Metadata, `"actual_decision":"native"`)
	require.Contains(t, events[0].Metadata, `"reason":"feature_required"`)
	setting.Audit.RecordOutput = setting.AuditRecordOutputDisabled
	applied = false
	require.NoError(t, WithRepoFeatureConfiguration(t.Context(), 1, nil, []unit.Type{unit.TypeIssues}, func(context.Context) error {
		applied = true
		return nil
	}))
	require.True(t, applied)
}
