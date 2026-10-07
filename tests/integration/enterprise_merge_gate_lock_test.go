// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	authz_service "gitea.dev/services/enterpriseauthz"
	repo_service "gitea.dev/services/repository"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

type mergeGateLockTestKey struct{}

type mergeGateConcurrentLockHook struct {
	enabled                 atomic.Bool
	configurationFeature    atomic.Bool
	repositoryBeforeFeature atomic.Bool
	first                   sync.Once
	second                  sync.Once
	held                    chan struct{}
	waiting                 chan struct{}
	release                 chan struct{}
}

func (h *mergeGateConcurrentLockHook) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	marker := c.Ctx.Value(mergeGateLockTestKey{})
	if !h.enabled.Load() || (marker != "configuration" && marker != "delete" && marker != "create") || !strings.HasPrefix(c.SQL, "UPDATE") {
		return c.Ctx, nil
	}
	if strings.Contains(c.SQL, "enterprise_feature_definition") {
		h.configurationFeature.Store(true)
		h.second.Do(func() { close(h.waiting) })
	} else if (strings.Contains(c.SQL, "repository") || strings.Contains(c.SQL, "user") && strings.Contains(c.SQL, "id=id")) && !h.configurationFeature.Load() {
		h.repositoryBeforeFeature.Store(true)
		if c.Ctx.Value(mergeGateLockTestKey{}) == "delete" {
			h.second.Do(func() { close(h.waiting) })
		}
	}
	return c.Ctx, nil
}

func TestEnterpriseMergeGatePGRuleAndRepositoryCreationLockOrder(t *testing.T) {
	if !setting.Database.Type.IsPostgreSQL() {
		t.Skip("requires PostgreSQL row-lock concurrency")
	}
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	setting.EnterpriseAuthz.Enforce = true
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 3})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 3}
	role, err := authz_service.CreateRole(t.Context(), actor, scope, authz_service.CreateRoleInput{Name: "Create race reviewer"})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	hook := &mergeGateConcurrentLockHook{held: make(chan struct{}), waiting: make(chan struct{}), release: make(chan struct{})}
	hook.enabled.Store(true)
	db.GetXORMEngineForTesting().AddHook(hook)
	defer hook.enabled.Store(false)
	var release sync.Once
	defer release.Do(func() { close(hook.release) })
	ruleDone, createDone := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := authz_service.PutProtectedPathRule(context.WithValue(ctx, mergeGateLockTestKey{}, "rule"), actor, scope, 0, authz_service.ProtectedPathRuleInput{Config: []byte(fmt.Sprintf(`{"path_pattern":"k8s/**","required_role_id":%d}`, role.Definition.ID))})
		ruleDone <- err
	}()
	select {
	case <-hook.held:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	go func() {
		_, err := repo_service.CreateRepositoryDirectly(context.WithValue(ctx, mergeGateLockTestKey{}, "create"), actor, owner, repo_service.CreateRepoOptions{Name: "gate-create-lock", IsPrivate: true}, false)
		createDone <- err
	}()
	select {
	case <-hook.waiting:
	case err := <-createDone:
		t.Fatalf("creation did not wait for policy locks: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.False(t, hook.repositoryBeforeFeature.Load())
	release.Do(func() { close(hook.release) })
	for _, done := range []chan error{ruleDone, createDone} {
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func TestEnterpriseMergeGatePGRuleAndRepositoryDeletionLockOrder(t *testing.T) {
	if !setting.Database.Type.IsPostgreSQL() {
		t.Skip("requires PostgreSQL row-lock concurrency")
	}
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 3}
	role, err := authz_service.CreateRole(t.Context(), owner, scope, authz_service.CreateRoleInput{Name: "Delete race reviewer"})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	hook := &mergeGateConcurrentLockHook{held: make(chan struct{}), waiting: make(chan struct{}), release: make(chan struct{})}
	hook.enabled.Store(true)
	db.GetXORMEngineForTesting().AddHook(hook)
	defer hook.enabled.Store(false)
	var release sync.Once
	defer release.Do(func() { close(hook.release) })
	ruleDone, deleteDone := make(chan error, 1), make(chan error, 1)
	go func() {
		_, err := authz_service.PutProtectedPathRule(context.WithValue(ctx, mergeGateLockTestKey{}, "rule"), owner, scope, 0, authz_service.ProtectedPathRuleInput{Config: []byte(fmt.Sprintf(`{"path_pattern":"k8s/**","required_role_id":%d}`, role.Definition.ID))})
		ruleDone <- err
	}()
	select {
	case <-hook.held:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	go func() {
		deleteDone <- repo_service.DeleteRepositoryDirectly(context.WithValue(ctx, mergeGateLockTestKey{}, "delete"), scope.ID)
	}()
	select {
	case <-hook.waiting:
	case err := <-deleteDone:
		t.Fatalf("deletion did not wait for policy locks: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	wrongOrder := hook.repositoryBeforeFeature.Load()
	release.Do(func() { close(hook.release) })
	for _, done := range []chan error{ruleDone, deleteDone} {
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	require.False(t, wrongOrder, "repository deletion must lock the policy scopes before its repository row")
}

func (h *mergeGateConcurrentLockHook) AfterProcess(c *contexts.ContextHook) error {
	if h.enabled.Load() && c.Ctx.Value(mergeGateLockTestKey{}) == "rule" && strings.HasPrefix(c.SQL, "UPDATE") && strings.Contains(c.SQL, "enterprise_feature_definition") {
		h.first.Do(func() {
			close(h.held)
			select {
			case <-h.release:
			case <-c.Ctx.Done():
			}
		})
	}
	return nil
}

func TestEnterpriseMergeGatePGRuleAndConfigurationLockOrder(t *testing.T) {
	if !setting.Database.Type.IsPostgreSQL() {
		t.Skip("requires PostgreSQL row-lock concurrency")
	}
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	setting.EnterpriseAuthz.Enforce = true
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	role, err := authz_service.CreateRole(t.Context(), owner, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}, authz_service.CreateRoleInput{Name: "Concurrent reviewer"})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	hook := &mergeGateConcurrentLockHook{held: make(chan struct{}), waiting: make(chan struct{}), release: make(chan struct{})}
	hook.enabled.Store(true)
	db.GetXORMEngineForTesting().AddHook(hook)
	defer hook.enabled.Store(false)
	var release sync.Once
	defer release.Do(func() { close(hook.release) })
	ruleDone := make(chan error, 1)
	go func() {
		_, err := authz_service.PutProtectedPathRule(context.WithValue(ctx, mergeGateLockTestKey{}, "rule"), owner, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}, 0, authz_service.ProtectedPathRuleInput{Config: []byte(fmt.Sprintf(`{"path_pattern":"k8s/**","required_role_id":%d}`, role.Definition.ID))})
		ruleDone <- err
	}()
	select {
	case <-hook.held:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	configurationDone := make(chan error, 1)
	go func() {
		configurationDone <- authz_service.WithRepoFeatureConfiguration(context.WithValue(ctx, mergeGateLockTestKey{}, "configuration"), 1, nil, nil, func(context.Context) error { return nil })
	}()
	select {
	case <-hook.waiting:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.False(t, hook.repositoryBeforeFeature.Load())
	release.Do(func() { close(hook.release) })
	select {
	case err := <-ruleDone:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case err := <-configurationDone:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
}

func TestEnterpriseMergeGatePGConcurrentRevisionAndRoleReference(t *testing.T) {
	if !setting.Database.Type.IsPostgreSQL() {
		t.Skip("requires PostgreSQL concurrent transactions")
	}
	defer tests.PrepareTestEnv(t)()
	featureTestMode(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	role, err := authz_service.CreateRole(t.Context(), owner, scope, authz_service.CreateRoleInput{Name: "CAS reviewer"})
	require.NoError(t, err)
	config := []byte(fmt.Sprintf(`{"path_pattern":"k8s/**","required_role_id":%d}`, role.Definition.ID))
	rule, err := authz_service.PutProtectedPathRule(t.Context(), owner, scope, 0, authz_service.ProtectedPathRuleInput{Config: config})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, pattern := range []string{"a/**", "b/**"} {
		go func() {
			<-start
			_, err := authz_service.PutProtectedPathRule(ctx, owner, scope, rule.ID, authz_service.ProtectedPathRuleInput{Config: []byte(fmt.Sprintf(`{"path_pattern":%q,"required_role_id":%d}`, pattern, role.Definition.ID)), ExpectedRevision: 1})
			results <- err
		}()
	}
	close(start)
	success, conflicts := 0, 0
	for range 2 {
		select {
		case err := <-results:
			if err == nil {
				success++
			} else {
				require.ErrorIs(t, err, authz_service.ErrRevisionConflict)
				conflicts++
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	require.Equal(t, 1, success)
	require.Equal(t, 1, conflicts)
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	upperRole, err := authz_service.CreateRole(ctx, admin, authz_model.Scope{Type: authz_model.ScopeSystem}, authz_service.CreateRoleInput{Name: "Upper scope reviewer"})
	require.NoError(t, err)
	start = make(chan struct{})
	for _, upperScope := range []authz_model.Scope{{Type: authz_model.ScopeSystem}, {Type: authz_model.ScopeOrg, ID: 3}} {
		go func() {
			<-start
			_, err := authz_service.PutProtectedPathRule(ctx, admin, upperScope, 0, authz_service.ProtectedPathRuleInput{Config: []byte(fmt.Sprintf(`{"path_pattern":"**","required_role_id":%d}`, upperRole.Definition.ID))})
			results <- err
		}()
	}
	close(start)
	for range 2 {
		select {
		case err := <-results:
			require.NoError(t, err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	policies, err := authz_service.EffectiveProtectedPathRules(ctx, 3)
	require.NoError(t, err)
	require.Len(t, policies, 2)
	otherRole, err := authz_service.CreateRole(ctx, owner, scope, authz_service.CreateRoleInput{Name: "Reference reviewer"})
	require.NoError(t, err)
	start = make(chan struct{})
	create := make(chan error, 1)
	remove := make(chan error, 1)
	go func() {
		<-start
		_, err := authz_service.PutProtectedPathRule(ctx, owner, scope, 0, authz_service.ProtectedPathRuleInput{Config: []byte(fmt.Sprintf(`{"path_pattern":"**","required_role_id":%d}`, otherRole.Definition.ID))})
		create <- err
	}()
	go func() { <-start; remove <- authz_service.DeleteRole(ctx, owner, scope, otherRole.Definition.ID, 1) }()
	close(start)
	var createErr, removeErr error
	select {
	case createErr = <-create:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case removeErr = <-remove:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if createErr == nil {
		require.ErrorIs(t, removeErr, authz_service.ErrRoleReferenced)
	} else {
		require.NoError(t, removeErr)
		require.ErrorIs(t, createErr, authz_service.ErrInvalidPolicy)
	}
}
