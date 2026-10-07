// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"
	"strings"
	"testing"

	"gitea.dev/models/db"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

func TestMergeGateTransferLockOrder(t *testing.T) {
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	hook := &mergeGateLifecycleLocks{enabled: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	t.Cleanup(func() { hook.enabled = false })
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, db.WithTx(t.Context(), func(tx context.Context) error { return lockTransferPurpose(tx, actor, repo, actor.ID) }))
	require.NotEmpty(t, hook.tables)
	require.Equal(t, "feature", hook.tables[0])
}

func TestMergeGateCreationLockOrder(t *testing.T) {
	ctx := enforceLifecycle(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true}))
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	hook := &mergeGateLifecycleLocks{enabled: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	t.Cleanup(func() { hook.enabled = false })
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repo := &repo_model.Repository{Owner: owner, OwnerID: owner.ID, OwnerName: owner.Name, Name: "gate-lock-order", LowerName: "gate-lock-order", IsPrivate: true}
	require.NoError(t, db.WithTx(ctx, func(tx context.Context) error { return createRepositoryInDB(tx, owner, owner, repo, false) }))
	require.NotEmpty(t, hook.tables)
	require.Equal(t, "feature", hook.tables[0])
}

type mergeGateLifecycleLocks struct {
	enabled bool
	tables  []string
}

func (h *mergeGateLifecycleLocks) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.enabled && strings.HasPrefix(c.SQL, "UPDATE") {
		if strings.Contains(c.SQL, "enterprise_feature_definition") {
			h.tables = append(h.tables, "feature")
		} else if strings.Contains(c.SQL, "id=id") {
			h.tables = append(h.tables, "resource")
		}
	}
	return c.Ctx, nil
}

func (*mergeGateLifecycleLocks) AfterProcess(*contexts.ContextHook) error { return nil }
