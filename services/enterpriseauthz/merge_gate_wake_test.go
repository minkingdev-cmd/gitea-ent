// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/automergequeue"

	"github.com/stretchr/testify/require"
)

func TestMergeGatePolicyWakeRequiresCommit(t *testing.T) {
	enableMergeGate(t)
	setting.EnterpriseMergeGate.Enforce = true
	var items []automergequeue.AutoMergeItem
	t.Cleanup(test.MockVariableValue(&automergequeue.AddToQueue, func(item automergequeue.AutoMergeItem) { items = append(items, item) }))
	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	scope := authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}
	require.NoError(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		_, err := PutFeatureGrant(ctx, actor, scope, authz.FeatureGitleaksScan, FeatureGrantInput{State: authz.FeatureEnabled, Config: []byte(`{}`)})
		require.NoError(t, err)
		require.Empty(t, items)
		return nil
	}))
	require.Len(t, items, 1)
	require.True(t, strings.HasPrefix(string(items[0]), "gate-scope:repo:1:"))
	rollback := errors.New("rollback policy change")
	require.ErrorIs(t, db.WithTx(t.Context(), func(ctx context.Context) error {
		_, err := PutFeatureGrant(ctx, actor, scope, authz.FeatureGitleaksScan, FeatureGrantInput{State: authz.FeatureDisabled, ExpectedRevision: 1, Config: []byte(`{}`)})
		require.NoError(t, err)
		return rollback
	}), rollback)
	require.Len(t, items, 1)
}
