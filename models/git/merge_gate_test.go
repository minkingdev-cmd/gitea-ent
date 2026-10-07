// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package git

import (
	"context"
	"errors"
	"strings"
	"testing"

	"gitea.dev/models/db"
	access_model "gitea.dev/models/perm/access"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

func TestMergeGateWhitelistReadsPreserveErrors(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	pb := &ProtectedBranch{EnableMergeWhitelist: true, MergeWhitelistTeamIDs: []int64{1}, EnableBypassAllowlist: true, BypassAllowlistTeamIDs: []int64{1}}
	actor := &user_model.User{ID: 4}
	hook := &mergeGateTeamReadFault{active: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	defer func() { hook.active = false }()
	allowed, err := IsUserMergeWhitelistedWithError(t.Context(), pb, actor.ID, access_model.Permission{})
	require.Error(t, err)
	require.False(t, allowed)
	allowed, err = CanBypassBranchProtectionWithError(t.Context(), pb, actor, false)
	require.Error(t, err)
	require.False(t, allowed)
	require.False(t, IsUserMergeWhitelisted(t.Context(), pb, actor.ID, access_model.Permission{}))
	require.False(t, CanBypassBranchProtection(t.Context(), pb, actor, false))
	pb.MergeWhitelistUserIDs = []int64{4}
	allowed, err = IsUserMergeWhitelistedWithError(t.Context(), pb, actor.ID, access_model.Permission{})
	require.NoError(t, err)
	require.True(t, allowed)
}

type mergeGateTeamReadFault struct{ active bool }

func (h *mergeGateTeamReadFault) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.active && strings.HasPrefix(c.SQL, "SELECT") && strings.Contains(c.SQL, "team_user") {
		return c.Ctx, errors.New("team storage failure")
	}
	return c.Ctx, nil
}
func (*mergeGateTeamReadFault) AfterProcess(*contexts.ContextHook) error { return nil }
