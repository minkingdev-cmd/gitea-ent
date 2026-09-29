// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"testing"

	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestCanManageProtectedUserAllowsWhenWeComIsDisabledOrUnconfigured(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()

	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	target := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})

	require.NoError(t, CanManageProtectedUser(t.Context(), actor, target, ProtectedUserOpEdit))
	protected, err := IsProtectedAdminUser(t.Context(), target.ID)
	require.NoError(t, err)
	require.False(t, protected)
}

func TestCanManageProtectedUserDeniesOtherAdminAndDestructiveSelfOperation(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockProtectedAdminSettings(t)

	actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	target := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: target.ID, CorpID: "corp-protected", WeComUserID: "guard.admin", LoginSourceID: 1, Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	require.NoError(t, dbInsertAdminAuthority(t, "guard.admin", true, true))

	err = CanManageProtectedUser(t.Context(), actor, target, ProtectedUserOpBadge)
	var denied *ProtectedUserDeniedError
	require.ErrorAs(t, err, &denied)
	require.Equal(t, ProtectedUserOpBadge, denied.Operation)
	require.Equal(t, ProtectedUserDenyOtherAdmin, denied.Reason)
	require.Equal(t, target.ID, denied.TargetID)
	require.Equal(t, map[string]any{
		"operation": ProtectedUserOpBadge,
		"reason":    ProtectedUserDenyOtherAdmin,
		"target_id": target.ID,
		"outcome":   "denied",
	}, denied.SafeAuditMetadata())

	require.NoError(t, CanManageProtectedUser(t.Context(), target, target, ProtectedUserOpEdit))
	err = CanManageProtectedUser(t.Context(), target, target, ProtectedUserOpDemoteSelf)
	require.ErrorAs(t, err, &denied)
	require.Equal(t, ProtectedUserDenySelfDemotion, denied.Reason)
	require.NotErrorIs(t, err, ErrWeComDenied)
}
