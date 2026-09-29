// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"errors"
	"testing"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/timeutil"

	"github.com/stretchr/testify/require"
)

type fakeAdminAuthorityClient struct {
	admins []AppAdminInfo
	err    error
}

func (f fakeAdminAuthorityClient) ListAppAdmins(context.Context) ([]AppAdminInfo, error) {
	return f.admins, f.err
}

func mockAuthoritySettings(t *testing.T) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:    true,
		CorpID:     "corp-auth",
		AgentID:    "1000002",
		CorpSecret: "secret",
	}))
}

func TestRefreshAdminAuthoritySnapshotPersistsManagementAndMessageOnlyAdmins(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockAuthoritySettings(t)

	result, err := RefreshAdminAuthoritySnapshot(t.Context(), fakeAdminAuthorityClient{admins: []AppAdminInfo{
		{UserID: "zhang.super", OpenUserID: "open-zhang", AuthType: 1},
		{UserID: "bot.notice", AuthType: 0},
	}}, AdminAuthorityRefreshOptions{Trigger: "cron", RunID: "run-1", Now: timeutil.TimeStamp(1780000000)})
	require.NoError(t, err)
	require.Equal(t, 2, result.Total)
	require.Equal(t, 1, result.ManagementCount)
	require.Equal(t, 1, result.MessageOnlyCount)

	var rows []wecom_model.AdminAuthority
	require.NoError(t, db.GetEngine(t.Context()).Where("corp_id = ?", "corp-auth").OrderBy("wecom_userid").Find(&rows))
	require.Len(t, rows, 2)
	require.False(t, rows[0].IsManagement)
	require.Equal(t, wecom_model.AdminAuthorityAuthTypeMessage, rows[0].AuthType)
	require.True(t, rows[1].IsManagement)
	require.Equal(t, "open-zhang", rows[1].OpenUserID)
	require.Equal(t, "run-1", rows[1].RefreshID)
}

func TestRefreshAdminAuthoritySnapshotIncludesMultipleManagementAdmins(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockAuthoritySettings(t)

	result, err := RefreshAdminAuthoritySnapshot(t.Context(), fakeAdminAuthorityClient{admins: []AppAdminInfo{
		{UserID: "admin.one", AuthType: 1},
		{UserID: "admin.two", AuthType: 1},
	}}, AdminAuthorityRefreshOptions{RunID: "multi-management", Now: timeutil.TimeStamp(1780000000)})
	require.NoError(t, err)
	require.Equal(t, 2, result.ManagementCount)

	count, err := db.GetEngine(t.Context()).Where("corp_id = ? AND is_management = ? AND is_active = ?", "corp-auth", true, true).Count(new(wecom_model.AdminAuthority))
	require.NoError(t, err)
	require.EqualValues(t, 2, count)
}

func TestRefreshAdminAuthoritySnapshotMarksMissingRowsInactiveAfterSuccessfulCompleteRefresh(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockAuthoritySettings(t)

	_, err := RefreshAdminAuthoritySnapshot(t.Context(), fakeAdminAuthorityClient{admins: []AppAdminInfo{
		{UserID: "old.admin", AuthType: 1},
		{UserID: "new.admin", AuthType: 1},
	}}, AdminAuthorityRefreshOptions{RunID: "initial", Now: timeutil.TimeStamp(1780000000)})
	require.NoError(t, err)

	result, err := RefreshAdminAuthoritySnapshot(t.Context(), fakeAdminAuthorityClient{admins: []AppAdminInfo{
		{UserID: "new.admin", AuthType: 1},
	}}, AdminAuthorityRefreshOptions{RunID: "second", Now: timeutil.TimeStamp(1780000100)})
	require.NoError(t, err)
	require.EqualValues(t, 1, result.DeactivatedMissing)

	oldAdmin := &wecom_model.AdminAuthority{CorpID: "corp-auth", AgentID: "1000002", WeComUserID: "old.admin"}
	has, err := db.GetEngine(t.Context()).Get(oldAdmin)
	require.NoError(t, err)
	require.True(t, has)
	require.False(t, oldAdmin.IsActive)
	require.Equal(t, "second", oldAdmin.RefreshID)

	newAdmin := &wecom_model.AdminAuthority{CorpID: "corp-auth", AgentID: "1000002", WeComUserID: "new.admin"}
	has, err = db.GetEngine(t.Context()).Get(newAdmin)
	require.NoError(t, err)
	require.True(t, has)
	require.True(t, newAdmin.IsActive)
}

func TestRefreshAdminAuthoritySnapshotFailurePreservesPreviousSnapshot(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockAuthoritySettings(t)

	_, err := RefreshAdminAuthoritySnapshot(t.Context(), fakeAdminAuthorityClient{admins: []AppAdminInfo{
		{UserID: "stable.admin", AuthType: 1},
	}}, AdminAuthorityRefreshOptions{RunID: "initial", Now: timeutil.TimeStamp(1780000000)})
	require.NoError(t, err)

	_, err = RefreshAdminAuthoritySnapshot(t.Context(), fakeAdminAuthorityClient{err: errors.New("provider unavailable")}, AdminAuthorityRefreshOptions{RunID: "failed", Now: timeutil.TimeStamp(1780000100)})
	require.Error(t, err)

	admin := &wecom_model.AdminAuthority{CorpID: "corp-auth", AgentID: "1000002", WeComUserID: "stable.admin"}
	has, err := db.GetEngine(t.Context()).Get(admin)
	require.NoError(t, err)
	require.True(t, has)
	require.True(t, admin.IsActive)
	require.Equal(t, "initial", admin.RefreshID)
	require.Equal(t, timeutil.TimeStamp(1780000000), admin.LastRefreshUnix)
}

func TestRefreshAdminAuthoritySnapshotReportsUnsupportedAuthoritySource(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockAuthoritySettings(t)

	_, err := RefreshAdminAuthoritySnapshot(t.Context(), nil, AdminAuthorityRefreshOptions{})
	require.ErrorIs(t, err, ErrWeComAuthorityUnsupported)
}

func TestHandleAdminAuthorityCallbackValidatesBoundaryAndRefreshesFromAPI(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockAuthoritySettings(t)

	result, err := HandleAdminAuthorityCallback(t.Context(), fakeAdminAuthorityClient{admins: []AppAdminInfo{
		{UserID: "callback.admin", AuthType: 1},
	}}, AdminAuthorityCallback{
		Validated: true,
		CorpID:    "corp-auth",
		AgentID:   "1000002",
		Event:     WeComChangeAppAdminEvent,
		TriggerID: "callback-run",
	})
	require.NoError(t, err)
	require.Equal(t, 1, result.ManagementCount)

	admin := &wecom_model.AdminAuthority{CorpID: "corp-auth", AgentID: "1000002", WeComUserID: "callback.admin"}
	has, err := db.GetEngine(t.Context()).Get(admin)
	require.NoError(t, err)
	require.True(t, has)
	require.True(t, admin.IsManagement)
	require.Equal(t, "callback", admin.RefreshTrigger)
	require.Equal(t, "callback-run", admin.RefreshID)
}

func TestHandleAdminAuthorityCallbackRejectsUnvalidatedOrMismatchedCallback(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockAuthoritySettings(t)

	_, err := HandleAdminAuthorityCallback(t.Context(), fakeAdminAuthorityClient{}, AdminAuthorityCallback{Event: WeComChangeAppAdminEvent})
	require.ErrorIs(t, err, ErrWeComDenied)

	_, err = HandleAdminAuthorityCallback(t.Context(), fakeAdminAuthorityClient{}, AdminAuthorityCallback{Validated: true, CorpID: "other-corp", Event: WeComChangeAppAdminEvent})
	require.ErrorIs(t, err, ErrWeComDenied)

	_, err = HandleAdminAuthorityCallback(t.Context(), fakeAdminAuthorityClient{}, AdminAuthorityCallback{Validated: true, CorpID: "corp-auth", Event: "change_contact"})
	require.ErrorIs(t, err, ErrWeComDenied)

	count, err := db.GetEngine(t.Context()).Count(new(wecom_model.AdminAuthority))
	require.NoError(t, err)
	require.Zero(t, count)
}
