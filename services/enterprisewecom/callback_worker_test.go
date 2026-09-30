// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"errors"
	"testing"
	"time"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/timeutil"

	"github.com/stretchr/testify/require"
)

func mockCallbackSettings(t *testing.T) {
	t.Helper()
	cfg := callbackTestConfig()
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: cfg.CorpID, AgentID: cfg.AgentID, AdminCallbackEnabled: true, AdminCallbackToken: cfg.Token, AdminCallbackAESKey: cfg.AESKey, AdminCallbackReceiverID: cfg.ReceiverID}))
}

func TestCallbackWorkerDurableRetryRecoveryAndCurrentAuthority(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockCallbackSettings(t)
	ctx := t.Context()
	now := timeutil.TimeStamp(1780000000)
	enc := callbackTestEncrypted(t, callbackTestEvent, callbackTestConfig().ReceiverID, "1234567890123456")
	verified, err := VerifyAdminCallbackEvent(callbackTestConfig(), callbackTestQuery(enc), []byte(`<xml><Encrypt>`+enc+`</Encrypt></xml>`), time.Unix(int64(now), 0))
	require.NoError(t, err)
	receipt, err := AcceptAdminCallback(ctx, verified, now)
	require.NoError(t, err)
	client := fakeAdminAuthorityClient{err: errors.New("secret=private-token user@example.org")}
	intervals := []int64{1, 5, 30, 120, 300}
	for i := range 6 {
		require.NoError(t, processAdminCallback(ctx, client, receipt.ID, now))
		stored := new(wecom_model.CallbackReceipt)
		has, err := db.GetEngine(ctx).ID(receipt.ID).Get(stored)
		require.NoError(t, err)
		require.True(t, has)
		require.Equal(t, i+1, stored.Attempts)
		require.NotContains(t, stored.Reason, "private-token")
		if i < 5 {
			require.Equal(t, wecom_model.CallbackReceiptPending, stored.Status)
			require.Equal(t, now+timeutil.TimeStamp(intervals[i]), stored.NextRetryUnix)
			now = stored.NextRetryUnix
		} else {
			require.Equal(t, wecom_model.CallbackReceiptFailed, stored.Status)
		}
	}
	verified.dedupKey = "different-event"
	receipt, err = AcceptAdminCallback(ctx, verified, now)
	require.NoError(t, err)
	// durable受理不需要queue唤醒才能在下一次扫描恢复。
	due, err := wecom_model.DueCallbackReceipts(ctx, setting.EnterpriseWeCom.CorpID, setting.EnterpriseWeCom.AgentID, now)
	require.NoError(t, err)
	require.Len(t, due, 1)
	require.NoError(t, processAdminCallback(ctx, fakeAdminAuthorityClient{admins: []AppAdminInfo{{UserID: "current-admin", AuthType: 1}}}, receipt.ID, now))
	stored := new(wecom_model.CallbackReceipt)
	has, err := db.GetEngine(ctx).ID(receipt.ID).Get(stored)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, wecom_model.CallbackReceiptSuccess, stored.Status)
	claimed, err := db.GetEngine(ctx).Where("wecom_userid = ?", "attacker@example.org").Exist(new(wecom_model.AdminAuthority))
	require.NoError(t, err)
	require.False(t, claimed)
	has, err = db.GetEngine(ctx).Where("wecom_userid = ? AND is_management = ?", "current-admin", true).Exist(new(wecom_model.AdminAuthority))
	require.NoError(t, err)
	require.True(t, has)
}

type callbackAuthorityClientFunc func(context.Context) ([]AppAdminInfo, error)

func (f callbackAuthorityClientFunc) ListAppAdmins(ctx context.Context) ([]AppAdminInfo, error) {
	return f(ctx)
}

func TestCallbackWorkerLostReceiptClaimRollsBackAuthority(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockCallbackSettings(t)
	ctx := t.Context()
	now := timeutil.TimeStamp(1780000000)
	_, err := RefreshAdminAuthoritySnapshot(ctx, fakeAdminAuthorityClient{admins: []AppAdminInfo{{UserID: "old-admin", AuthType: 1}}}, AdminAuthorityRefreshOptions{RunID: "old-state", Now: now})
	require.NoError(t, err)
	receipt, _, err := wecom_model.AcceptCallbackReceipt(ctx, &wecom_model.CallbackReceipt{CorpID: setting.EnterpriseWeCom.CorpID, AgentID: setting.EnterpriseWeCom.AgentID, Event: WeComChangeAppAdminEvent, DedupKey: "lost-claim"}, now)
	require.NoError(t, err)
	client := callbackAuthorityClientFunc(func(ctx context.Context) ([]AppAdminInfo, error) {
		_, err := db.GetEngine(ctx).ID(receipt.ID).Cols("lease_token").Update(&wecom_model.CallbackReceipt{LeaseToken: "replacement-worker"})
		return []AppAdminInfo{{UserID: "new-admin", AuthType: 1}}, err
	})
	err = processAdminCallback(ctx, client, receipt.ID, now)
	require.Error(t, err)
	require.Equal(t, 503, CallbackErrorStatus(err))
	active, err := db.GetEngine(ctx).Where("wecom_userid = ? AND is_active = ?", "old-admin", true).Exist(new(wecom_model.AdminAuthority))
	require.NoError(t, err)
	require.True(t, active)
	newAdmin, err := db.GetEngine(ctx).Where("wecom_userid = ?", "new-admin").Exist(new(wecom_model.AdminAuthority))
	require.NoError(t, err)
	require.False(t, newAdmin)
}

func TestVerifiedCallbackRefreshUsesDistinctRunIDs(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockCallbackSettings(t)
	enc := callbackTestEncrypted(t, callbackTestEvent, callbackTestConfig().ReceiverID, "1234567890123456")
	verified, err := VerifyAdminCallbackEvent(callbackTestConfig(), callbackTestQuery(enc), []byte(`<xml><Encrypt>`+enc+`</Encrypt></xml>`), time.Unix(1780000000, 0))
	require.NoError(t, err)
	first, err := HandleAdminAuthorityCallback(t.Context(), fakeAdminAuthorityClient{}, verified)
	require.NoError(t, err)
	second, err := HandleAdminAuthorityCallback(t.Context(), fakeAdminAuthorityClient{}, verified)
	require.NoError(t, err)
	require.NotEqual(t, first.RefreshID, second.RefreshID)
}

func TestCallbackWorkerDoesNotClaimOtherApplicationReceipt(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockCallbackSettings(t)
	now := timeutil.TimeStamp(1780000000)
	receipt, _, err := wecom_model.AcceptCallbackReceipt(t.Context(), &wecom_model.CallbackReceipt{CorpID: setting.EnterpriseWeCom.CorpID, AgentID: "other-app", Event: WeComChangeAppAdminEvent, DedupKey: "other-app-event"}, now)
	require.NoError(t, err)
	before := *receipt
	calls := 0
	client := callbackAuthorityClientFunc(func(context.Context) ([]AppAdminInfo, error) {
		calls++
		return nil, nil
	})
	require.NoError(t, processAdminCallback(t.Context(), client, receipt.ID, now))
	stored := new(wecom_model.CallbackReceipt)
	has, err := db.GetEngine(t.Context()).ID(receipt.ID).Get(stored)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, before, *stored)
	require.Zero(t, calls)
}
