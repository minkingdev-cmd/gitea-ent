// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"strconv"
	"testing"

	"gitea.dev/models/db"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/timeutil"

	"github.com/stretchr/testify/require"
)

func TestCallbackReceiptDurableDedupClaimsRecoveryAndCleanup(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	now := timeutil.TimeStamp(1780000000)
	event := &CallbackReceipt{CorpID: "corp", AgentID: "agent", Event: "change_app_admin", DedupKey: "digest"}
	first, created, err := AcceptCallbackReceipt(ctx, event, now)
	require.NoError(t, err)
	require.True(t, created)
	second, created, err := AcceptCallbackReceipt(ctx, &CallbackReceipt{CorpID: "corp", AgentID: "agent", Event: "change_app_admin", DedupKey: "digest"}, now)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, first.ID, second.ID)
	claimed, err := ClaimCallbackReceipt(ctx, first.ID, "worker-1", now, 60)
	require.NoError(t, err)
	require.NotNil(t, claimed)
	require.Equal(t, 1, claimed.Attempts)
	lost, err := ClaimCallbackReceipt(ctx, first.ID, "worker-2", now, 60)
	require.NoError(t, err)
	require.Nil(t, lost)
	recovered, err := ClaimCallbackReceipt(ctx, first.ID, "worker-2", now+61, 60)
	require.NoError(t, err)
	require.NotNil(t, recovered)
	err = FinishCallbackReceipt(ctx, first.ID, "worker-1", CallbackReceiptSuccess, "", now+61, 0)
	require.Error(t, err)
	require.NoError(t, FinishCallbackReceipt(ctx, first.ID, "worker-2", CallbackReceiptSuccess, "", now+61, 0))
	pending, _, err := AcceptCallbackReceipt(ctx, &CallbackReceipt{CorpID: "corp", AgentID: "agent", Event: "change_app_admin", DedupKey: "pending"}, now)
	require.NoError(t, err)
	require.NoError(t, CleanupCallbackReceipts(ctx, now+86400))
	has, err := db.GetEngine(ctx).ID(first.ID).Exist(new(CallbackReceipt))
	require.NoError(t, err)
	require.True(t, has)
	require.NoError(t, CleanupCallbackReceipts(ctx, now+86500))
	has, err = db.GetEngine(ctx).ID(first.ID).Exist(new(CallbackReceipt))
	require.NoError(t, err)
	require.False(t, has)
	has, err = db.GetEngine(ctx).ID(pending.ID).Exist(new(CallbackReceipt))
	require.NoError(t, err)
	require.True(t, has)
}

func TestCallbackReceiptConcurrentAcceptanceAndClaim(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	ctx := t.Context()
	now := timeutil.TimeStamp(1780000000)
	type accepted struct {
		receipt *CallbackReceipt
		created bool
		err     error
	}
	start := make(chan struct{})
	results := make(chan accepted, 8)
	for range 8 {
		go func() {
			<-start
			receipt, created, err := AcceptCallbackReceipt(ctx, &CallbackReceipt{CorpID: "corp", AgentID: "agent", Event: "change_app_admin", DedupKey: "same-reencrypted-event"}, now)
			results <- accepted{receipt, created, err}
		}()
	}
	close(start)
	var id int64
	createdCount := 0
	for range 8 {
		result := <-results
		require.NoError(t, result.err)
		require.NotNil(t, result.receipt)
		if id == 0 {
			id = result.receipt.ID
		}
		require.Equal(t, id, result.receipt.ID)
		if result.created {
			createdCount++
		}
	}
	require.Equal(t, 1, createdCount)
	type claimed struct {
		receipt *CallbackReceipt
		err     error
	}
	claims := make(chan claimed, 8)
	start = make(chan struct{})
	for i := range 8 {
		go func() {
			<-start
			receipt, err := ClaimCallbackReceipt(ctx, id, strconv.Itoa(i), now, 60)
			claims <- claimed{receipt, err}
		}()
	}
	close(start)
	winners := 0
	for range 8 {
		result := <-claims
		require.NoError(t, result.err)
		if result.receipt != nil {
			winners++
		}
	}
	require.Equal(t, 1, winners)
	count, err := db.GetEngine(ctx).Count(new(CallbackReceipt))
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
}
