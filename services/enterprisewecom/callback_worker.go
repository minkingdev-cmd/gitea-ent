// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	audit_model "gitea.dev/models/audit"
	wecom_model "gitea.dev/models/enterprisewecom"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/graceful"
	"gitea.dev/modules/log"
	"gitea.dev/modules/queue"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/timeutil"
	"gitea.dev/services/audit"
)

var adminCallbackQueue struct {
	sync.RWMutex
	queue *queue.WorkerPoolQueue[int64]
}

func AdminCallbackEnabled() bool {
	return setting.EnterpriseWeCom.Enabled && setting.EnterpriseWeCom.AdminCallbackEnabled
}

func AdminCallbackSettings() AdminCallbackConfig {
	cfg := setting.EnterpriseWeCom
	return AdminCallbackConfig{Token: cfg.AdminCallbackToken, AESKey: cfg.AdminCallbackAESKey, ReceiverID: cfg.AdminCallbackReceiverID, CorpID: cfg.CorpID, AgentID: cfg.AgentID}
}

func RecordAdminCallbackOutcome(ctx context.Context, outcome, reason string, receiptID int64) {
	audit.RecordAs(ctx, user_model.NewAuthSourceUser(), audit_model.EnterpriseWeComAuthorityRefresh, nil, "trigger", "callback", "stage", "callback", "corp_id", setting.EnterpriseWeCom.CorpID, "agent_id", setting.EnterpriseWeCom.AgentID, "outcome", outcome, "reason", reason, "receipt_id", receiptID)
}

func AcceptAdminCallback(ctx context.Context, callback AdminAuthorityCallback, now timeutil.TimeStamp) (*wecom_model.CallbackReceipt, error) {
	if !AdminCallbackEnabled() {
		return nil, callbackError(404, "callback_disabled")
	}
	if !callback.verified || callback.dedupKey == "" || callback.CorpID != setting.EnterpriseWeCom.CorpID || callback.AgentID != setting.EnterpriseWeCom.AgentID || callback.Event != WeComChangeAppAdminEvent {
		return nil, callbackError(403, "callback_scope_mismatch")
	}
	receipt, created, err := wecom_model.AcceptCallbackReceipt(ctx, &wecom_model.CallbackReceipt{CorpID: callback.CorpID, AgentID: callback.AgentID, Event: callback.Event, DedupKey: callback.dedupKey}, now)
	if err != nil {
		return nil, callbackError(503, "callback_storage_failed")
	}
	if created {
		RecordAdminCallbackOutcome(ctx, "accepted", "", receipt.ID)
	}
	adminCallbackQueue.RLock()
	q := adminCallbackQueue.queue
	adminCallbackQueue.RUnlock()
	if q != nil {
		if err = q.Push(receipt.ID); err != nil && !errors.Is(err, queue.ErrAlreadyInQueue) {
			log.Warn("enterprise wecom callback wake-up deferred: callback_queue_unavailable")
		}
	}
	return receipt, nil
}

func InitAdminCallbackQueue(ctx context.Context) error {
	if !AdminCallbackEnabled() {
		return nil
	}
	adminCallbackQueue.Lock()
	if adminCallbackQueue.queue != nil {
		adminCallbackQueue.Unlock()
		return nil
	}
	scope := sha256.Sum256([]byte(setting.EnterpriseWeCom.CorpID + "\x00" + setting.EnterpriseWeCom.AgentID))
	q := queue.CreateUniqueQueue(ctx, "enterprise_wecom_admin_callback_"+hex.EncodeToString(scope[:8]), func(ids ...int64) []int64 {
		for _, id := range ids {
			if err := processAdminCallback(ctx, NewClientFromSettings(), id, timeutil.TimeStampNow()); err != nil {
				log.Error("enterprise wecom callback processing failed: callback_storage_failed")
			}
		}
		return nil
	})
	if q == nil {
		adminCallbackQueue.Unlock()
		return callbackError(503, "callback_queue_unavailable")
	}
	adminCallbackQueue.queue = q
	adminCallbackQueue.Unlock()
	go graceful.GetManager().RunWithCancel(q)
	return ScanAdminCallbacks(ctx)
}

func ScanAdminCallbacks(ctx context.Context) error {
	if !AdminCallbackEnabled() {
		return nil
	}
	now := timeutil.TimeStampNow()
	if err := wecom_model.CleanupCallbackReceipts(ctx, now); err != nil {
		return callbackError(503, "callback_storage_failed")
	}
	receipts, err := wecom_model.DueCallbackReceipts(ctx, setting.EnterpriseWeCom.CorpID, setting.EnterpriseWeCom.AgentID, now)
	if err != nil {
		return callbackError(503, "callback_storage_failed")
	}
	adminCallbackQueue.RLock()
	q := adminCallbackQueue.queue
	adminCallbackQueue.RUnlock()
	if q == nil {
		return callbackError(503, "callback_queue_unavailable")
	}
	for _, receipt := range receipts {
		if err := q.Push(receipt.ID); err != nil && !errors.Is(err, queue.ErrAlreadyInQueue) {
			return callbackError(503, "callback_queue_unavailable")
		}
	}
	return nil
}

func processAdminCallback(ctx context.Context, client AdminAuthorityClient, id int64, now timeutil.TimeStamp) error {
	if !AdminCallbackEnabled() {
		return nil
	}
	tokenBytes := make([]byte, 24)
	if _, err := rand.Read(tokenBytes); err != nil {
		return callbackError(503, "callback_storage_failed")
	}
	token := hex.EncodeToString(tokenBytes)
	receipt, err := wecom_model.ClaimCallbackReceiptForScope(ctx, setting.EnterpriseWeCom.CorpID, setting.EnterpriseWeCom.AgentID, id, token, now, 90)
	if err != nil {
		return callbackError(503, "callback_storage_failed")
	}
	if receipt == nil {
		return nil
	}
	finish := func(ctx context.Context, status wecom_model.CallbackReceiptStatus, reason string, nextRetry timeutil.TimeStamp) error {
		return wecom_model.FinishCallbackReceipt(ctx, id, token, status, reason, now, nextRetry)
	}
	if receipt.CorpID != setting.EnterpriseWeCom.CorpID || receipt.AgentID != setting.EnterpriseWeCom.AgentID || receipt.Event != WeComChangeAppAdminEvent {
		return finish(ctx, wecom_model.CallbackReceiptFailed, "callback_scope_mismatch", 0)
	}
	if receipt.Attempts > 6 {
		return finish(ctx, wecom_model.CallbackReceiptFailed, "callback_retry_exhausted", 0)
	}
	workCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	_, err = RefreshAdminAuthoritySnapshot(workCtx, client, AdminAuthorityRefreshOptions{CorpID: receipt.CorpID, AgentID: receipt.AgentID, Trigger: "callback", RunID: token, Now: now, OnPublished: func(ctx context.Context) error { return finish(ctx, wecom_model.CallbackReceiptSuccess, "", 0) }})
	if err == nil {
		return nil
	}
	cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cleanupCancel()
	status := wecom_model.CallbackReceiptPending
	reason := "authority_fetch_failed"
	if safe, ok := errors.AsType[*GovernanceError](err); ok {
		switch safe.Reason {
		case "writer_busy", "stale_candidate", "coordination_unavailable", "provider_error", "publish_failed", "cancelled", "timed_out":
			reason = safe.Reason
		case "scope_mismatch", "incomplete_authority_source", "unsupported_authority_source":
			status = wecom_model.CallbackReceiptFailed
			reason = safe.Reason
		}
	}
	nextRetry := timeutil.TimeStamp(0)
	switch {
	case errors.Is(err, ErrWeComAuthorityUnsupported), errors.Is(err, ErrWeComDenied), errors.Is(err, ErrWeComDisabled):
		status = wecom_model.CallbackReceiptFailed
		reason = "authority_source_unsupported"
	case receipt.Attempts >= 6:
		status = wecom_model.CallbackReceiptFailed
		reason = "callback_retry_exhausted"
	default:
		if status == wecom_model.CallbackReceiptPending {
			backoff := [...]timeutil.TimeStamp{1, 5, 30, 120, 300}
			nextRetry = now + backoff[receipt.Attempts-1]
		}
	}
	if err = finish(cleanupCtx, status, reason, nextRetry); err != nil {
		return callbackError(503, "callback_storage_failed")
	}
	RecordAdminCallbackOutcome(cleanupCtx, string(status), reason, id)
	return nil
}
