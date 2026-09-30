// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"errors"

	"gitea.dev/models/db"
	"gitea.dev/modules/timeutil"

	"xorm.io/builder"
)

type CallbackReceiptStatus string

const (
	CallbackReceiptPending CallbackReceiptStatus = "pending"
	CallbackReceiptRunning CallbackReceiptStatus = "running"
	CallbackReceiptSuccess CallbackReceiptStatus = "success"
	CallbackReceiptFailed  CallbackReceiptStatus = "failed"
)

type CallbackReceipt struct {
	ID             int64                 `xorm:"pk autoincr"`
	CorpID         string                `xorm:"VARCHAR(128) NOT NULL INDEX"`
	AgentID        string                `xorm:"VARCHAR(64) NOT NULL INDEX"`
	Event          string                `xorm:"VARCHAR(64) NOT NULL"`
	DedupKey       string                `xorm:"VARCHAR(64) NOT NULL UNIQUE"`
	Status         CallbackReceiptStatus `xorm:"VARCHAR(16) NOT NULL INDEX"`
	RunID          string                `xorm:"VARCHAR(64)"`
	Attempts       int
	NextRetryUnix  timeutil.TimeStamp `xorm:"INDEX"`
	LeaseUntilUnix timeutil.TimeStamp `xorm:"INDEX"`
	LeaseToken     string             `xorm:"VARCHAR(64)"`
	Reason         string             `xorm:"VARCHAR(64)"`
	CreatedUnix    timeutil.TimeStamp
	UpdatedUnix    timeutil.TimeStamp
}

func (*CallbackReceipt) TableName() string { return "enterprise_wecom_callback_receipt" }
func init()                                { db.RegisterModel(new(CallbackReceipt)) }

var ErrCallbackClaimLost = errors.New("callback_claim_lost")

func AcceptCallbackReceipt(ctx context.Context, receipt *CallbackReceipt, now timeutil.TimeStamp) (*CallbackReceipt, bool, error) {
	existing := &CallbackReceipt{DedupKey: receipt.DedupKey}
	has, err := db.GetEngine(ctx).Get(existing)
	if err != nil {
		return nil, false, err
	}
	if has {
		return existing, false, nil
	}
	receipt.Status = CallbackReceiptPending
	receipt.NextRetryUnix = now
	receipt.CreatedUnix = now
	receipt.UpdatedUnix = now
	_, err = db.GetEngine(ctx).Insert(receipt)
	if err == nil {
		return receipt, true, nil
	}
	// 唯一约束解决多实例受理竞争，失败后重新读取而不依赖数据库错误文本。
	existing = &CallbackReceipt{DedupKey: receipt.DedupKey}
	has, readErr := db.GetEngine(ctx).Get(existing)
	if readErr == nil && has {
		return existing, false, nil
	}
	return nil, false, err
}

func callbackDue(now timeutil.TimeStamp) builder.Cond {
	return builder.Or(builder.And(builder.Eq{"status": CallbackReceiptPending}, builder.Lte{"next_retry_unix": now}), builder.And(builder.Eq{"status": CallbackReceiptRunning}, builder.Lte{"lease_until_unix": now}))
}

func DueCallbackReceipts(ctx context.Context, corpID, agentID string, now timeutil.TimeStamp) ([]*CallbackReceipt, error) {
	var receipts []*CallbackReceipt
	err := db.GetEngine(ctx).Where(builder.And(callbackDue(now), builder.Eq{"corp_id": corpID, "agent_id": agentID})).OrderBy("id").Limit(100).Find(&receipts)
	return receipts, err
}

func ClaimCallbackReceipt(ctx context.Context, id int64, token string, now timeutil.TimeStamp, leaseSeconds int64) (*CallbackReceipt, error) {
	return claimCallbackReceipt(ctx, id, token, now, leaseSeconds, builder.NewCond())
}

func ClaimCallbackReceiptForScope(ctx context.Context, corpID, agentID string, id int64, token string, now timeutil.TimeStamp, leaseSeconds int64) (*CallbackReceipt, error) {
	return claimCallbackReceipt(ctx, id, token, now, leaseSeconds, builder.Eq{"corp_id": corpID, "agent_id": agentID})
}

func claimCallbackReceipt(ctx context.Context, id int64, token string, now timeutil.TimeStamp, leaseSeconds int64, scope builder.Cond) (*CallbackReceipt, error) {
	var result *CallbackReceipt
	err := db.WithTx(ctx, func(ctx context.Context) error {
		changed, err := db.GetEngine(ctx).ID(id).Where(builder.And(callbackDue(now), scope)).Cols("status", "lease_token", "lease_until_unix", "updated_unix").Update(&CallbackReceipt{Status: CallbackReceiptRunning, LeaseToken: token, LeaseUntilUnix: now + timeutil.TimeStamp(leaseSeconds), UpdatedUnix: now})
		if err != nil || changed == 0 {
			return err
		}
		receipt := new(CallbackReceipt)
		has, err := db.GetEngine(ctx).ID(id).Get(receipt)
		if err != nil {
			return err
		}
		if !has {
			return ErrCallbackClaimLost
		}
		receipt.Attempts++
		receipt.RunID = token
		if _, err = db.GetEngine(ctx).ID(id).Cols("attempts", "run_id").Update(receipt); err != nil {
			return err
		}
		result = receipt
		return nil
	})
	return result, err
}

func FinishCallbackReceipt(ctx context.Context, id int64, token string, status CallbackReceiptStatus, reason string, now, nextRetry timeutil.TimeStamp) error {
	changed, err := db.GetEngine(ctx).ID(id).Where("status = ? AND lease_token = ? AND lease_until_unix > ?", CallbackReceiptRunning, token, now).
		Cols("status", "reason", "updated_unix", "next_retry_unix", "lease_token", "lease_until_unix").Update(&CallbackReceipt{Status: status, Reason: reason, UpdatedUnix: now, NextRetryUnix: nextRetry})
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrCallbackClaimLost
	}
	return nil
}

func CleanupCallbackReceipts(ctx context.Context, now timeutil.TimeStamp) error {
	_, err := db.GetEngine(ctx).Where(builder.And(builder.In("status", CallbackReceiptSuccess, CallbackReceiptFailed), builder.Lt{"updated_unix": now - 86400})).Delete(new(CallbackReceipt))
	return err
}
