// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/modules/log"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/timeutil"
	"gitea.dev/services/audit"
)

type GovernanceError struct {
	Stage  string
	Reason string
	cause  error
}

func (e *GovernanceError) Error() string { return "wecom governance: " + e.Stage + ": " + e.Reason }
func (e *GovernanceError) Unwrap() error { return e.cause }

func governanceError(stage, reason string) error {
	return &GovernanceError{Stage: stage, Reason: reason}
}

func safeGovernanceError(stage string, err error) error {
	if err == nil {
		return nil
	}
	if safe, ok := errors.AsType[*GovernanceError](err); ok {
		return safe
	}
	reason := "publish_failed"
	switch {
	case errors.Is(err, context.Canceled):
		reason = "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		reason = "timed_out"
	case errors.Is(err, ErrWeComAuthorityUnsupported):
		reason = "unsupported_authority_source"
	}
	return &GovernanceError{Stage: stage, Reason: reason, cause: err}
}

func safeProviderError(stage string, err error) error {
	safe := safeGovernanceError(stage, err)
	if safe == nil {
		return nil
	}
	if typed, ok := errors.AsType[*GovernanceError](safe); ok && typed.Reason == "publish_failed" {
		return &GovernanceError{Stage: stage, Reason: "provider_error", cause: err}
	}
	return safe
}

func newGovernanceID(prefix string) string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic("unable to generate governance operation identifier")
	}
	return prefix + "-" + hex.EncodeToString(value[:])
}

type (
	governanceLeaseKey struct{}
	governanceLease    struct {
		row     wecom_model.GovernanceCoordinator
		stop    chan struct{}
		done    chan struct{}
		stopped bool
	}
)

const governanceLeaseSeconds = 120

func configuredGovernanceScope(corpID, agentID string) error {
	if corpID == "" || agentID == "" || corpID != setting.EnterpriseWeCom.CorpID || agentID != setting.EnterpriseWeCom.AgentID {
		return governanceError("preflight", "scope_mismatch")
	}
	return nil
}

func withGovernanceLease(ctx context.Context, corpID, agentID, owner string, f func(context.Context) error) error {
	if err := configuredGovernanceScope(corpID, agentID); err != nil {
		return err
	}
	if lease, ok := ctx.Value(governanceLeaseKey{}).(*governanceLease); ok {
		if lease.row.CorpID != corpID || lease.row.AgentID != agentID {
			return governanceError("preflight", "scope_mismatch")
		}
		return f(ctx)
	}
	if db.InTransaction(ctx) {
		return governanceError("preflight", "invalid_publish_context")
	}
	row := wecom_model.GovernanceCoordinator{CorpID: corpID, AgentID: agentID}
	has, err := db.GetEngine(ctx).Get(&row)
	if err != nil {
		return safeGovernanceError("claim", err)
	}
	if !has {
		if err := db.Insert(ctx, &row); err != nil {
			row = wecom_model.GovernanceCoordinator{CorpID: corpID, AgentID: agentID}
			if has, readErr := db.GetEngine(ctx).Get(&row); readErr != nil || !has {
				return governanceError("claim", "coordination_unavailable")
			}
		}
	}
	now := time.Now().Unix()
	updated := row
	updated.LeaseOwner = owner
	updated.LeaseUntilUnix = now + governanceLeaseSeconds
	updated.FencingGeneration++
	n, err := db.GetEngine(ctx).Where("id = ? AND fencing_generation = ? AND published_revision = ? AND lease_until_unix <= ?", row.ID, row.FencingGeneration, row.PublishedRevision, now).
		Cols("lease_owner", "lease_until_unix", "fencing_generation").Update(&updated)
	if err != nil {
		return safeGovernanceError("claim", err)
	}
	if n != 1 {
		return governanceError("claim", "writer_busy")
	}
	lease := &governanceLease{row: updated, stop: make(chan struct{}), done: make(chan struct{})}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	workCtx = context.WithValue(workCtx, governanceLeaseKey{}, lease)
	go func() {
		defer close(lease.done)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-workCtx.Done():
				return
			case <-lease.stop:
				return
			case <-ticker.C:
				n, err := db.GetEngine(workCtx).Where("id = ? AND lease_owner = ? AND fencing_generation = ? AND lease_until_unix > ?", row.ID, owner, updated.FencingGeneration, time.Now().Unix()).
					Cols("lease_until_unix").Update(&wecom_model.GovernanceCoordinator{LeaseUntilUnix: time.Now().Unix() + governanceLeaseSeconds})
				if err != nil || n != 1 {
					cancel()
					return
				}
			}
		}
	}()
	defer func() {
		stopGovernanceRenewal(lease)
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		_, err := db.GetEngine(cleanup).Where("id = ? AND lease_owner = ? AND fencing_generation = ?", row.ID, owner, updated.FencingGeneration).
			Cols("lease_owner", "lease_until_unix").Update(&wecom_model.GovernanceCoordinator{})
		if err != nil {
			log.Error("WeCom governance lease cleanup failed: evidence_persist_failed")
		}
	}()
	if _, err := db.GetEngine(ctx).Where("corp_id = ? AND agent_id = ? AND status = ? AND run_id <> ?", corpID, agentID, wecom_model.ReconcileRunStatusRunning, owner).
		Cols("status", "stage", "reason", "error_message", "finished_unix").Update(&wecom_model.ReconcileRun{Status: wecom_model.ReconcileRunStatusFailed, Stage: "recovery", Reason: "interrupted", ErrorMessage: "wecom governance: recovery: interrupted", FinishedUnix: timeutil.TimeStampNow()}); err != nil {
		return safeGovernanceError("recovery", err)
	}
	return f(workCtx)
}

func stopGovernanceRenewal(lease *governanceLease) {
	if !lease.stopped {
		close(lease.stop)
		<-lease.done
		lease.stopped = true
	}
}

func publishGovernance(ctx context.Context, orgID int64, f func(context.Context, int64) error) error {
	lease, ok := ctx.Value(governanceLeaseKey{}).(*governanceLease)
	if !ok {
		return governanceError("publish", "missing_coordinator")
	}
	stopGovernanceRenewal(lease)
	ctx, auditError := audit.WithRequiredPersistence(ctx)
	err := db.WithTx(ctx, func(ctx context.Context) error {
		if err := ctx.Err(); err != nil {
			return safeGovernanceError("publish", err)
		}
		update := &wecom_model.GovernanceCoordinator{PublishedRevision: lease.row.PublishedRevision + 1, ManagedOrgID: lease.row.ManagedOrgID}
		if orgID > 0 {
			if lease.row.ManagedOrgID != 0 && lease.row.ManagedOrgID != orgID {
				return governanceError("preflight", "managed_org_conflict")
			}
			if _, err := resolveGeneratedTargetOrg(ctx, orgID); err != nil {
				return err
			}
			update.ManagedOrgID = orgID
		}
		n, err := db.GetEngine(ctx).Where("id = ? AND lease_owner = ? AND fencing_generation = ? AND published_revision = ? AND lease_until_unix > ?", lease.row.ID, lease.row.LeaseOwner, lease.row.FencingGeneration, lease.row.PublishedRevision, time.Now().Unix()).
			Cols("published_revision", "managed_org_id").Update(update)
		if err != nil {
			return safeGovernanceError("publish", err)
		}
		if n != 1 {
			return governanceError("publish", "stale_candidate")
		}
		if err := f(ctx, update.PublishedRevision); err != nil {
			return err
		}
		if err := auditError(); err != nil {
			return governanceError("evidence", "evidence_persist_failed")
		}
		return ctx.Err()
	})
	return safeGovernanceError("publish", err)
}

func withGeneratedMutation(ctx context.Context, f func(context.Context) error) error {
	if _, ok := ctx.Value(governanceLeaseKey{}).(*governanceLease); ok && db.InTransaction(ctx) {
		return f(ctx)
	}
	if !setting.EnterpriseWeCom.Enabled {
		return ErrWeComDisabled
	}
	orgID, err := resolveGeneratedTargetOrg(ctx, 0)
	if err != nil {
		return err
	}
	return withGovernanceLease(ctx, setting.EnterpriseWeCom.CorpID, setting.EnterpriseWeCom.AgentID, newGovernanceID("internal"), func(ctx context.Context) error {
		return publishGovernance(ctx, orgID, func(ctx context.Context, _ int64) error { return f(ctx) })
	})
}
