// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"net/http"
	"time"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/log"
	"gitea.dev/modules/metrics"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/web/middleware"
	"gitea.dev/services/audit"
)

func RecordDerivedPackageIndexDecision(ctx context.Context, ownerID int64, indexKind string, policy *FeaturePolicy) error {
	if !setting.EnterpriseAuthz.Enabled {
		return nil
	}
	denied := &ExecutionError{Reason: "feature_disabled", Status: http.StatusForbidden}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	owner, err := user_model.GetUserByID(bounded, ownerID)
	if err != nil {
		_ = FeatureGuardError(err)
		if setting.EnterpriseAuthz.Enforce {
			return denied
		}
		return nil
	}
	scope := audit_model.EntityRef{Type: audit_model.ScopeUser, ID: owner.ID}
	if owner.IsOrganization() {
		scope.Type = audit_model.ScopeOrganization
	}
	actor, _ := middleware.GetContextData(ctx)[middleware.ContextDataKeySignedUser].(*user_model.User)
	actorID := int64(0)
	if actor != nil {
		actorID = actor.ID
	}
	mode, actual, phase, outcome := "shadow", "native", "admission", "native"
	if setting.EnterpriseAuthz.Enforce {
		mode, actual, phase, outcome = "enforce", "deny", "terminal", "denied"
	}
	params := audit.RecordParams{Action: audit_model.EnterpriseFeatureDecision, Actor: audit_model.EntityRef{Type: audit_model.ScopeUser, ID: actorID}, ActorCredential: safeCredentialReference(RequestCredentialCeiling(ctx, actor).Reference), Impersonator: safeAuditImpersonator(ctx, actorID), Scope: scope, Metadata: map[string]any{"catalog_version": authz.FeatureCatalogVersion, "feature_key": authz.FeaturePackages, "mode": mode, "candidate_decision": "deny", "actual_decision": actual, "reason": "feature_disabled", "derived_index": indexKind, "phase": phase, "outcome": outcome, "snapshot": featureSnapshot(policy)}}
	attribution := audit.AttributionFromContext(ctx)
	record := func() {
		detached, cancel := context.WithTimeout(audit.WithAttribution(context.Background(), attribution), time.Second)
		defer cancel()
		if err := db.WithIndependentTx(detached, func(tx context.Context) error { return audit.RecordEvent(tx, params) }); err != nil {
			metrics.EnterpriseFeatureFailure.WithLabelValues("audit_unavailable").Inc()
			log.Error("Derived package index candidate evidence unavailable")
		}
	}
	metrics.EnterpriseFeatureDecision.WithLabelValues(string(authz.FeaturePackages), mode, actual).Inc()
	if db.InTransaction(ctx) {
		db.AfterRollback(ctx, record)
		db.AfterCommit(ctx, record)
	} else {
		record()
	}
	if setting.EnterpriseAuthz.Enforce {
		return denied
	}
	return nil
}
