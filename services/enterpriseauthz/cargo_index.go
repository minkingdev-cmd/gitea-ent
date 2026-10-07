// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"slices"
	"time"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/log"
	"gitea.dev/modules/metrics"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	"gitea.dev/modules/web/middleware"
	"gitea.dev/services/audit"
)

func AdoptCargoIndex(ctx context.Context, actor *user_model.User, repoID int64, confirmed bool, sourceRepoIDs ...int64) error {
	scope := authz_model.Scope{Type: authz_model.ScopeSystem}
	if _, err := resolveManagementScope(ctx, actor, scope); err != nil {
		return err
	}
	if !confirmed {
		return util.ErrInvalidArgument
	}
	if setting.Audit.RecordOutput != setting.AuditRecordOutputDatabase {
		return ErrPolicyStorage
	}
	original, err := repo_model.GetRepositoryByID(ctx, repoID)
	if err != nil {
		return err
	}
	return db.WithTx(ctx, func(tx context.Context) error {
		for _, id := range slices.Sorted(slices.Values([]int64{actor.ID, original.OwnerID})) {
			if err := authz_model.LockSubject(tx, authz_model.SubjectUser, id); err != nil {
				return ErrPolicyStorage
			}
		}
		for _, id := range slices.Sorted(slices.Values(append(slices.Clone(sourceRepoIDs), repoID))) {
			if id <= 0 {
				return util.ErrInvalidArgument
			}
			if err := authz_model.LockScope(tx, authz_model.Scope{Type: authz_model.ScopeRepo, ID: id}); err != nil {
				return ErrPolicyStorage
			}
		}

		if _, err := resolveManagementScope(tx, actor, scope); err != nil {
			return err
		}
		repo, err := repo_model.GetRepositoryByID(tx, repoID)
		if err != nil {
			return err
		}
		if repo.OwnerID != original.OwnerID {
			return ErrRevisionConflict
		}
		alreadyMarked := repo.InternalUsage == repo_model.InternalUsageCargoIndex
		if repo.InternalUsage != "" && !alreadyMarked {
			return ErrRevisionConflict
		}
		exists, err := db.GetEngine(tx).Where("owner_id=? AND internal_usage=? AND id<>?", repo.OwnerID, repo_model.InternalUsageCargoIndex, repo.ID).Exist(new(repo_model.Repository))
		if err != nil {
			return ErrPolicyStorage
		}
		if exists {
			return util.NewAlreadyExistErrorf("cargo_index_purpose_conflict")
		}
		repo.InternalUsage = repo_model.InternalUsageCargoIndex
		if err := repo_model.UpdateRepositoryColsWithAutoTime(tx, repo, "internal_usage"); err != nil {
			return ErrPolicyStorage
		}
		addedSource := false
		for _, id := range sourceRepoIDs {
			if _, err := repo_model.GetRepositoryByID(tx, id); err != nil {
				return err
			}
			source := &authz_model.CargoIndexSource{IndexRepoID: repoID, SourceRepoID: id}
			exists, err := db.GetEngine(tx).Where("index_repo_id=? AND source_repo_id=?", repoID, id).Exist(new(authz_model.CargoIndexSource))
			if err != nil {
				return err
			}
			if !exists {
				addedSource = true
				if err := db.Insert(tx, source); err != nil {
					return err
				}
			}
		}
		if alreadyMarked && !addedSource {
			return nil
		}
		return audit.RecordEvent(tx, audit.RecordParams{Action: audit_model.EnterpriseCargoIndexAdopt, Actor: audit_model.EntityRef{Type: audit_model.ScopeUser, ID: actor.ID}, Scope: audit_model.EntityRef{Type: audit_model.ScopeRepository, ID: repo.ID}, Metadata: map[string]any{"internal_usage": repo.InternalUsage, "owner_id": repo.OwnerID, "confirmation": "operator_verified_index_purpose_and_complete_history", "source_repo_ids": sourceRepoIDs}})
	})
}

func RequireCargoIndexFeature(ctx context.Context, repo *repo_model.Repository) error {
	if !setting.EnterpriseAuthz.Enabled || repo.InternalUsage != repo_model.InternalUsageCargoIndex {
		return nil
	}
	if err := RequireRepoFeature(ctx, repo.ID, authz.FeaturePackages); err != nil {
		return err
	}
	if err := RequireOwnerFeature(ctx, repo.OwnerID, authz.FeaturePackages); err != nil {
		return err
	}
	var policy *FeaturePolicy
	read := func(tx context.Context) error {
		denied, err := authz_model.CandidateDeniedCargoIndexRepositoryIDs(tx, repo.ID)
		if err != nil {
			return err
		}
		if len(denied) == 0 {
			return nil
		}
		policy, err = GetFeaturePolicy(tx, authz.FeaturePackages, authz_model.Scope{Type: authz_model.ScopeRepo, ID: repo.ID})
		return err
	}
	var err error
	if db.InTransaction(ctx) {
		err = read(ctx)
	} else {
		err = db.WithIndependentReadTx(ctx, read)
	}
	if err != nil {
		return FeatureGuardError(err)
	}
	if policy == nil {
		return nil
	}
	if setting.EnterpriseAuthz.Enforce {
		return FeatureIntentDenied(ctx, repo.ID, authz.FeaturePackages, policy, "feature_disabled")
	}
	recordCargoIndexShadowCandidate(ctx, repo.ID, policy)
	return nil
}

func recordCargoIndexShadowCandidate(ctx context.Context, repoID int64, policy *FeaturePolicy) {
	actor, _ := middleware.GetContextData(ctx)[middleware.ContextDataKeySignedUser].(*user_model.User)
	actorID := int64(0)
	if actor != nil {
		actorID = actor.ID
	}
	params := audit.RecordParams{Action: audit_model.EnterpriseFeatureDecision, Actor: audit_model.EntityRef{Type: audit_model.ScopeUser, ID: actorID}, ActorCredential: safeCredentialReference(RequestCredentialCeiling(ctx, actor).Reference), Impersonator: safeAuditImpersonator(ctx, actorID), Scope: audit_model.EntityRef{Type: audit_model.ScopeRepository, ID: repoID}, Metadata: map[string]any{"feature_key": authz.FeaturePackages, "catalog_version": authz.FeatureCatalogVersion, "mode": "shadow", "candidate_decision": "deny", "actual_decision": "native", "reason": "feature_disabled", "derived_index": "cargo", "phase": "admission", "snapshot": featureSnapshot(policy)}}
	attribution := audit.AttributionFromContext(ctx)
	record := func() {
		detached, cancel := context.WithTimeout(audit.WithAttribution(context.Background(), attribution), time.Second)
		defer cancel()
		if err := db.WithIndependentTx(detached, func(tx context.Context) error { return audit.RecordEvent(tx, params) }); err != nil {
			metrics.EnterpriseFeatureFailure.WithLabelValues("audit_unavailable").Inc()
			log.Error("Cargo index shadow candidate evidence unavailable")
		}
	}
	metrics.EnterpriseFeatureDecision.WithLabelValues(string(authz.FeaturePackages), "shadow", "native").Inc()
	if db.InTransaction(ctx) {
		db.AfterCommit(ctx, record)
		db.AfterRollback(ctx, record)
	} else {
		record()
	}
}

func CheckCargoIndexFeature(ctx context.Context, repo *repo_model.Repository) error {
	if !setting.EnterpriseAuthz.Enabled || repo.InternalUsage != repo_model.InternalUsageCargoIndex {
		return nil
	}
	read := func(tx context.Context) error {
		owner, err := user_model.GetUserByID(tx, repo.OwnerID)
		if err != nil {
			return ErrPolicyStorage
		}
		ownerScope := authz_model.Scope{Type: authz_model.ScopeSystem}
		if owner.IsOrganization() {
			ownerScope = authz_model.Scope{Type: authz_model.ScopeOrg, ID: owner.ID}
		}
		for _, scope := range []authz_model.Scope{{Type: authz_model.ScopeRepo, ID: repo.ID}, ownerScope} {
			policy, err := GetFeaturePolicy(tx, authz.FeaturePackages, scope)
			if err != nil {
				return ErrPolicyStorage
			}
			if setting.EnterpriseAuthz.Enforce && policy.Effective.State == authz.FeatureDisabled {
				return util.ErrPermissionDenied
			}
		}
		denied, err := authz_model.CandidateDeniedCargoIndexRepositoryIDs(tx, repo.ID)
		if err != nil {
			return ErrPolicyStorage
		}
		if setting.EnterpriseAuthz.Enforce && len(denied) > 0 {
			return util.ErrPermissionDenied
		}
		return nil
	}
	if db.InTransaction(ctx) {
		return read(ctx)
	}
	return db.WithIndependentReadTx(ctx, read)
}
