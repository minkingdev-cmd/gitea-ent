// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"maps"
	"net/http"
	"slices"
	"time"

	audit_model "gitea.dev/models/audit"
	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	secret_model "gitea.dev/models/secret"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	webhook_model "gitea.dev/models/webhook"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/log"
	"gitea.dev/modules/metrics"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/util"
	"gitea.dev/modules/web/middleware"
	"gitea.dev/services/audit"

	"xorm.io/builder"
)

var ErrFeatureParentLocked = errors.New("feature_parent_locked")

type FeatureGrantInput struct {
	State            authz.FeatureState
	Config           []byte
	ExpectedRevision int64
}

type FeaturePolicy struct {
	Grant           *authz_model.FeatureGrant
	Effective       authz.ResolvedFeature
	Chain           []authz.FeatureLayer
	Hash            string
	PolicyRevision  int64
	OwnerID         int64
	NativeAvailable bool
	Pending         bool
}

func featurePolicy(ctx context.Context, key authz.FeatureKey, scope authz_model.Scope) (*FeaturePolicy, error) {
	metadata, known := authz.LookupFeature(key)
	if !known || !scope.Valid() {
		return nil, util.ErrNotExist
	}
	definition, exists, err := db.Get[authz_model.FeatureDefinition](ctx, builder.Eq{"key": key})
	if err != nil || !exists || definition.Validate() != nil {
		return nil, ErrPolicyStorage
	}
	scopes := []authz_model.Scope{{Type: authz_model.ScopeSystem}}
	var repo *repo_model.Repository
	var ownerID int64
	switch scope.Type {
	case authz_model.ScopeOrg:
		owner, err := user_model.GetUserByID(ctx, scope.ID)
		if user_model.IsErrUserNotExist(err) || err == nil && !owner.IsOrganization() {
			return nil, util.ErrNotExist
		}
		if err != nil {
			return nil, ErrPolicyStorage
		}
		ownerID = owner.ID
		scopes = append(scopes, scope)
	case authz_model.ScopeRepo:
		repo, err = repo_model.GetRepositoryByID(ctx, scope.ID)
		if repo_model.IsErrRepoNotExist(err) {
			return nil, util.ErrNotExist
		}
		if err != nil {
			return nil, ErrPolicyStorage
		}
		owner, err := user_model.GetUserByID(ctx, repo.OwnerID)
		if err != nil {
			return nil, ErrPolicyStorage
		}
		ownerID = owner.ID
		if owner.IsOrganization() {
			scopes = append(scopes, authz_model.Scope{Type: authz_model.ScopeOrg, ID: owner.ID})
		}
		scopes = append(scopes, scope)
	}
	conditions := make([]builder.Cond, 0, len(scopes))
	for _, current := range scopes {
		conditions = append(conditions, builder.Eq{"scope_type": current.Type, "scope_id": current.ID})
	}
	var grants []authz_model.FeatureGrant
	if err := db.GetEngine(ctx).Where(builder.And(builder.Eq{"feature_key": key}, builder.Or(conditions...))).Find(&grants); err != nil {
		return nil, ErrPolicyStorage
	}
	policy := &FeaturePolicy{Grant: &authz_model.FeatureGrant{FeatureKey: key, ScopeType: scope.Type, ScopeID: scope.ID, State: authz.FeatureInherited, ConfigJSON: "{}"}, OwnerID: ownerID, PolicyRevision: definition.PolicyRevision, NativeAvailable: true}
	for _, current := range scopes {
		for i := range grants {
			grant := &grants[i]
			if grant.Scope() != current {
				continue
			}
			if grant.Validate() != nil {
				return nil, ErrPolicyStorage
			}
			config, _, _ := authz.ParseFeatureConfig(key, grant.State, []byte(grant.ConfigJSON))
			policy.Chain = append(policy.Chain, authz.FeatureLayer{Scope: authz_model.FeatureScopeName(current.Type), ID: current.ID, State: grant.State, Config: config, Revision: grant.Revision})
			if current == scope {
				policy.Grant = grant
			}
		}
	}
	policy.Effective, err = authz.ResolveFeature(metadata, policy.Chain)
	if err != nil {
		return nil, ErrPolicyStorage
	}
	encoded, err := json.Marshal(struct {
		CatalogVersion, SchemaVersion int
		PolicyRevision, OwnerID       int64
		Scope                         authz_model.Scope
		Chain                         []authz.FeatureLayer
	}{authz.FeatureCatalogVersion, metadata.ConfigSchemaVersion, definition.PolicyRevision, ownerID, scope, policy.Chain})
	if err != nil {
		return nil, ErrPolicyStorage
	}
	hash := sha256.Sum256(encoded)
	policy.Hash = hex.EncodeToString(hash[:])
	policy.NativeAvailable, err = featureNativeAvailable(ctx, key, scope, repo, policy.Effective.Config)
	if err != nil {
		return nil, ErrPolicyStorage
	}
	policy.Pending = policy.Effective.State == authz.FeatureRequired && !policy.NativeAvailable
	return policy, nil
}

func GetFeaturePolicy(ctx context.Context, key authz.FeatureKey, scope authz_model.Scope) (*FeaturePolicy, error) {
	if db.InTransaction(ctx) {
		var policy *FeaturePolicy
		err := db.WithSavepoint(ctx, func(tx context.Context) error { var err error; policy, err = featurePolicy(tx, key, scope); return err })
		return policy, err
	}
	var policy *FeaturePolicy
	err := db.WithIndependentReadTx(ctx, func(tx context.Context) error { var err error; policy, err = featurePolicy(tx, key, scope); return err })
	return policy, err
}

func featureCredential(ctx context.Context, actor *user_model.User, scope authz_model.Scope, write bool) error {
	if actor == nil || actor.ExtDoerData != nil {
		return util.ErrPermissionDenied
	}
	token, exists := middleware.GetContextData(ctx)["ApiTokenScope"].(auth_model.AccessTokenScope)
	if !exists {
		return nil
	}
	publicOnly, err := token.PublicOnly()
	if err != nil || write && publicOnly {
		return util.ErrPermissionDenied
	}
	required := auth_model.AccessTokenScopeReadRepository
	switch scope.Type {
	case authz_model.ScopeSystem:
		required = auth_model.AccessTokenScopeReadAdmin
		if write {
			required = auth_model.AccessTokenScopeWriteAdmin
		}
	case authz_model.ScopeOrg:
		required = auth_model.AccessTokenScopeReadOrganization
		if write {
			required = auth_model.AccessTokenScopeWriteOrganization
		}
	default:
		if write {
			required = auth_model.AccessTokenScopeWriteRepository
		}
	}
	allowed, err := token.HasScope(required)
	if err != nil || !allowed {
		return util.ErrPermissionDenied
	}
	return nil
}

func featureMutationAction(ctx context.Context, resolved *managementScope) error {
	if err := featureCredential(ctx, resolved.actor, resolved.scope, true); err != nil {
		return err
	}
	if resolved.repo == nil {
		return nil
	}
	permission, err := access_model.GetDoerRepoPermission(ctx, resolved.repo, resolved.actor)
	if err != nil {
		return ErrPolicyStorage
	}
	decision, err := evaluate(ctx, EvaluateInput{Actor: resolved.actor, Repo: resolved.repo, Permission: &permission, Credential: RequestCredentialCeiling(ctx, resolved.actor), Action: authz.ManageFeatureGrant, ConditionContext: authz.ConditionContext{Source: "api"}}, true)
	if err != nil {
		return ErrPolicyStorage
	}
	if decision.CandidateDecision != "allow" {
		return util.ErrPermissionDenied
	}
	return nil
}

func GetManagedFeaturePolicy(ctx context.Context, actor *user_model.User, key authz.FeatureKey, scope authz_model.Scope) (*FeaturePolicy, error) {
	if _, err := authorizePolicy(ctx, actor, scope); err != nil {
		return nil, err
	}
	if err := featureCredential(ctx, actor, scope, false); err != nil {
		return nil, err
	}
	var policy *FeaturePolicy
	err := db.WithIndependentReadTx(ctx, func(tx context.Context) error {
		if _, err := authorizePolicy(tx, actor, scope); err != nil {
			return err
		}
		var err error
		policy, err = featurePolicy(tx, key, scope)
		return err
	})
	return policy, err
}

func PutFeatureGrant(ctx context.Context, actor *user_model.User, scope authz_model.Scope, key authz.FeatureKey, input FeatureGrantInput) (*FeaturePolicy, error) {
	return mutateFeatureGrant(ctx, actor, scope, key, input, false)
}

func ResetFeatureGrant(ctx context.Context, actor *user_model.User, scope authz_model.Scope, key authz.FeatureKey, expectedRevision int64) error {
	_, err := mutateFeatureGrant(ctx, actor, scope, key, FeatureGrantInput{State: authz.FeatureInherited, Config: []byte("{}"), ExpectedRevision: expectedRevision}, true)
	return err
}

func mutateFeatureGrant(ctx context.Context, actor *user_model.User, scope authz_model.Scope, key authz.FeatureKey, input FeatureGrantInput, reset bool) (*FeaturePolicy, error) {
	var result *FeaturePolicy
	err := withPolicyMutation(ctx, actor, scope, func(tx context.Context, resolved *managementScope) error {
		if err := featureMutationAction(tx, resolved); err != nil {
			return err
		}
		_, known := authz.LookupFeature(key)
		if !known {
			if reset {
				return util.ErrNotExist
			}
			return ErrInvalidPolicy
		}
		_, canonical, err := authz.ParseFeatureConfig(key, input.State, input.Config)
		if err != nil || input.ExpectedRevision < 0 {
			return ErrInvalidPolicy
		}
		if err := authz_model.LockFeatures(tx, []authz.FeatureKey{key}); err != nil {
			return ErrPolicyStorage
		}
		before, err := featurePolicy(tx, key, scope)
		if err != nil {
			return err
		}
		if before.Grant.Revision != input.ExpectedRevision {
			return ErrRevisionConflict
		}
		ancestors := before.Chain
		if len(ancestors) > 0 && ancestors[len(ancestors)-1].Scope == authz_model.FeatureScopeName(scope.Type) {
			ancestors = ancestors[:len(ancestors)-1]
		}
		metadata, _ := authz.LookupFeature(key)
		parent, err := authz.ResolveFeature(metadata, ancestors)
		if err != nil {
			return ErrPolicyStorage
		}
		if input.State != authz.FeatureInherited && parent.LockedBy != nil && (parent.State == authz.FeatureDisabled && input.State != authz.FeatureDisabled || parent.State == authz.FeatureRequired && input.State == authz.FeatureDisabled) {
			return ErrFeatureParentLocked
		}
		if before.Grant.State == input.State && before.Grant.ConfigJSON == canonical {
			result = before
			return nil
		}
		grant := *before.Grant
		grant.State, grant.ConfigJSON, grant.Revision, grant.UpdatedBy = input.State, canonical, input.ExpectedRevision+1, resolved.actor.ID
		if grant.ID == 0 {
			grant.CreatedBy = resolved.actor.ID
			if _, err := db.GetEngine(tx).Insert(&grant); err != nil {
				return ErrPolicyStorage
			}
		} else {
			affected, err := db.GetEngine(tx).Where("id = ? AND revision = ?", grant.ID, input.ExpectedRevision).Cols("state", "config_json", "revision", "updated_by").Update(&grant)
			if err != nil {
				return ErrPolicyStorage
			}
			if affected != 1 {
				return ErrRevisionConflict
			}
		}
		if _, err := db.GetEngine(tx).Where("key = ?", key).SetExpr("policy_revision", "policy_revision + 1").Update(new(authz_model.FeatureDefinition)); err != nil {
			return ErrPolicyStorage
		}
		result, err = featurePolicy(tx, key, scope)
		if err != nil {
			return err
		}
		action := audit_model.EnterpriseFeatureGrantUpdate
		if reset {
			action = audit_model.EnterpriseFeatureGrantReset
		}
		beforeHash := sha256.Sum256([]byte(before.Grant.ConfigJSON))
		afterHash := sha256.Sum256([]byte(canonical))
		return recordPolicyEvent(tx, resolved, action, map[string]any{"feature_key": key, "scope": authz_model.FeatureScopeName(scope.Type), "scope_id": scope.ID, "before_state": before.Grant.State, "after_state": grant.State, "before_revision": before.Grant.Revision, "after_revision": grant.Revision, "before_config_hash": hex.EncodeToString(beforeHash[:]), "after_config_hash": hex.EncodeToString(afterHash[:]), "chain_hash": result.Hash, "catalog_version": authz.FeatureCatalogVersion})
	})
	if err != nil {
		if errors.Is(err, ErrFeatureParentLocked) {
			return nil, ErrFeatureParentLocked
		}
		return nil, safePolicyError(err)
	}
	return result, nil
}

func RequireRepoFeature(ctx context.Context, repoID int64, key authz.FeatureKey) error {
	return RequireFeature(ctx, key, authz_model.Scope{Type: authz_model.ScopeRepo, ID: repoID})
}

func RequireOwnerFeature(ctx context.Context, ownerID int64, key authz.FeatureKey) error {
	if !setting.EnterpriseAuthz.Enabled {
		return nil
	}
	owner, err := user_model.GetUserByID(ctx, ownerID)
	if err != nil {
		return FeatureGuardError(err)
	}
	scope := authz_model.Scope{Type: authz_model.ScopeSystem}
	if owner.IsOrganization() {
		scope = authz_model.Scope{Type: authz_model.ScopeOrg, ID: ownerID}
	}
	return RequireFeature(ctx, key, scope)
}

func FeatureGuardError(err error) error {
	metrics.EnterpriseFeatureFailure.WithLabelValues("policy_unavailable").Inc()
	if !setting.EnterpriseAuthz.Enforce {
		return nil
	}
	if errors.Is(err, util.ErrNotExist) || errors.Is(err, context.Canceled) {
		return &ExecutionError{Reason: "invalid_feature_context", Status: http.StatusForbidden}
	}
	if errors.Is(err, db.ErrObservationTransactionUnavailable) {
		return &ExecutionError{Reason: "feature_policy_unavailable", Status: http.StatusServiceUnavailable}
	}
	if !setting.EnterpriseAuthz.FailClosedOnError {
		log.Error("Enterprise feature check fell back to native permissions: feature_policy_unavailable")
		return nil
	}
	return &ExecutionError{Reason: "feature_policy_unavailable", Status: http.StatusServiceUnavailable}
}

func RequireFeature(ctx context.Context, key authz.FeatureKey, scope authz_model.Scope) error {
	if !setting.EnterpriseAuthz.Enabled {
		return nil
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	policy, err := GetFeaturePolicy(bounded, key, scope)
	if err != nil {
		return FeatureGuardError(err)
	}
	actual := "native"
	candidate := "allow"
	if policy.Effective.State == authz.FeatureDisabled {
		candidate = "deny"
	}
	if setting.EnterpriseAuthz.Enforce && policy.Effective.CapabilityKind == "native_gate" {
		actual = candidate
	}
	mode := "shadow"
	if setting.EnterpriseAuthz.Enforce {
		mode = "enforce"
	}
	metrics.EnterpriseFeatureDecision.WithLabelValues(string(key), mode, actual).Inc()
	auditScope := audit_model.EntityRef{Type: audit_model.ScopeSystem}
	if scope.Type == authz_model.ScopeOrg {
		auditScope = audit_model.EntityRef{Type: audit_model.ScopeOrganization, ID: scope.ID}
	}
	if scope.Type == authz_model.ScopeRepo {
		auditScope = audit_model.EntityRef{Type: audit_model.ScopeRepository, ID: scope.ID}
	}
	actor, _ := middleware.GetContextData(ctx)[middleware.ContextDataKeySignedUser].(*user_model.User)
	actorRef := audit_model.EntityRef{Type: audit_model.ScopeUser}
	if actor != nil {
		actorRef.ID = actor.ID
	}
	params := audit.RecordParams{Action: audit_model.EnterpriseFeatureDecision, Actor: actorRef, ActorCredential: safeCredentialReference(RequestCredentialCeiling(ctx, actor).Reference), Impersonator: safeAuditImpersonator(ctx, actorRef.ID), Scope: auditScope, Metadata: map[string]any{"catalog_version": authz.FeatureCatalogVersion, "mode": mode, "feature_key": key, "state": policy.Effective.State, "chain_hash": policy.Hash, "capability_kind": policy.Effective.CapabilityKind, "candidate_decision": candidate, "actual_decision": actual, "native_available": policy.NativeAvailable, "pending": policy.Pending, "snapshot": featureSnapshot(policy), "phase": "admission"}}
	if db.IsReadOnly(ctx) {
		params.Metadata["phase"] = "policy_probe"
		params.Metadata["actual_decision"] = "not_executed"
		err = db.WithSavepoint(bounded, func(tx context.Context) error {
			if !setting.AuditRecordEnabled() {
				return errors.New("audit_recording_disabled")
			}
			_, err := db.GetEngine(tx).Query("SELECT id FROM audit_event WHERE 1=0")
			return err
		})
		if err == nil {
			recordFeatureAfterTransaction(ctx, params)
		}
	} else {
		err = db.WithSavepoint(bounded, func(tx context.Context) error { return audit.RecordEvent(tx, params) })
	}
	if db.InTransaction(ctx) {
		terminal := params
		terminal.Metadata = maps.Clone(params.Metadata)
		terminal.Metadata["phase"] = "terminal"
		terminal.Metadata["outcome"] = "rolled_back"
		if actual == "deny" {
			terminal.Metadata["outcome"] = "denied"
		}
		recordFeatureAfterRollback(ctx, terminal)
	}
	if err != nil {
		metrics.EnterpriseFeatureFailure.WithLabelValues("audit_unavailable").Inc()
		log.Error("Enterprise feature admission evidence unavailable")
	}
	if actual == "deny" {
		return &ExecutionError{Reason: "feature_disabled", Status: http.StatusForbidden}
	}
	if err != nil {
		return FeatureGuardError(err)
	}
	return nil
}

func CheckRepoFeatureIntent(ctx context.Context, repoID int64, key authz.FeatureKey, before, after bool) error {
	if !setting.EnterpriseAuthz.Enabled || before == after {
		return nil
	}
	policy, err := GetFeaturePolicy(ctx, key, authz_model.Scope{Type: authz_model.ScopeRepo, ID: repoID})
	if err != nil {
		return FeatureGuardError(err)
	}
	if policy.Effective.State == authz.FeatureDisabled && after {
		return FeatureIntentDenied(ctx, repoID, key, policy, "feature_disabled")
	}
	if policy.Effective.State == authz.FeatureRequired && !after {
		return FeatureIntentDenied(ctx, repoID, key, policy, "feature_required")
	}
	return nil
}

func WithRepoFeatureConfiguration(ctx context.Context, repoID int64, units []repo_model.RepoUnit, deleteUnitTypes []unit.Type, apply func(context.Context) error) error {
	if !setting.EnterpriseAuthz.Enabled {
		return apply(ctx)
	}
	if !setting.EnterpriseAuthz.Enforce {
		bounded, cancel := context.WithTimeout(ctx, time.Second)
		if err := db.WithSavepoint(bounded, func(tx context.Context) error {
			return checkRepoFeatureUnitIntent(tx, repoID, units, deleteUnitTypes)
		}); err != nil {
			_ = FeatureGuardError(err)
		}
		cancel()
		return apply(ctx)
	}
	return db.WithTx(ctx, func(tx context.Context) error {
		if setting.EnterpriseMergeGate.Enabled {
			if err := LockMergeGatePolicyScopes(tx, authz_model.Scope{Type: authz_model.ScopeRepo, ID: repoID}); err != nil {
				return err
			}
		}
		if err := authz_model.LockScope(tx, authz_model.Scope{Type: authz_model.ScopeRepo, ID: repoID}); err != nil {
			return err
		}
		if err := authz_model.LockFeatures(tx, repoUnitFeatureKeys()); err != nil {
			if denied := FeatureGuardError(err); denied != nil {
				return denied
			}
		}
		if err := checkRepoFeatureUnitIntent(tx, repoID, units, deleteUnitTypes); err != nil {
			return err
		}
		return apply(tx)
	})
}

func repoUnitFeatureKeys() []authz.FeatureKey {
	return []authz.FeatureKey{authz.FeatureIssues, authz.FeaturePackages, authz.FeaturePullRequests, authz.FeatureWiki}
}

func checkRepoFeatureUnitIntent(ctx context.Context, repoID int64, units []repo_model.RepoUnit, deleteUnitTypes []unit.Type) error {
	var current []repo_model.RepoUnit
	if err := db.GetEngine(ctx).Where("repo_id = ?", repoID).Find(&current); err != nil {
		return err
	}
	for _, key := range repoUnitFeatureKeys() {
		before := slices.ContainsFunc(current, func(u repo_model.RepoUnit) bool { return FeatureForUnit(u.Type) == key })
		after := slices.ContainsFunc(current, func(u repo_model.RepoUnit) bool {
			return FeatureForUnit(u.Type) == key && !slices.Contains(deleteUnitTypes, u.Type) && !slices.ContainsFunc(units, func(next repo_model.RepoUnit) bool { return next.Type == u.Type })
		}) || slices.ContainsFunc(units, func(u repo_model.RepoUnit) bool { return FeatureForUnit(u.Type) == key })
		if err := CheckRepoFeatureIntent(ctx, repoID, key, before, after); err != nil {
			return err
		}
	}
	return nil
}

func FeatureForUnit(typ unit.Type) authz.FeatureKey {
	return map[unit.Type]authz.FeatureKey{unit.TypeIssues: authz.FeatureIssues, unit.TypeExternalTracker: authz.FeatureIssues, unit.TypePullRequests: authz.FeaturePullRequests, unit.TypeWiki: authz.FeatureWiki, unit.TypeExternalWiki: authz.FeatureWiki, unit.TypePackages: authz.FeaturePackages}[typ]
}

func featureSnapshot(policy *FeaturePolicy) api.EnterpriseFeatureSnapshot {
	metadata, _ := authz.LookupFeature(policy.Effective.Key)
	encoded, _ := json.Marshal(policy.Effective.Config)
	hash := sha256.Sum256(encoded)
	return api.EnterpriseFeatureSnapshot{Version: 1, Key: string(policy.Effective.Key), State: string(policy.Effective.State), Source: policy.Effective.Source.Scope, Locked: policy.Effective.LockedBy != nil, Conflict: len(policy.Effective.Conflicts) > 0, ChainHash: policy.Hash, ConfigHash: hex.EncodeToString(hash[:]), ContextCount: len(policy.Effective.Config.CheckContexts), CapabilityKind: policy.Effective.CapabilityKind, NativeAvailable: policy.NativeAvailable, Pending: policy.Pending, ConfigSchemaVersion: metadata.ConfigSchemaVersion}
}

func featureForAction(action authz.Action) authz.FeatureKey {
	switch action {
	case authz.CreatePullRequest, authz.ReviewPullRequest, authz.MergePullRequest:
		return authz.FeaturePullRequests
	case authz.ManageWebhook:
		return authz.FeatureWebhooks
	case authz.ManageSecret:
		return authz.FeatureCISecretManagement
	case authz.ManageBranchProtection:
		return authz.FeatureRequiredStatusChecks
	}
	return ""
}

func ListFeaturePolicies(ctx context.Context, actor *user_model.User, scope authz_model.Scope, managed bool) ([]*FeaturePolicy, error) {
	var result []*FeaturePolicy
	err := db.WithIndependentReadTx(ctx, func(tx context.Context) error {
		if managed {
			if _, err := authorizePolicy(tx, actor, scope); err != nil {
				return err
			}
			if err := featureCredential(tx, actor, scope, false); err != nil {
				return err
			}
		}
		for _, metadata := range authz.FeatureCatalog() {
			policy, err := featurePolicy(tx, metadata.Key, scope)
			if err != nil {
				return err
			}
			result = append(result, policy)
		}
		return nil
	})
	return result, err
}

func featureNativeAvailable(ctx context.Context, key authz.FeatureKey, scope authz_model.Scope, repo *repo_model.Repository, config authz.FeatureConfig) (bool, error) {
	metadata, _ := authz.LookupFeature(key)
	if metadata.CapabilityKind == "policy_only" {
		return false, nil
	}
	types := map[authz.FeatureKey][]unit.Type{
		authz.FeatureIssues: {unit.TypeIssues, unit.TypeExternalTracker}, authz.FeaturePullRequests: {unit.TypePullRequests}, authz.FeatureWiki: {unit.TypeWiki, unit.TypeExternalWiki}, authz.FeaturePackages: {unit.TypePackages},
	}[key]
	if len(types) > 0 {
		if key == authz.FeaturePackages && !setting.Packages.Enabled {
			return false, nil
		}
		var available []unit.Type
		for _, typ := range types {
			if !typ.UnitGlobalDisabled() {
				available = append(available, typ)
			}
		}
		if len(available) == 0 {
			return false, nil
		}
		if repo == nil {
			return true, nil
		}
		return db.GetEngine(ctx).Where(builder.Eq{"repo_id": repo.ID}).In("type", available).Exist(new(repo_model.RepoUnit))
	}
	switch key {
	case authz.FeatureWebhooks:
		cond := builder.Eq{"repo_id": int64(0), "owner_id": int64(0), "is_system_webhook": true}
		var sources []builder.Cond
		sources = append(sources, cond)
		if scope.Type == authz_model.ScopeOrg {
			sources = append(sources, builder.Eq{"owner_id": scope.ID, "repo_id": int64(0)})
		}
		if repo != nil {
			sources = append(sources, builder.Eq{"repo_id": repo.ID}, builder.Eq{"owner_id": repo.OwnerID, "repo_id": int64(0)})
		}
		return db.GetEngine(ctx).Where(builder.And(builder.Eq{"is_active": true}, builder.Or(sources...))).Exist(new(webhook_model.Webhook))
	case authz.FeatureCISecretManagement:
		if scope.Type == authz_model.ScopeSystem {
			return false, nil
		}
		cond := builder.Eq{"owner_id": scope.ID, "repo_id": int64(0)}
		if repo != nil {
			return db.GetEngine(ctx).Where(builder.Or(builder.Eq{"repo_id": repo.ID}, builder.Eq{"owner_id": repo.OwnerID, "repo_id": int64(0)})).Exist(new(secret_model.Secret))
		}
		return db.GetEngine(ctx).Where(cond).Exist(new(secret_model.Secret))
	case authz.FeatureRequiredStatusChecks:
		if repo == nil {
			return false, nil
		}
		var rules []*git_model.ProtectedBranch
		if err := db.GetEngine(ctx).Where("repo_id=? AND enable_status_check=?", repo.ID, true).Find(&rules); err != nil {
			return false, err
		}
		for _, rule := range rules {
			complete := true
			for _, mandatory := range config.CheckContexts {
				complete = complete && slices.Contains(rule.StatusCheckContexts, mandatory)
			}
			if complete {
				return true, nil
			}
		}
		return false, nil
	}
	return true, nil
}

func recordFeatureAfterRollback(ctx context.Context, params audit.RecordParams) {
	attribution := audit.AttributionFromContext(ctx)
	db.AfterRollback(ctx, func() {
		detached, cancel := context.WithTimeout(audit.WithAttribution(context.Background(), attribution), time.Second)
		defer cancel()
		if err := db.WithIndependentTx(detached, func(tx context.Context) error { return audit.RecordEvent(tx, params) }); err != nil {
			metrics.EnterpriseFeatureFailure.WithLabelValues("terminal_evidence_unavailable").Inc()
			log.Error("Enterprise feature terminal evidence unavailable")
		}
	})
}

func FeatureIntentDenied(ctx context.Context, repoID int64, key authz.FeatureKey, policy *FeaturePolicy, reason string) error {
	actor, _ := middleware.GetContextData(ctx)[middleware.ContextDataKeySignedUser].(*user_model.User)
	actorID := int64(0)
	if actor != nil {
		actorID = actor.ID
	}
	params := audit.RecordParams{Action: audit_model.EnterpriseFeatureDecision, Actor: audit_model.EntityRef{Type: audit_model.ScopeUser, ID: actorID}, ActorCredential: safeCredentialReference(RequestCredentialCeiling(ctx, actor).Reference), Impersonator: safeAuditImpersonator(ctx, actorID), Scope: audit_model.EntityRef{Type: audit_model.ScopeRepository, ID: repoID}, Metadata: map[string]any{"catalog_version": authz.FeatureCatalogVersion, "feature_key": key, "candidate_decision": "deny", "actual_decision": "deny", "phase": "terminal", "outcome": "denied", "reason": reason, "snapshot": featureSnapshot(policy)}}
	if !setting.EnterpriseAuthz.Enforce {
		metrics.EnterpriseFeatureDecision.WithLabelValues(string(key), "shadow", "native").Inc()
		params.Metadata["mode"] = "shadow"
		params.Metadata["actual_decision"] = "native"
		params.Metadata["phase"] = "admission"
		delete(params.Metadata, "outcome")
		recordFeatureAfterTransaction(ctx, params)
		return nil
	}
	params.Metadata["mode"] = "enforce"
	metrics.EnterpriseFeatureDecision.WithLabelValues(string(key), "enforce", "deny").Inc()
	recordFeatureAfterRollback(ctx, params)
	return &ExecutionError{Reason: reason, Status: http.StatusForbidden}
}

func recordFeatureAfterTransaction(ctx context.Context, params audit.RecordParams) {
	attribution := audit.AttributionFromContext(ctx)
	record := func() {
		detached, cancel := context.WithTimeout(audit.WithAttribution(context.Background(), attribution), time.Second)
		defer cancel()
		if err := db.WithIndependentTx(detached, func(tx context.Context) error { return audit.RecordEvent(tx, params) }); err != nil {
			metrics.EnterpriseFeatureFailure.WithLabelValues("audit_unavailable").Inc()
			log.Error("Enterprise feature shadow candidate evidence unavailable")
		}
	}
	if db.InTransaction(ctx) {
		db.AfterCommit(ctx, record)
		db.AfterRollback(ctx, record)
	} else {
		record()
	}
}
