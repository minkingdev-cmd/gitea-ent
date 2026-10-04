// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"
	"slices"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	"gitea.dev/services/audit"
)

type migrationSourceKey struct{}

func WithMigrationSource(ctx context.Context, source string) context.Context {
	if !setting.EnterpriseAuthz.Enabled || ctx.Value(migrationSourceKey{}) != nil {
		return ctx
	}
	return WithOperation(context.WithValue(ctx, migrationSourceKey{}, source))
}

func MarkMigrationTargetCreated(ctx context.Context, repoID int64) {
	if !setting.EnterpriseAuthz.Enabled || repoID <= 0 {
		return
	}
	source, _ := ctx.Value(migrationSourceKey{}).(string)
	if !slices.Contains([]string{"api", "web", "system"}, source) {
		return
	}
	if state, ok := ctx.Value(operationKey{}).(*operationState); ok && state != nil {
		db.AfterCommit(ctx, func() { state.migrationTargetCreated.Store(true) })
	}
}

func MigrationSourceFailureReason(err error) string {
	if invalid, ok := errors.AsType[*git.ErrInvalidCloneAddr](err); ok {
		if invalid.IsPermissionDenied {
			return "source_policy_denied"
		}
		return "source_invalid"
	}
	return "source_check_failed"
}

func MigrationTargetFailureReason(err error) string {
	var reserved db.ErrNameReserved
	var chars db.ErrNameCharsNotAllowed
	var pattern db.ErrNamePatternNotAllowed
	switch {
	case repo_model.IsErrRepoAlreadyExist(err):
		return "repository_name_conflict"
	case repo_model.IsErrRepoFilesAlreadyExist(err):
		return "repository_files_conflict"
	case repo_model.IsErrReachLimitOfRepo(err):
		return "quota_exceeded"
	case errors.Is(err, util.ErrPermissionDenied):
		return "target_permission_denied"
	case errors.As(err, &reserved), errors.As(err, &chars), errors.As(err, &pattern):
		return "repository_name_invalid"
	default:
		return "target_creation_failed"
	}
}

func RecordMigrationFailure(ctx context.Context, actor *user_model.User, ownerID int64, stage, reason string) {
	if !setting.EnterpriseAuthz.Enabled {
		return
	}
	source, _ := ctx.Value(migrationSourceKey{}).(string)
	if !slices.Contains([]string{"api", "web", "system"}, source) ||
		!slices.Contains([]string{"authorize_owner", "site_policy", "validate_request", "validate_source", "prepare_task", "create_target"}, stage) ||
		!slices.Contains([]string{"owner_permission_denied", "owner_resolution_failed", "migration_disabled", "mirror_creation_disabled", "invalid_request", "source_policy_denied", "source_invalid", "source_check_failed", "repository_name_conflict", "repository_files_conflict", "quota_exceeded", "target_permission_denied", "repository_name_invalid", "target_creation_failed", "task_preparation_failed", "task_creation_failed"}, reason) ||
		actor == nil && source != "system" || actor != nil && (actor.ID <= 0 || actor.IsOrganization()) || ownerID < 0 {
		reportObservationFailure("", 0, authz.Migrate, "invalid_observation_context")
		return
	}
	ctx = WithOperation(ctx)
	state, ok := ctx.Value(operationKey{}).(*operationState)
	if !ok || state == nil {
		reportObservationFailure("", 0, authz.Migrate, "invalid_observation_context")
		return
	}
	state.migrationFailure.Do(func() {
		if state.migrationTargetCreated.Load() {
			return
		}
		outcome := NativeFailed
		if slices.Contains([]string{"owner_permission_denied", "migration_disabled", "mirror_creation_disabled", "source_policy_denied", "repository_name_conflict", "repository_files_conflict", "quota_exceeded", "target_permission_denied", "repository_name_invalid"}, reason) {
			outcome = NativeDenied
		}
		actorRef := audit_model.EntityRef{Type: audit_model.ScopeSystem}
		if actor != nil {
			actorRef = audit_model.EntityRef{Type: audit_model.ScopeUser, ID: actor.ID}
		}
		metadata := map[string]any{"operation_id": state.id, "actor_id": actorRef.ID, "request_source": source, "stage": stage, "reason": reason, "native_outcome": string(outcome)}
		if ownerID > 0 {
			metadata["owner_id"] = ownerID
		}
		evidenceCtx, cancel := context.WithTimeout(ctx, observationBudget)
		defer cancel()
		err := db.WithIndependentTx(evidenceCtx, func(tx context.Context) error {
			if setting.Audit.RecordOutput != setting.AuditRecordOutputDatabase {
				return errors.New("database_audit_required")
			}
			return audit.RecordEvent(tx, audit.RecordParams{Action: audit_model.EnterpriseAuthzMigrationFailure, Actor: actorRef, Scope: actorRef, Impersonator: safeAuditImpersonator(tx, actorRef.ID), Metadata: metadata})
		})
		if err != nil {
			reportObservationFailure(state.id, 0, authz.Migrate, safeObservationReason(evidenceCtx, err, "evidence_persist_failed"))
		}
	})
}

type managedMigrationKey struct{}

func WithManagedMigration(ctx context.Context) context.Context {
	if !setting.EnterpriseAuthz.Enabled {
		return ctx
	}
	return context.WithValue(ctx, managedMigrationKey{}, true)
}

func WithMigrationTargetObservation(ctx context.Context, actor *user_model.User, repo *repo_model.Repository) (context.Context, *Observation) {
	if !setting.EnterpriseAuthz.Enabled || ctx.Value(managedMigrationKey{}) != nil {
		return ctx, nil
	}
	if source, ok := ctx.Value(migrationSourceKey{}).(string); ok {
		ctx = withMigrationOrigin(ctx, source)
	}
	if repo != nil && repo.OwnerID == 0 && repo.ID > 0 {
		source := "system"
		if value, ok := ctx.Value(migrationSourceKey{}).(string); ok {
			source = value
		}
		input := EvaluateInput{Actor: actor, Repo: repo, Credential: RequestCredentialCeiling(ctx, actor), Action: authz.Migrate, ConditionContext: authz.ConditionContext{Source: source}}
		return WithPreparedObservationContext(ctx, input, func(ctx context.Context, input EvaluateInput) (EvaluateInput, error) {
			resolved, err := repo_model.GetRepositoryByID(ctx, repo.ID)
			if err != nil {
				return input, err
			}
			input.Repo = resolved
			permission, err := access_model.GetDoerRepoPermission(ctx, resolved, actor)
			input.Permission = &permission
			return input, err
		})
	}
	return WithRepoMutationObservation(ctx, actor, repo, authz.Migrate)
}

func withMigrationOrigin(ctx context.Context, source string) context.Context {
	switch source {
	case "web":
		return audit.WithOrigin(ctx, audit_model.OriginUI)
	case "api":
		return audit.WithOrigin(ctx, audit_model.OriginAPI)
	default:
		return ctx
	}
}

func prepareQueuedMigrationObservation(ctx context.Context, actor *user_model.User, repo *repo_model.Repository) (authz.HookOperationTicket, *Observation) {
	if !setting.EnterpriseAuthz.Enabled {
		return "", nil
	}
	if actor == nil || repo == nil {
		return "", nil
	}
	var err error
	if actor.Name == "" {
		actor, err = user_model.GetUserByID(ctx, actor.ID)
		if err != nil {
			MigrationObservationPersistenceGap(repo.ID)
			return "", nil
		}
	}
	if repo.OwnerID == 0 {
		repo, err = repo_model.GetRepositoryByID(ctx, repo.ID)
		if err != nil {
			MigrationObservationPersistenceGap(repo.ID)
			return "", nil
		}
	}
	source, _ := ctx.Value(migrationSourceKey{}).(string)
	if source == "" {
		source = "system"
	}
	input := EvaluateInput{Actor: actor, Repo: repo, Credential: RequestCredentialCeiling(ctx, actor), Action: authz.Migrate, ConditionContext: authz.ConditionContext{Source: source}}
	ticket := NewHookOperationTicket(ctx, input, nil)
	restored, operation := RestoreHookOperation(ctx, ticket, repo.ID, actor.ID, "")
	if operation == nil {
		return "", nil
	}
	_, observation := BeginResolvedObservation(restored, input, func(ctx context.Context) (*access_model.Permission, error) {
		permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
		return &permission, err
	})
	return ticket, observation
}

func MigrationObservationPersistenceGap(repoID int64) {
	if setting.EnterpriseAuthz.Enabled {
		reportObservationFailure("", repoID, authz.Migrate, "evidence_persist_failed")
	}
}

func ObserveQueuedMigration(ctx context.Context, actor *user_model.User, repo *repo_model.Repository, outcome NativeOutcome, persist func(context.Context, authz.HookOperationTicket) error) {
	if !setting.EnterpriseAuthz.Enabled {
		return
	}
	bounded, cancel := context.WithTimeout(ctx, observationBudget)
	defer cancel()
	ticket, observation := prepareQueuedMigrationObservation(bounded, actor, repo)
	if ticket != "" && persist != nil {
		if err := persist(bounded, ticket); err != nil {
			MigrationObservationPersistenceGap(repo.ID)
		}
	}
	observation.Finish(bounded, outcome, StageMigration)
}

func MigrationNativeOutcome(err error) NativeOutcome {
	if err == nil {
		return NativeSuccess
	}
	if MigrationSourceFailureReason(err) == "source_policy_denied" {
		return NativeDenied
	}
	return NativeFailed
}
