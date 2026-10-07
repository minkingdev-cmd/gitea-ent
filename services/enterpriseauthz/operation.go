// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"slices"

	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/services/audit"
)

type (
	boundObservationKey struct{}
	executionParentKey  struct{}
)

type boundObservation struct {
	actorID, repoID int64
	action          authz.Action
	observation     *Observation
	source          string
	credential      CredentialCeiling
	branch          string
	branchKnown     bool
}

func WithObservationContext(ctx context.Context, input EvaluateInput) (context.Context, *Observation) {
	ctx, observation := BeginObservation(ctx, input)
	return bindObservationContext(ctx, input, observation), observation
}

func WithPreparedObservationContext(ctx context.Context, input EvaluateInput, prepare func(context.Context, EvaluateInput) (EvaluateInput, error)) (context.Context, *Observation) {
	ctx, observation := BeginPreparedObservation(ctx, input, prepare)
	return bindObservationContext(ctx, input, observation), observation
}

func bindObservationContext(ctx context.Context, input EvaluateInput, observation *Observation) context.Context {
	if !setting.EnterpriseAuthz.Enabled || input.Repo == nil || input.Repo.ID <= 0 || !authz.ValidSource(input.ConditionContext.Source) || input.ConditionContext.Source == "diagnostic" {
		return ctx
	}
	credential := input.Credential
	credential.Actions = slices.Clone(credential.Actions)
	bound := boundObservation{actorID: actorID(input), repoID: input.Repo.ID, action: input.Action, observation: observation, source: input.ConditionContext.Source, credential: credential, branch: input.ConditionContext.Branch, branchKnown: input.ConditionContext.BranchKnown}
	if store := reqctx.FromContext(ctx); store != nil {
		store.SetContextValue(boundObservationKey{}, bound)
		return ctx
	}
	return context.WithValue(ctx, boundObservationKey{}, bound)
}

func DetachedObservationContext(target, source context.Context) context.Context {
	if !setting.EnterpriseAuthz.Enabled {
		return target
	}
	// 不传播请求取消、业务事务或其他请求权限。
	for _, key := range []any{operationKey{}, boundObservationKey{}, mergeGateQueueKey{}} {
		if value := source.Value(key); value != nil {
			target = context.WithValue(target, key, value)
		}
	}
	if setting.EnterpriseAuthz.Enforce {
		target = context.WithValue(target, executionParentKey{}, ExecutionParentContext(source))
	}
	return audit.CopyAttribution(target, source)
}

func ExecutionParentContext(ctx context.Context) context.Context {
	if parent, ok := ctx.Value(executionParentKey{}).(context.Context); ok && parent != nil {
		return parent
	}
	return ctx
}

func ExecutionAttribution(ctx context.Context, actorID, repoID int64) (string, CredentialCeiling) {
	if bound, ok := ctx.Value(boundObservationKey{}).(boundObservation); ok && bound.actorID == actorID && bound.repoID == repoID {
		return bound.source, bound.credential
	}
	return ExecutionSource(ctx), RequestCredentialCeiling(ExecutionParentContext(ctx), audit.DoerFromContext(ctx))
}

func ExecutionAttributionForActor(ctx context.Context, actor *user_model.User, repoID int64) (string, CredentialCeiling) {
	if actor == nil {
		return "system", CredentialCeiling{}
	}
	if bound, ok := ctx.Value(boundObservationKey{}).(boundObservation); ok && bound.actorID == actor.ID && bound.repoID == repoID {
		return bound.source, bound.credential
	}
	return ExecutionSource(ctx), RequestCredentialCeiling(ExecutionParentContext(ctx), actor)
}

func FinishOperationObservation(ctx context.Context, actorID, repoID int64, action authz.Action, outcome NativeOutcome, stage NativeStage) {
	if !setting.EnterpriseAuthz.Enabled {
		return
	}
	bound, ok := ctx.Value(boundObservationKey{}).(boundObservation)
	if ok && bound.actorID == actorID && bound.repoID == repoID && bound.action == action {
		bound.observation.Finish(ctx, outcome, stage)
	}
}
