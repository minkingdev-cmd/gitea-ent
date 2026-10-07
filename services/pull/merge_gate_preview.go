// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"slices"

	auth_model "gitea.dev/models/auth"
	issues_model "gitea.dev/models/issues"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/util"
	"gitea.dev/modules/web/middleware"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func PreviewMergeGate(ctx context.Context, actor *user_model.User, repoID, pullID int64, style repo_model.MergeStyle, commitIDs ...string) (*api.EnterpriseMergeGatePreview, error) {
	if !setting.EnterpriseMergeGate.Enabled {
		return nil, util.ErrNotExist
	}
	if actor == nil || actor.ID <= 0 || actor.ExtDoerData != nil {
		return nil, util.ErrPermissionDenied
	}
	actor, err := user_model.GetUserByID(ctx, actor.ID)
	if err != nil {
		return nil, err
	}
	if !actor.IsIndividual() || !actor.IsActive || actor.ProhibitLogin {
		return nil, util.ErrPermissionDenied
	}
	if actor.IsAdmin {
		actor.IsAdmin, err = access_model.HasSystemManagementAuthority(ctx, actor)
		if err != nil {
			return nil, err
		}
	}
	pr, err := issues_model.GetPullRequestByID(ctx, pullID)
	if err != nil {
		return nil, err
	}
	if pr.BaseRepoID != repoID {
		return nil, util.ErrNotExist
	}
	if err := pr.LoadBaseRepo(ctx); err != nil {
		return nil, err
	}
	permission, err := access_model.GetDoerRepoPermission(ctx, pr.BaseRepo, actor)
	if err != nil {
		return nil, err
	}
	ceiling := authz_service.RequestCredentialCeiling(ctx, actor)
	if scope, ok := middleware.GetContextData(ctx)["ApiTokenScope"].(auth_model.AccessTokenScope); ok {
		publicOnly, err := scope.PublicOnly()
		if err != nil || publicOnly && pr.BaseRepo.IsPrivate {
			return nil, util.ErrNotExist
		}
	}
	if !ceiling.Read || !permission.CanRead(unit.TypeCode) || !permission.CanRead(unit.TypePullRequests) {
		return nil, util.ErrNotExist
	}
	if err := authz_service.CheckCargoIndexFeature(ctx, pr.BaseRepo); err != nil {
		return nil, err
	}
	prUnit, err := pr.BaseRepo.GetUnit(ctx, unit.TypePullRequests)
	if err != nil {
		return nil, err
	}
	if style == "" {
		style = prUnit.PullRequestsConfig().DefaultMergeStyle
	}
	if !slices.Contains([]repo_model.MergeStyle{repo_model.MergeStyleMerge, repo_model.MergeStyleRebase, repo_model.MergeStyleRebaseMerge, repo_model.MergeStyleSquash, repo_model.MergeStyleFastForwardOnly, repo_model.MergeStyleManuallyMerged}, style) {
		return nil, authz_service.ErrInvalidPolicy
	}
	mode := "shadow"
	if setting.EnterpriseMergeGate.Enforce {
		mode = "enforce"
	}
	phase, resultSHA := "preview", ""
	var current *mergeGateGitContext
	cancel := func() {}
	if style == repo_model.MergeStyleManuallyMerged {
		phase = "manual_recognition"
		if len(commitIDs) > 0 {
			resultSHA = commitIDs[0]
		}
		current, _ = prepareManualMergeGateGit(ctx, pr, resultSHA, false)
	} else {
		current, cancel, _ = prepareMergeGateGit(ctx, pr)
	}
	defer cancel()
	source := authz_service.ExecutionSource(ctx)
	if source != "web" {
		source = "api"
	}
	evaluation, err := collectMergeGateEvaluation(ctx, pr, actor, style, mode, phase, source, ceiling, authz.MergeGateBypass{}, current, resultSHA)
	if err != nil {
		return nil, err
	}
	result := authz.EvaluateMergeGate(authz.MergeGateInput{Mode: mode, Phase: "preview", Facts: evaluation.Snapshot.Facts})
	headSHA, baseSHA := evaluation.Snapshot.HeadSHA, evaluation.Snapshot.BaseSHA
	descriptors := map[string]authz.MergeGateReasonDescriptor{}
	for _, descriptor := range authz.MergeGateReasonCatalog() {
		descriptors[descriptor.Code] = descriptor
	}
	reasons := make([]api.EnterpriseMergeGateReason, 0, len(result.BlockingReasons))
	for _, reason := range result.BlockingReasons {
		descriptor := descriptors[reason.Code]
		safe := api.EnterpriseMergeGateReason{Code: reason.Code, Source: reason.Source, State: reason.State, MessageKey: descriptor.MessageKey, Tone: descriptor.Tone, BypassCategory: descriptor.BypassCategory}
		if !slices.Contains(reasons, safe) {
			reasons = append(reasons, safe)
		}
	}
	probe, err := collectMergeGateEvaluation(ctx, pr, actor, style, mode, phase, source, ceiling, authz.MergeGateBypass{Requested: true, Reason: "merge gate capability preview", Categories: []string{"required_approvals", "rejected_review", "official_review_request", "codeowners_review", "required_check", "sensitive_path_approval", "sensitive_path_check"}}, current, resultSHA)
	if err != nil {
		return nil, err
	}
	canBypass := probe.Bypass.Authorized && probe.Bypass.NativeAllowed && (probe.Result.CandidateDecision == "bypass" || probe.Result.CandidateDecision == "allow")
	scheduled := authz.EvaluateMergeGate(authz.MergeGateInput{Mode: "enforce", Phase: "schedule", Facts: evaluation.Snapshot.Facts})
	canSchedule := style != repo_model.MergeStyleManuallyMerged && (scheduled.CandidateDecision == "allow" || scheduled.Waiting)
	return &api.EnterpriseMergeGatePreview{CanBypass: canBypass, CanSchedule: canSchedule, SnapshotVersion: authz.MergeGateSnapshotVersion, Mode: mode, Phase: "preview", PreviewOnly: true, CandidateDecision: result.CandidateDecision, AdmissionDecision: result.AdmissionDecision, HeadSHA: headSHA, BaseSHA: baseSHA, Reasons: reasons}, nil
}
