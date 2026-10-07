// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"crypto/sha256"
	"fmt"

	"gitea.dev/models/db"
	issues_model "gitea.dev/models/issues"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/json"
	authz_service "gitea.dev/services/enterpriseauthz"
)

type mergeGateSnapshot struct {
	Version               int                                      `json:"snapshot_version"`
	RepoID                int64                                    `json:"repo_id"`
	OwnerID               int64                                    `json:"owner_id"`
	PullID                int64                                    `json:"pull_id"`
	IssueID               int64                                    `json:"issue_id"`
	ActorID               int64                                    `json:"actor_id"`
	HeadSHA               string                                   `json:"head_sha"`
	BaseSHA               string                                   `json:"base_sha"`
	ResultSHA             string                                   `json:"result_sha,omitempty"`
	CredentialAttribution *authz_service.MergeGateQueueAttribution `json:"credential_attribution,omitempty"`
	ManualPushProof       bool                                     `json:"manual_push_proof,omitempty"`
	PusherID              int64                                    `json:"pusher_id,omitempty"`
	GitAlreadyPresent     bool                                     `json:"git_already_present,omitempty"`
	Branch                string                                   `json:"branch"`
	Facts                 []authz.MergeGateFact                    `json:"facts"`
	Sensitive             mergeGateSensitiveFacts                  `json:"sensitive"`
	Native                mergeGateNativeEvidence                  `json:"native"`
	Statuses              mergeGateStatusFacts                     `json:"statuses"`
	Action                string                                   `json:"action"`
	BypassAction          string                                   `json:"bypass_action,omitempty"`
	BypassRequested       bool                                     `json:"bypass_requested"`
	BypassCategories      []string                                 `json:"bypass_categories,omitempty"`
	BypassAuthorized      bool                                     `json:"bypass_authorized"`
	NativeBypassAllowed   bool                                     `json:"native_bypass_allowed"`
}

type mergeGateEvaluation struct {
	Snapshot mergeGateSnapshot
	Result   authz.MergeGateResult
	JSON     string
	Hash     string
	Bypass   authz.MergeGateBypass
}

func collectMergeGateEvaluation(ctx context.Context, pr *issues_model.PullRequest, actor *user_model.User, style repo_model.MergeStyle, mode, phase, source string, ceiling authz_service.CredentialCeiling, bypass authz.MergeGateBypass, current *mergeGateGitContext, resultSHA string) (mergeGateEvaluation, error) {
	var evaluation mergeGateEvaluation
	snapshot := &evaluation.Snapshot
	snapshot.Version = authz.MergeGateSnapshotVersion
	snapshot.RepoID, snapshot.PullID, snapshot.ActorID = pr.BaseRepoID, pr.ID, actor.ID
	if current != nil {
		snapshot.HeadSHA, snapshot.BaseSHA = current.HeadSHA, current.BaseSHA
		snapshot.PusherID, snapshot.GitAlreadyPresent = current.PusherID, current.Manual
		snapshot.ManualPushProof = current.PushProof
		if current.PushProof {
			snapshot.CredentialAttribution = current.CredentialAttribution
		}
	}
	snapshot.ResultSHA, snapshot.Branch = resultSHA, pr.BaseBranch
	if !ceiling.Read || !ceiling.Write {
		snapshot.Facts = append(snapshot.Facts, authz.MergeGateFact{Code: "credential_denied", Source: "credential", State: "failed"})
	}
	addError := func(code string) {
		snapshot.Facts = append(snapshot.Facts, authz.MergeGateFact{Code: code, Source: "gate", State: "error"})
	}
	collect := func(tx context.Context) error {
		currentPR, err := issues_model.GetPullRequestByID(tx, pr.ID)
		if err != nil {
			return err
		}
		if currentPR.BaseRepoID != pr.BaseRepoID || currentPR.BaseBranch != pr.BaseBranch || currentPR.HeadRepoID != pr.HeadRepoID || currentPR.HeadBranch != pr.HeadBranch || currentPR.Flow != pr.Flow {
			addError("state_changed")
		}
		if err := currentPR.LoadBaseRepo(tx); err != nil {
			return err
		}
		snapshot.OwnerID, snapshot.IssueID = currentPR.BaseRepo.OwnerID, currentPR.IssueID
		freshActor, err := user_model.GetUserByID(tx, actor.ID)
		if err != nil {
			return err
		}
		freshActor.ExtDoerData = actor.ExtDoerData
		if freshActor.IsAdmin {
			freshActor.IsAdmin, err = access_model.HasSystemManagementAuthority(tx, freshActor)
			if err != nil {
				return err
			}
		}
		permission, err := access_model.GetDoerRepoPermission(tx, currentPR.BaseRepo, freshActor)
		if err != nil {
			return err
		}
		if !permission.CanRead(unit.TypeCode) || !permission.CanRead(unit.TypePullRequests) {
			snapshot.Facts = append(snapshot.Facts, authz.MergeGateFact{Code: "native_permission_denied", Source: "native", State: "failed"})
			return nil
		}
		if current == nil || current.Repo == nil {
			addError("paths_incomplete")
		} else {
			repo, err := git.OpenRepository(tx, current.Repo)
			if err != nil {
				addError("paths_incomplete")
			} else {
				defer repo.Close()
				mergeBase, err := git.MergeBase(tx, current.Repo, current.BaseSHA, current.HeadSHA)
				if err == nil {
					snapshot.Sensitive, err = collectMergeGateSensitivePaths(tx, currentPR, repo, current.BaseSHA, current.HeadSHA, mergeBase)
				}
				if err != nil {
					addError("paths_incomplete")
				} else {
					snapshot.Facts = append(snapshot.Facts, snapshot.Sensitive.Facts...)
				}
			}
		}
		native, evidence, err := collectMergeGateNativeState(tx, currentPR, freshActor, style, phase, current)
		snapshot.Native = evidence
		if err != nil {
			addError("facts_read_failed")
		} else {
			snapshot.Facts = append(snapshot.Facts, native...)
		}
		snapshot.Statuses, err = collectMergeGateStatuses(tx, currentPR, snapshot.HeadSHA, snapshot.Sensitive.Contexts)
		if err != nil {
			addError("policy_read_failed")
		} else {
			snapshot.Facts = append(snapshot.Facts, snapshot.Statuses.Facts...)
		}
		action := authz_service.EvaluateInput{Actor: freshActor, Repo: currentPR.BaseRepo, Permission: &permission, Credential: ceiling, Action: authz.MergePullRequest, ConditionContext: authz.ConditionContext{Source: source, Branch: currentPR.BaseBranch, BranchKnown: true}}
		if current != nil {
			action.ConditionContext.Paths, action.ConditionContext.PathsComplete = current.Paths, current.Paths != nil
		}
		decision, err := authz_service.EvaluateMergeGateAction(tx, action)
		if json.Valid([]byte(decision.Snapshot)) {
			snapshot.Action = decision.Snapshot
		}
		if err != nil || decision.CandidateDecision == "error" {
			addError("policy_read_failed")
		} else if decision.CandidateDecision != "allow" {
			snapshot.Facts = append(snapshot.Facts, authz.MergeGateFact{Code: "missing_action", Source: "action", State: "failed"})
		}
		if bypass.Requested {
			action.Action = authz.BypassMergeGate
			decision, err := authz_service.EvaluateMergeGateAction(tx, action)
			if json.Valid([]byte(decision.Snapshot)) {
				snapshot.BypassAction = decision.Snapshot
			}
			bypass.Authorized = err == nil && decision.CandidateDecision == "allow"
			if err != nil || decision.CandidateDecision == "error" {
				addError("policy_read_failed")
			} else if !bypass.Authorized {
				snapshot.Facts = append(snapshot.Facts, authz.MergeGateFact{Code: "missing_action", Source: "bypass_action", State: "failed"})
			}
			bypass.NativeAllowed, err = mergeGateNativeBypass(tx, currentPR, freshActor, &permission)
			if err != nil {
				addError("facts_read_failed")
			} else if !bypass.NativeAllowed {
				snapshot.Facts = append(snapshot.Facts, authz.MergeGateFact{Code: "native_permission_denied", Source: "bypass", State: "failed"})
			}
		}
		return nil
	}
	var err error
	if db.InTransaction(ctx) {
		err = collect(ctx)
	} else {
		err = db.WithIndependentReadTx(ctx, collect)
	}
	if err != nil {
		return mergeGateEvaluation{}, err
	}
	snapshot.BypassRequested, snapshot.BypassAuthorized, snapshot.NativeBypassAllowed = bypass.Requested, bypass.Authorized, bypass.NativeAllowed
	if normalized, err := authz.NormalizeMergeGateBypass(bypass); err == nil {
		snapshot.BypassCategories = normalized.Categories
	}
	evaluation.Bypass = bypass
	if err := sealMergeGateEvaluation(&evaluation); err != nil {
		return mergeGateEvaluation{}, err
	}
	evaluation.Result = authz.EvaluateMergeGate(authz.MergeGateInput{Mode: mode, Phase: phase, Facts: snapshot.Facts, Bypass: bypass})
	return evaluation, nil
}

func sealMergeGateEvaluation(evaluation *mergeGateEvaluation) error {
	raw, err := authz.MarshalMergeGateSnapshot(evaluation.Snapshot)
	if err != nil {
		snapshot := &evaluation.Snapshot
		snapshot.Native = mergeGateNativeEvidence{}
		snapshot.Sensitive, snapshot.Statuses, snapshot.Action, snapshot.BypassAction = mergeGateSensitiveFacts{}, mergeGateStatusFacts{}, "", ""
		snapshot.Facts = []authz.MergeGateFact{{Code: "snapshot_too_large", Source: "gate", State: "error"}}
		raw, err = authz.MarshalMergeGateSnapshot(snapshot)
	}
	if err != nil {
		return err
	}
	evaluation.JSON, evaluation.Hash = raw, fmt.Sprintf("%x", sha256.Sum256([]byte(raw)))
	return nil
}

func collectStableMergeGateEvaluation(ctx context.Context, collect func(context.Context) (mergeGateEvaluation, error), phases ...string) (mergeGateEvaluation, error) {
	evaluation, err := collect(ctx)
	if err != nil {
		return evaluation, err
	}
	for range 2 {
		fresh, err := collect(ctx)
		if err != nil {
			return mergeGateEvaluation{}, err
		}
		if fresh.Hash == evaluation.Hash {
			return fresh, nil
		}
		evaluation = fresh
	}
	evaluation.Snapshot.Facts = append(evaluation.Snapshot.Facts, authz.MergeGateFact{Code: "state_changed", Source: "gate", State: "error"})
	if err := sealMergeGateEvaluation(&evaluation); err != nil {
		return mergeGateEvaluation{}, err
	}
	mode, phase := "enforce", "admission"
	if evaluation.Result.AdmissionDecision == "not_enforced" {
		mode = "shadow"
	}
	if len(phases) > 0 {
		phase = phases[0]
	}
	evaluation.Result = authz.EvaluateMergeGate(authz.MergeGateInput{Mode: mode, Phase: phase, Facts: evaluation.Snapshot.Facts, Bypass: evaluation.Bypass})
	return evaluation, nil
}
