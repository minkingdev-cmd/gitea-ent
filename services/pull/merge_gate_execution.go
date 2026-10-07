// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"errors"
	"net/http"
	"time"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitrepo"
	"gitea.dev/modules/json"
	"gitea.dev/modules/log"
	"gitea.dev/modules/setting"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func mergeGateNativeBypass(ctx context.Context, pr *issues_model.PullRequest, actor *user_model.User, permission *access_model.Permission) (bool, error) {
	pb, err := git_model.GetFirstMatchProtectedBranchRule(ctx, pr.BaseRepoID, pr.BaseBranch)
	if err != nil {
		return false, err
	}
	if pb == nil {
		return permission.IsAdmin(), nil
	}
	return git_model.CanBypassBranchProtectionWithError(ctx, pb, actor, permission.IsAdmin())
}

func mergeGateExecutionError(reason string, status int) error {
	return &authz_service.ExecutionError{Reason: reason, Status: status}
}

func mergeGateRejection(result authz.MergeGateResult) error {
	if result.AdmissionDecision == "not_enforced" || result.AdmissionDecision == "allow" || result.AdmissionDecision == "bypass" {
		return nil
	}
	if result.CandidateDecision == "error" {
		for _, fact := range result.BlockingReasons {
			if fact.Code == "state_changed" {
				return mergeGateExecutionError("merge_gate_state_changed", http.StatusConflict)
			}
		}
		return mergeGateExecutionError("merge_gate_unavailable", http.StatusServiceUnavailable)
	}
	for _, fact := range result.BlockingReasons {
		switch fact.Code {
		case "actor_invalid", "credential_denied", "missing_action", "native_permission_denied", "feature_disabled":
			return mergeGateExecutionError("merge_gate_permission_denied", http.StatusForbidden)
		}
	}
	for _, fact := range result.BlockingReasons {
		if fact.Code == "bypass_invalid" || fact.Code == "auto_bypass_denied" {
			return mergeGateExecutionError("merge_gate_bypass_invalid", http.StatusUnprocessableEntity)
		}
	}
	return mergeGateExecutionError("merge_gate_denied", http.StatusConflict)
}

func prepareMergeGateGit(ctx context.Context, pr *issues_model.PullRequest) (*mergeGateGitContext, func(), error) {
	tmp, cancel, err := createTemporaryRepoForPRWithGuard(ctx, pr, func(ctx context.Context, pr *issues_model.PullRequest) error {
		return checkPullFeatures(ctx, pr, authz_service.CheckCargoIndexFeature)
	})
	if err != nil {
		return nil, func() {}, err
	}
	current, err := mergeGateGitAt(ctx, tmp.tmpRepo, "")
	return current, cancel, err
}

func mergeGateGitAt(ctx context.Context, repo gitrepo.RepositoryFacade, baseSHA string) (*mergeGateGitContext, error) {
	headSHA, err := git.GetFullCommitID(ctx, repo, git.BranchPrefix+tmpRepoTrackingBranch)
	if err != nil {
		return nil, err
	}
	if baseSHA == "" {
		baseSHA, err = git.GetFullCommitID(ctx, repo, git.BranchPrefix+tmpRepoBaseBranch)
	}
	if err != nil {
		return nil, err
	}
	mergeBase, err := git.MergeBase(ctx, repo, baseSHA, headSHA)
	if err != nil {
		return nil, err
	}
	paths, err := collectMergeGatePaths(ctx, repo, mergeBase, headSHA)
	if err != nil {
		return nil, err
	}
	return &mergeGateGitContext{Repo: repo, BaseSHA: baseSHA, HeadSHA: headSHA, Paths: paths}, nil
}

func checkMergeGateBeforeMutation(ctx context.Context, pr *issues_model.PullRequest, actor *user_model.User, style repo_model.MergeStyle, options MergeOptions, automatic bool) error {
	if !setting.EnterpriseMergeGate.Enabled || !setting.EnterpriseMergeGate.Enforce {
		return nil
	}
	var current *mergeGateGitContext
	cancel := func() {}
	permission, err := access_model.GetDoerRepoPermission(ctx, pr.BaseRepo, actor)
	if err != nil {
		return mergeGateExecutionError("merge_gate_unavailable", http.StatusServiceUnavailable)
	}
	if permission.CanRead(unit.TypeCode) && permission.CanRead(unit.TypePullRequests) {
		current, cancel, _ = prepareMergeGateGit(ctx, pr)
	}
	defer cancel()
	_, err = admitMergeGate(ctx, pr, actor, style, options, automatic, current, "", false)
	return err
}

func admitMergeGate(ctx context.Context, pr *issues_model.PullRequest, actor *user_model.User, style repo_model.MergeStyle, options MergeOptions, automatic bool, current *mergeGateGitContext, resultSHA string, start bool, phases ...string) (*authz_model.MergeGateEvaluation, error) {
	if !setting.EnterpriseMergeGate.Enabled {
		return nil, nil //nolint:nilnil // 关闭时没有门禁记录。
	}
	bounded, cancel := context.WithTimeout(authz_service.ExecutionParentContext(ctx), 5*time.Second)
	defer cancel()
	mode, phase := "shadow", "admission"
	if setting.EnterpriseMergeGate.Enforce {
		mode = "enforce"
	}
	if automatic {
		phase = "auto_admission"
	}
	if len(phases) > 0 {
		phase = phases[0]
	}
	source, original := authz_service.ExecutionAttributionForActor(ctx, actor, pr.BaseRepoID)
	bypass := authz.MergeGateBypass{Requested: options.Force || automatic && (options.BypassReason != "" || len(options.BypassCategories) > 0), Reason: options.BypassReason, Categories: options.BypassCategories}
	var record *authz_model.MergeGateEvaluation
	var rejection error
	err := db.WithIndependentTx(bounded, func(tx context.Context) error {
		if err := authz_service.LockMergeGatePolicyScopes(tx, authz_model.Scope{Type: authz_model.ScopeRepo, ID: pr.BaseRepoID}); err != nil {
			return err
		}
		repo, err := repo_model.GetRepositoryByID(tx, pr.BaseRepoID)
		if err != nil {
			return err
		}
		var credentialErr error
		evaluation, err := collectStableMergeGateEvaluation(tx, func(tx context.Context) (mergeGateEvaluation, error) {
			ceiling := original
			readErr := db.WithSavepoint(tx, func(snapshot context.Context) error {
				var err error
				if automatic && phase == "auto_admission" {
					ceiling, err = authz_service.MergeGateAutoCredential(snapshot, authz_service.MergeGateAutoQueueID(ctx), pr.ID, actor.ID, repo)
				} else {
					ceiling, err = authz_service.RefreshMergeGateCredential(snapshot, actor.ID, repo, original)
				}
				return err
			})
			if errors.Is(readErr, db.ErrObservationTransactionUnavailable) {
				return mergeGateEvaluation{}, readErr
			}
			if readErr != nil {
				credentialErr = readErr
				ceiling = original
			}
			evaluation, err := collectMergeGateEvaluation(tx, pr, actor, style, mode, phase, source, ceiling, bypass, current, resultSHA)
			if err != nil {
				return mergeGateEvaluation{}, err
			}
			if credentialErr != nil {
				evaluation.Snapshot.Facts = append(evaluation.Snapshot.Facts, authz.MergeGateFact{Code: "facts_read_failed", Source: "credential", State: "error"})
				if err := sealMergeGateEvaluation(&evaluation); err != nil {
					return mergeGateEvaluation{}, err
				}
				evaluation.Result = authz.EvaluateMergeGate(authz.MergeGateInput{Mode: mode, Phase: phase, Facts: evaluation.Snapshot.Facts, Bypass: evaluation.Bypass})
			}
			return evaluation, nil
		}, phase)
		if err != nil {
			return err
		}
		if current != nil {
			fresh, err := issues_model.GetPullRequestByID(tx, pr.ID)
			if err != nil {
				return err
			}
			if err := fresh.LoadHeadRepo(tx); err != nil {
				return err
			}
			actualBase, err := git.GetFullCommitID(tx, repo, git.BranchPrefix+pr.BaseBranch)
			if err != nil {
				return err
			}
			var headRepo gitrepo.RepositoryFacade
			if fresh.HeadRepo != nil {
				headRepo = fresh.HeadRepo
			}
			headRef := git.BranchPrefix + fresh.HeadBranch
			if fresh.Flow == issues_model.PullRequestFlowAGit {
				headRepo, headRef = repo, fresh.GetGitHeadRefName()
			}
			actualHead := ""
			if headRepo != nil {
				actualHead, err = git.GetFullCommitID(tx, headRepo, headRef)
				if err != nil {
					return err
				}
			}
			if current.Manual {
				actualHead, err = git.GetFullCommitID(tx, repo, fresh.GetGitHeadRefName())
				if err != nil {
					return err
				}
			}
			baseMatches := current.BaseSHA == actualBase
			if current.Manual {
				baseMatches = current.TargetSHA == actualBase
			}
			if !baseMatches || current.HeadSHA != actualHead {
				evaluation.Snapshot.Facts = append(evaluation.Snapshot.Facts, authz.MergeGateFact{Code: "state_changed", Source: "gate", State: "error"})
				if err := sealMergeGateEvaluation(&evaluation); err != nil {
					return err
				}
				evaluation.Result = authz.EvaluateMergeGate(authz.MergeGateInput{Mode: mode, Phase: phase, Facts: evaluation.Snapshot.Facts, Bypass: evaluation.Bypass})
			}
		}
		result := evaluation.Result
		if phase == "schedule" && mode == "enforce" {
			result.AdmissionDecision = result.CandidateDecision
			if result.Waiting {
				result.AdmissionDecision = "allow"
			}
		}
		rejection = mergeGateRejection(result)
		if !start && rejection == nil && (len(phases) < 2 || phases[1] != "capture") {
			return nil
		}
		if automatic && mode == "enforce" && !start && rejection != nil && evaluation.Result.CandidateDecision == "deny" {
			previous := new(authz_model.MergeGateEvaluation)
			found, err := db.GetEngine(tx).Where("scheduled_merge_id=? AND pull_id=? AND phase=?", authz_service.MergeGateAutoQueueID(ctx), pr.ID, phase).Desc("id").Get(previous)
			if err != nil {
				return err
			}
			if found && previous.Validate() == nil && previous.ExecutionState == "not_started" && previous.CandidateDecision == "deny" && previous.SnapshotHash == evaluation.Hash {
				record = previous
				return nil
			}
		}
		reasons, err := json.Marshal(struct{ Blocking, Bypassed []authz.MergeGateFact }{evaluation.Result.BlockingReasons, evaluation.Result.BypassedReasons})
		if err != nil {
			return err
		}
		reason := ""
		if normalized, err := authz.NormalizeMergeGateBypass(bypass); err == nil {
			reason = normalized.Reason
		}
		attempt := 1
		if len(phases) > 1 && phases[1] == "capture" {
			attempt = int(pr.ID)
		}
		record = &authz_model.MergeGateEvaluation{ScheduledMergeID: authz_service.MergeGateAutoQueueID(ctx), OperationID: authz_service.MergeGateOperationID(ctx), Attempt: attempt, Phase: phase, RepoID: pr.BaseRepoID, PullID: pr.ID, IssueID: evaluation.Snapshot.IssueID, ActorID: actor.ID, Source: source, Mode: mode, HeadSHA: evaluation.Snapshot.HeadSHA, BaseSHA: evaluation.Snapshot.BaseSHA, CandidateDecision: evaluation.Result.CandidateDecision, AdmissionDecision: evaluation.Result.AdmissionDecision, ReasonsJSON: string(reasons), SnapshotJSON: evaluation.JSON, SnapshotHash: evaluation.Hash, SnapshotVersion: authz.MergeGateSnapshotVersion, BypassRequested: evaluation.Result.BypassRequested, BypassUsed: evaluation.Result.BypassUsed, BypassReason: reason, ExecutionState: "not_started"}
		return authz_service.PersistMergeGateEvaluationTx(tx, record, start && rejection == nil)
	})
	if err != nil {
		if mode == "shadow" {
			log.Warn("Enterprise merge gate shadow evidence unavailable")
			return nil, nil //nolint:nilnil // shadow 故障不阻断原生执行。
		}
		return nil, mergeGateExecutionError("merge_gate_evidence_persist_failed", http.StatusServiceUnavailable)
	}
	return record, rejection
}

func (execution *mergeExecution) finishMergeGate(operationErr error) error {
	if execution == nil || execution.gate == nil || execution.gateTerminalAttempted {
		return nil
	}
	execution.gateTerminalAttempted = true
	state, sha := "failed", ""
	if execution.gatePushAttempted {
		state = "unknown"
	}
	if execution.gatePushSucceeded {
		pr, err := issues_model.GetPullRequestByID(execution.ctx, execution.gate.PullID)
		if err == nil && pr.HasMerged && pr.MergedCommitID == execution.gateResultSHA {
			proofCtx, cancel := context.WithTimeout(context.WithoutCancel(execution.ctx), time.Second)
			proof, proofErr := authz_service.HasMergeGateMarker(proofCtx, execution.gate, execution.gateResultSHA)
			cancel()
			if proofErr == nil && proof {
				state, sha = "succeeded", execution.gateResultSHA
			}
		}
	}
	bounded, cancel := context.WithTimeout(context.WithoutCancel(execution.ctx), time.Second)
	defer cancel()
	if err := authz_service.FinishMergeGateEvaluation(bounded, execution.gate, state, sha); err != nil {
		if execution.gate.Mode == "shadow" {
			log.Warn("Enterprise merge gate shadow terminal evidence unavailable")
			return nil
		}
		return errors.Join(operationErr, mergeGateExecutionError("merge_gate_terminal_unknown", http.StatusServiceUnavailable))
	}
	if state == "unknown" && execution.gate.Mode == "enforce" {
		return errors.Join(operationErr, mergeGateExecutionError("merge_gate_terminal_unknown", http.StatusServiceUnavailable))
	}
	return nil
}

func CheckPullMergeableForRequest(ctx context.Context, actor *user_model.User, permission *access_model.Permission, pr *issues_model.PullRequest, checkType MergeCheckType, style repo_model.MergeStyle, options MergeOptions, commitID string) error {
	if style == "" {
		style = repo_model.MergeStyleMerge
	}
	if setting.EnterpriseMergeGate.Enabled && setting.EnterpriseMergeGate.Enforce {
		if actor == nil || actor.ID <= 0 || pr == nil {
			return mergeGateExecutionError("merge_gate_permission_denied", http.StatusForbidden)
		}
		ctx = authz_service.WithOperation(ctx)
		if err := pr.LoadBaseRepo(ctx); err != nil {
			return mergeGateExecutionError("merge_gate_unavailable", http.StatusServiceUnavailable)
		}
		freshPermission, err := access_model.GetDoerRepoPermission(ctx, pr.BaseRepo, actor)
		if err != nil {
			return mergeGateExecutionError("merge_gate_unavailable", http.StatusServiceUnavailable)
		}
		var current *mergeGateGitContext
		cancel := func() {}
		phase, automatic := "admission", checkType == MergeCheckTypeAuto
		if automatic {
			phase = "schedule"
		}
		if freshPermission.CanRead(unit.TypeCode) && freshPermission.CanRead(unit.TypePullRequests) {
			if checkType == MergeCheckTypeManually {
				current, _ = prepareManualMergeGateGit(ctx, pr, commitID, false)
				phase = "manual_recognition"
			} else {
				current, cancel, _ = prepareMergeGateGit(ctx, pr)
			}
		}
		defer cancel()
		if _, err := admitMergeGate(ctx, pr, actor, style, options, automatic, current, commitID, false, phase); err != nil {
			return err
		}
	}
	return CheckPullMergeable(ctx, actor, permission, pr, checkType, style, options.Force)
}
