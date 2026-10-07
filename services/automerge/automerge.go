// Copyright 2021 Gitea. All rights reserved.
// SPDX-License-Identifier: MIT

package automerge

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	access_model "gitea.dev/models/perm/access"
	pull_model "gitea.dev/models/pull"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/globallock"
	"gitea.dev/modules/graceful"
	"gitea.dev/modules/log"
	"gitea.dev/modules/process"
	"gitea.dev/modules/queue"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/timeutil"
	"gitea.dev/services/automergequeue"
	authz_service "gitea.dev/services/enterpriseauthz"
	notify_service "gitea.dev/services/notify"
	pull_service "gitea.dev/services/pull"
	repo_service "gitea.dev/services/repository"
)

// Init runs the task queue to that handles auto merges
func Init(ctx context.Context) error {
	notify_service.RegisterNotifier(NewNotifier())

	automergequeue.AutoMergeQueue = queue.CreateUniqueQueue(graceful.GetManager().ShutdownContext(), "pr_auto_merge",
		func(items ...automergequeue.AutoMergeItem) (unhandled []automergequeue.AutoMergeItem) {
			for _, item := range items {
				handleAutoMergeItem(item)
			}
			return nil
		},
	)
	if automergequeue.AutoMergeQueue == nil {
		return errors.New("unable to create pr_auto_merge queue")
	}
	go graceful.GetManager().RunWithCancel(automergequeue.AutoMergeQueue)
	populateRecentAutoMergeItems(ctx)
	return nil
}

func populateRecentAutoMergeItems(ctx context.Context) {
	if setting.EnterpriseMergeGate.Enabled && setting.EnterpriseMergeGate.Enforce {
		if err := wakeMergeGateScope(ctx, authz_model.Scope{Type: authz_model.ScopeSystem}); err != nil {
			log.Error("AutoMerge: startup policy wake failed: %v", err)
		}
		return
	}
	// in case Gitea's restart aborted some scheduled auto-merge pull requests, try to re-start the recent ones
	pullIDs, err := pull_model.GetScheduledMergePullIDsSince(ctx, timeutil.TimeStampNow().AddDuration(-24*time.Hour))
	if err != nil {
		log.Error("Failed to get recent scheduled auto-merge pull requests: %v", err)
		return
	}
	for _, pullID := range pullIDs {
		pull, err := issues_model.GetPullRequestByID(ctx, pullID)
		if err != nil {
			log.Error("Failed to get scheduled pull request [%d]: %v", pullID, err)
			continue
		}
		automergequeue.StartAutoMergeCheckByPullHead(ctx, pull)
	}
}

// ScheduleAutoMerge if schedule is false and no error, pull can be merged directly
func ScheduleAutoMerge(ctx context.Context, doer *user_model.User, pull *issues_model.PullRequest, style repo_model.MergeStyle, message string, deleteBranchAfterMerge bool, options ...ScheduleOptions) (scheduled bool, err error) {
	if pull == nil || doer == nil {
		return false, errors.New("invalid auto merge target")
	}
	release := func() {}
	if setting.EnterpriseMergeGate.Enabled {
		ctx = authz_service.WithOperation(ctx)
	}
	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
		release, err = globallock.Lock(ctx, fmt.Sprintf("pull_working_%d", pull.ID))
		if err != nil {
			return false, err
		}
	}
	defer release()
	ctx, admission, doer, err := beginAutoMergeSchedule(ctx, doer, pull, style, message, deleteBranchAfterMerge)
	if err != nil {
		if setting.EnterpriseMergeGate.Enabled && setting.EnterpriseMergeGate.Enforce && doer != nil && doer.ID > 0 && pull != nil && pull.ID > 0 {
			mergeOptions := pull_service.MergeOptions{}
			if len(options) > 0 {
				mergeOptions = options[0].MergeOptions
			}
			if evidenceErr := pull_service.PersistDeniedMergeGateSchedule(ctx, doer, pull, style, mergeOptions); evidenceErr != nil {
				err = evidenceErr
			}
		}
		return false, err
	}
	defer func() {
		outcome := authz_service.NativeUnknown
		if err != nil {
			outcome = authz_service.NativeFailed
		}
		admission.Finish(ctx, outcome, authz_service.StageOperation)
	}()
	err = db.WithTx(ctx, func(ctx context.Context) error {
		if len(options) > 0 && options[0].ReplaceExisting {
			if err := authz_service.CancelMergeGateSchedulesTx(ctx, pull.ID); err != nil {
				return err
			}
			if err := pull_model.DeleteScheduledAutoMerge(ctx, pull.ID); err != nil {
				return err
			}
		}
		if err := pull_model.ScheduleAutoMerge(ctx, doer, pull.ID, style, message, deleteBranchAfterMerge); err != nil {
			return err
		}
		mergeOptions := pull_service.MergeOptions{}
		if len(options) > 0 {
			mergeOptions = options[0].MergeOptions
		}
		if setting.EnterpriseMergeGate.Enabled {
			_, queue, err := pull_model.GetScheduledMergeByPullID(ctx, pull.ID)
			if err != nil {
				return err
			}
			if queue == nil {
				return errors.New("merge_gate_queue_unattributed")
			}
			save := func(tx context.Context) error {
				return pull_service.PersistMergeGateScheduleTx(tx, doer, pull, queue.ID, style, mergeOptions)
			}
			if setting.EnterpriseMergeGate.Enforce {
				if err := save(ctx); err != nil {
					return err
				}
			} else if err := db.WithSavepoint(ctx, save); err != nil {
				log.Warn("Enterprise merge gate shadow queue evidence unavailable")
			}
		}
		_, err = issues_model.CreateAutoMergeComment(ctx, issues_model.CommentTypePRScheduledToAutoMerge, pull, doer)
		return err
	})
	if err != nil && setting.EnterpriseMergeGate.Enabled && setting.EnterpriseMergeGate.Enforce {
		if rejection, ok := errors.AsType[*authz_service.ExecutionError](err); ok && strings.HasPrefix(rejection.Reason, "merge_gate_") {
			mergeOptions := pull_service.MergeOptions{}
			if len(options) > 0 {
				mergeOptions = options[0].MergeOptions
			}
			if evidenceErr := pull_service.PersistDeniedMergeGateSchedule(ctx, doer, pull, style, mergeOptions); evidenceErr != nil {
				err = evidenceErr
			}
		}
	}
	// Old code made "scheduled" to be true after "ScheduleAutoMerge", but it's not right:
	// If the transaction rolls back, then the pull request is not scheduled to auto merge.
	// So we should only set "scheduled" to true if there is no error.
	scheduled = err == nil
	release()
	if scheduled {
		log.Trace("Pull request [%d] scheduled for auto merge with style [%s] and message [%s]", pull.ID, style, message)
		automergequeue.StartAutoMergeCheckByPullHead(ctx, pull)
	}
	return scheduled, err
}

// RemoveScheduledAutoMerge cancels a previously scheduled pull request
func RemoveScheduledAutoMerge(ctx context.Context, doer *user_model.User, pull *issues_model.PullRequest) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if err := authz_service.CancelMergeGateSchedulesTx(ctx, pull.ID); err != nil {
			return err
		}
		if err := pull_model.DeleteScheduledAutoMerge(ctx, pull.ID); err != nil {
			return err
		}

		_, err := issues_model.CreateAutoMergeComment(ctx, issues_model.CommentTypePRUnScheduledToAutoMerge, pull, doer)
		return err
	})
}

var errSkipAutoMerge = errors.New("skip auto merge")

func handleAutoMergeItem(item automergequeue.AutoMergeItem) {
	ctx, _, finished := process.GetManager().AddContext(graceful.GetManager().HammerContext(), "AutoMerge: "+string(item))
	defer finished()

	fields := strings.Split(string(item), ":")
	if len(fields) == 4 && fields[0] == "gate-scope" {
		id, err := strconv.ParseInt(fields[2], 10, 64)
		scope := authz_model.Scope{Type: authz_model.ScopeType(fields[1]), ID: id}
		if err == nil && scope.Valid() && setting.EnterpriseMergeGate.Enabled && setting.EnterpriseMergeGate.Enforce {
			if err := wakeMergeGateScope(ctx, scope); err != nil {
				log.Error("AutoMerge: policy wake failed: %v", err)
			}
		}
		return
	}
	if len(fields) != 3 || fields[0] != "pr" {
		return
	}
	pullIDStr, headCommitID := fields[1], fields[2]
	pullID, _ := strconv.ParseInt(pullIDStr, 10, 64)
	pr, err := issues_model.GetPullRequestByID(ctx, pullID)
	if err != nil {
		log.Error("AutoMerge: GetPullRequestByID[%d]: %v", pullID, err)
		return
	}

	err = handlePullRequestAutoMerge(ctx, pr, headCommitID)
	if errors.Is(err, errSkipAutoMerge) {
		log.Debug("AutoMerge: skipping pull request [%d] auto merge: %v", pullID, err)
	} else if err != nil {
		log.Error("AutoMerge: failed to auto merge pull request [%d]: %v", pullID, err)
	} else {
		log.Info("AutoMerge: auto merge pull request [%d]", pullID)
	}
}

// handlePullRequestAutoMerge merge the pull request if all checks are successful
func handlePullRequestAutoMerge(ctx context.Context, pr *issues_model.PullRequest, expectedHeadCommitID string) error {
	_ = pr.LoadIssue(ctx)
	if (pr.Issue != nil && pr.Issue.IsClosed) || pr.HasMerged {
		// if the PR has been closed or merged, delete the automerge record and skip
		err := pull_model.DeleteScheduledAutoMerge(ctx, pr.ID)
		if err != nil {
			return errors.Join(errSkipAutoMerge, err)
		}
		return nil
	}

	if (!setting.EnterpriseMergeGate.Enabled || !setting.EnterpriseMergeGate.Enforce) && (!pr.IsStatusMergeable() || pr.IsWorkInProgress(ctx)) {
		// quick check: if the PR can't be merged, just skip
		return errors.Join(errSkipAutoMerge, errors.New("pull request is not mergeable or is work in progress"))
	}

	// Check if there is a scheduled pr in the db
	exists, scheduledPRM, err := pull_model.GetScheduledMergeByPullID(ctx, pr.ID)
	if err != nil {
		return fmt.Errorf("failed to get scheduled auto-merge: %w", err)
	}
	if !exists {
		return errors.Join(errSkipAutoMerge, errors.New("pull request doesn't exist"))
	}

	if err = pr.LoadBaseRepo(ctx); err != nil {
		return fmt.Errorf("failed to load base repo: %w", err)
	}
	if err = pr.LoadHeadRepo(ctx); err != nil {
		return fmt.Errorf("failed to load head repo: %w", err)
	}

	// check the sha is the same as pull request head commit id
	baseGitRepo, err := git.OpenRepository(ctx, pr.BaseRepo)
	if err != nil {
		return fmt.Errorf("failed to open base git repo: %w", err)
	}
	defer baseGitRepo.Close()

	headCommitID, err := baseGitRepo.GetRefCommitID(ctx, pr.GetGitHeadRefName())
	if err != nil {
		return fmt.Errorf("failed to get ref commit ID: %w", err)
	}
	if headCommitID != expectedHeadCommitID {
		return errors.Join(errSkipAutoMerge, errors.New("head commit ID changed"))
	}

	// Get all checks for this pr
	// We get the latest sha commit hash again to handle the case where the check of a previous push
	// did not succeed or was not finished yet.

	switch pr.Flow {
	case issues_model.PullRequestFlowGithub:
		headBranchExist := pr.HeadRepo != nil
		if headBranchExist {
			headBranchExist, _ = git_model.IsBranchExist(ctx, pr.HeadRepo.ID, pr.HeadBranch)
		}
		if !headBranchExist {
			return errors.Join(errSkipAutoMerge, errors.New("head branch does not exist"))
		}
	case issues_model.PullRequestFlowAGit:
		headBranchExist := git.IsReferenceExist(ctx, pr.BaseRepo, pr.GetGitHeadRefName())
		if !headBranchExist {
			return errors.Join(errSkipAutoMerge, errors.New("head branch (agit) does not exist"))
		}
	default:
		return errors.Join(errSkipAutoMerge, errors.New("unsupported pull request git flow type"))
	}

	if !setting.EnterpriseMergeGate.Enabled || !setting.EnterpriseMergeGate.Enforce {
		// Check if all checks succeeded
		pass, err := pull_service.IsPullCommitStatusPass(ctx, pr)
		if err != nil {
			return fmt.Errorf("failed to check pull commit status: %w", err)
		}
		if !pass {
			return errors.Join(errSkipAutoMerge, errors.New("unsuccessful status checks"))
		}
	}

	// Merge if all checks succeeded
	_, doer, err := user_model.GetPossibleUserByID(ctx, scheduledPRM.DoerID)
	if err != nil {
		return fmt.Errorf("failed to get scheduled user[%d]: %w", scheduledPRM.DoerID, err)
	}
	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
		if doer.ID <= 0 {
			return errors.Join(errSkipAutoMerge, errors.New("scheduled actor is no longer active"))
		}
		if doer.IsAdmin {
			doer.IsAdmin, err = access_model.HasSystemManagementAuthority(ctx, doer)
			if err != nil {
				return err
			}
		}
	}

	perm, err := access_model.GetDoerRepoPermission(ctx, pr.BaseRepo, doer)
	if err != nil {
		return fmt.Errorf("failed to get doer repo permission: %w", err)
	}

	ceiling := authz_service.CredentialCeiling{Read: true, Write: true}
	if setting.EnterpriseMergeGate.Enabled && setting.EnterpriseMergeGate.Enforce {
		ctx = authz_service.WithMergeGateAutoQueue(ctx, scheduledPRM.ID)
		ceiling, err = authz_service.MergeGateAutoCredential(ctx, scheduledPRM.ID, pr.ID, doer.ID, pr.BaseRepo)
		if err != nil {
			ceiling = authz_service.CredentialCeiling{} // 写前准入重新读取并持久化故障。
		}
	}
	ctx, _ = authz_service.WithObservationContext(ctx, authz_service.EvaluateInput{
		Actor: doer, Repo: pr.BaseRepo, Permission: &perm,
		Credential: ceiling,
		Action:     authz.MergePullRequest, ConditionContext: authz.ConditionContext{Source: "auto_merge", Branch: pr.BaseBranch, BranchKnown: true},
	})
	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce && (!setting.EnterpriseMergeGate.Enabled || !setting.EnterpriseMergeGate.Enforce) && (!doer.IsActive || doer.ProhibitLogin) {
		authz_service.FinishOperationObservation(ctx, doer.ID, pr.BaseRepoID, authz.MergePullRequest, authz_service.NativeDenied, authz_service.StageAuthorization)
		return errors.Join(errSkipAutoMerge, errors.New("scheduled actor is no longer active"))
	}

	if !setting.EnterpriseMergeGate.Enabled || !setting.EnterpriseMergeGate.Enforce {
		if err := pull_service.CheckPullMergeable(ctx, doer, &perm, pr, pull_service.MergeCheckTypeGeneral, scheduledPRM.MergeStyle, false); err != nil {
			return errors.Join(errSkipAutoMerge, errors.New("pull request is not mergeable"))
		}
	}

	if setting.EnterpriseMergeGate.Enabled {
		ctx = authz_service.WithMergeGateAutoQueue(ctx, scheduledPRM.ID)
	}

	// although expectedHeadCommitID is checked before, we should pass it to the Merge function to
	// make it be checked again in case the head commit id changed after the previous check.
	if err := pull_service.Merge(ctx, pr, doer, scheduledPRM.MergeStyle, expectedHeadCommitID, scheduledPRM.Message, true); err != nil {
		if pull_service.IsErrSHADoesNotMatch(err) {
			return errors.Join(errSkipAutoMerge, err)
		}
		// FIXME: if merge failed, we should display some error message to the pull request page, or retry later.
		// The resolution is add a new column on automerge table named `error_message` to store the error message and displayed
		// on the pull request page. But this should not be finished in a bug fix PR which will be backport to release branch.
		return fmt.Errorf("failed to merge PR:%d: %w", pr.ID, err)
	}

	// the PR has been merged, so no error should be returned after this point
	{
		deleteBranchAfterMerge, err := pull_service.ShouldDeleteBranchAfterMerge(ctx, &scheduledPRM.DeleteBranchAfterMerge, pr.BaseRepo, pr)
		if err != nil {
			log.Error("ShouldDeleteBranchAfterMerge: %v", err)
		} else if deleteBranchAfterMerge {
			cleanupCtx, observation, cleanupErr := autoMergeBranchCleanupContext(ctx, doer, pr.HeadRepoID, pr.HeadBranch, ceiling)
			if cleanupErr == nil {
				cleanupErr = repo_service.DeleteBranchAfterMerge(cleanupCtx, doer, pr.ID, nil)
			}
			outcome := authz_service.NativeSuccess
			if cleanupErr != nil {
				outcome = authz_service.NativeFailed
			}
			observation.Finish(cleanupCtx, outcome, authz_service.StageOperation)
			if cleanupErr != nil {
				log.Error("DeleteBranchAfterMerge: %v", cleanupErr)
			}
		}
	}
	return nil
}

func wakeMergeGateScope(ctx context.Context, scope authz_model.Scope) error {
	cursor := int64(0)
	for {
		var pulls []*issues_model.PullRequest
		query := db.GetEngine(ctx).Table("pull_request").Select("pull_request.*").Join("INNER", "pull_auto_merge", "pull_auto_merge.pull_id=pull_request.id").Join("INNER", "issue", "issue.id=pull_request.issue_id").Where("pull_request.has_merged=? AND issue.is_closed=? AND pull_request.id>?", false, false, cursor)
		switch scope.Type {
		case authz_model.ScopeRepo:
			query = query.And("pull_request.base_repo_id=?", scope.ID)
		case authz_model.ScopeOrg:
			query = query.Join("INNER", "repository", "repository.id=pull_request.base_repo_id").And("repository.owner_id=?", scope.ID)
		}
		if err := query.Asc("pull_request.id").Limit(100).Find(&pulls); err != nil {
			return err
		}
		if len(pulls) == 0 {
			return nil
		}
		for _, pr := range pulls {
			if err := ctx.Err(); err != nil {
				return err
			}
			cursor = pr.ID
			automergequeue.StartAutoMergeCheckByPullHead(ctx, pr)
		}
	}
}
