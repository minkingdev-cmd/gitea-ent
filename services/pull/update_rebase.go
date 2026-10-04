// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"fmt"
	"strings"

	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/log"
	repo_module "gitea.dev/modules/repository"
	"gitea.dev/modules/setting"
	authz_service "gitea.dev/services/enterpriseauthz"
)

// updateHeadByRebaseOnToBase handles updating a PR's head branch by rebasing it on the PR current base branch
func updateHeadByRebaseOnToBase(ctx context.Context, pr *issues_model.PullRequest, doer *user_model.User, execution *mergeExecution) error {
	// "Clone" base repo and add the cache headers for the head repo and branch
	mergeCtx, cancel, err := createTemporaryRepoForMerge(ctx, pr, doer, "")
	if err != nil {
		return err
	}
	defer cancel()

	// Determine the old merge-base before the rebase - we use this for LFS push later on
	oldMergeBase, _, _ := gitcmd.NewCommand("merge-base").AddDashesAndList(tmpRepoBaseBranch, tmpRepoTrackingBranch).
		WithRepo(mergeCtx.tmpRepo).RunStdString(ctx)
	oldMergeBase = strings.TrimSpace(oldMergeBase)
	oldHead, err := git.GetFullCommitID(ctx, mergeCtx.tmpRepo, tmpRepoTrackingBranch)
	if err != nil {
		return err
	}

	// Rebase the tracking branch on to the base as the staging branch
	if err := rebaseTrackingOnToBase(mergeCtx, repo_model.MergeStyleRebaseUpdate); err != nil {
		return err
	}
	newHead, err := git.GetFullCommitID(ctx, mergeCtx.tmpRepo, tmpRepoStagingBranch)
	if err != nil {
		return err
	}
	ctx, ticket, release, err := beginPullGitExecution(ctx, doer, pr.HeadRepo, mergeCtx.tmpRepo, pr.HeadBranch, oldHead, newHead, false, true, execution)
	if err != nil {
		return err
	}
	defer release()

	if setting.LFS.StartServer {
		// Now we need to ensure that the head repository contains any LFS objects between the new base and the old mergebase
		// It's questionable about where this should go - either after or before the push
		// I think in the interests of data safety - failures to push to the lfs should prevent
		// the push as you can always re-rebase.
		if err := LFSPush(ctx, mergeCtx.tmpBasePath, mergeCtx.tmpRepo, tmpRepoBaseBranch, oldMergeBase, &issues_model.PullRequest{
			HeadRepoID: pr.BaseRepoID,
			BaseRepoID: pr.HeadRepoID,
		}); err != nil {
			log.Error("Unable to push lfs objects between %s and %s up to head branch in %-v: %v", tmpRepoBaseBranch, oldMergeBase, pr, err)
			return err
		}
	}

	// Now determine who the pushing author should be
	var headUser *user_model.User
	if err := pr.HeadRepo.LoadOwner(ctx); err != nil {
		if !user_model.IsErrUserNotExist(err) {
			log.Error("Can't find user: %d for head repository in %-v - %v", pr.HeadRepo.OwnerID, pr, err)
			return err
		}
		log.Error("Can't find user: %d for head repository in %-v - defaulting to doer: %-v - %v", pr.HeadRepo.OwnerID, pr, doer, err)
		headUser = doer
	} else {
		headUser = pr.HeadRepo.Owner
	}

	pushCmd := gitcmd.NewCommand("push", "-f", "head_repo").
		AddDynamicArguments(tmpRepoStagingBranch + ":" + git.BranchPrefix + pr.HeadBranch)
	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
		pushCmd = gitcmd.NewCommand("push", "head_repo").AddOptionFormat("--force-with-lease=%s:%s", git.BranchPrefix+pr.HeadBranch, oldHead).
			AddDynamicArguments(tmpRepoStagingBranch + ":" + git.BranchPrefix + pr.HeadBranch)
	}

	// Push back to the head repository.
	// TODO: this cause an api call to "/api/internal/hook/post-receive/...",
	//       that prevents us from doint the whole merge in one db transaction
	mergeCtx.outbuf.Reset()

	env := repo_module.FullPushingEnvironment(
		headUser, doer, pr.HeadRepo, pr.HeadRepo.Name, pr.ID, pr.Index,
	)
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		ticket = authz_service.ManagedHookOperationTicket(ctx, doer, pr.HeadRepo, pr.HeadBranch, authz.PushBranch)
	}
	env = repo_module.WithAuthzOperation(env, string(ticket))
	if err := pushCmd.
		WithEnv(env).
		WithRepo(mergeCtx.tmpRepo).
		WithStdoutBuffer(mergeCtx.outbuf).
		RunWithStderr(ctx); err != nil {
		if strings.Contains(err.Stderr(), "non-fast-forward") {
			return &git.ErrPushOutOfDate{
				StdOut: mergeCtx.outbuf.String(),
				StdErr: err.Stderr(),
				Err:    err,
			}
		} else if strings.Contains(err.Stderr(), "! [remote rejected]") {
			err := &git.ErrPushRejected{
				StdOut: mergeCtx.outbuf.String(),
				StdErr: err.Stderr(),
				Err:    err,
			}
			err.GenerateMessage()
			return err
		}
		return fmt.Errorf("git push: %s", err.Stderr())
	}
	mergeCtx.outbuf.Reset()
	return nil
}
