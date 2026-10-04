// Copyright 2019 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package private

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/private"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	"gitea.dev/modules/web"
	"gitea.dev/services/agit"
	gitea_context "gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
	pull_service "gitea.dev/services/pull"
)

type preReceiveContext struct {
	*gitea_context.PrivateContext
	env           []string
	policyContext context.Context
	opts          *private.HookOptions

	// this context should only contain shared variables, mutable variables like "current branch name" shouldn't be put here
	canWriteCodeUnitCached *bool
	canCreatePullRequest   *bool
	protectedTags          []*git_model.ProtectedTag
}

func (ctx *preReceiveContext) canWriteCodeUnit() bool {
	if ctx.canWriteCodeUnitCached == nil {
		ctx.canWriteCodeUnitCached = new(ctx.Repo.Permission.CanWrite(unit.TypeCode))
	}
	return *ctx.canWriteCodeUnitCached
}

// canWriteCodeRef returns true if pusher can write to the code ref (branch/tag/commit)
func (ctx *preReceiveContext) canWriteCodeRef(refFullName git.RefName) bool {
	if ctx.canWriteCodeUnit() {
		return true
	}
	// then check whether if the pusher is a maintainer who can write the PR author's head repo branch
	if !refFullName.IsBranch() {
		return false
	}
	return issues_model.CanMaintainerWriteToBranch(ctx.nativeContext(), ctx.Repo.Permission, refFullName.BranchName(), ctx.Doer)
}

// assertCanWriteRef returns true if pusher can write to the code ref, otherwise it responds with 403 Forbidden and returns false
func (ctx *preReceiveContext) assertCanWriteRef(refFullName git.RefName) bool {
	if !ctx.canWriteCodeRef(refFullName) {
		if ctx.Written() {
			return false
		}
		ctx.PrivateUserErrorf(http.StatusForbidden, "User permission denied for writing.")
		return false
	}
	return true
}

// CanCreatePullRequest returns true if pusher can create pull requests
func (ctx *preReceiveContext) CanCreatePullRequest() bool {
	if ctx.canCreatePullRequest == nil {
		ctx.canCreatePullRequest = new(ctx.Repo.Permission.CanRead(unit.TypePullRequests))
	}
	return *ctx.canCreatePullRequest
}

// AssertCreatePullRequest returns true if can create pull requests
func (ctx *preReceiveContext) AssertCreatePullRequest() bool {
	if !ctx.CanCreatePullRequest() {
		if ctx.Written() {
			return false
		}
		ctx.PrivateUserErrorf(http.StatusForbidden, "User permission denied for creating pull-request.")
		return false
	}
	return true
}

// HookPreReceive checks whether a individual commit is acceptable
func HookPreReceive(ctx *gitea_context.PrivateContext) {
	opts := web.GetForm[*private.HookOptions](ctx)
	if !loadContextDoerPermission(ctx, opts.UserID, opts.UserExtDoerData) {
		return
	}

	ourCtx := &preReceiveContext{
		PrivateContext: ctx,
		env:            generateGitEnv(opts), // Generate git environment for checking commits
		opts:           opts,
	}

	operationCtx, operation := receiveOperation(ctx, opts)
	if len(opts.OldCommitIDs) != len(opts.NewCommitIDs) || len(opts.OldCommitIDs) != len(opts.RefFullNames) {
		ctx.PrivateUserErrorf(http.StatusForbidden, "invalid_execution_context")
		return
	}

	// Iterate across the provided old commit IDs
	for i := range opts.OldCommitIDs {
		oldCommitID := opts.OldCommitIDs[i]
		newCommitID := opts.NewCommitIDs[i]
		refFullName := opts.RefFullNames[i]

		switch {
		case refFullName.IsBranch():
			finish := observeReceiveBranch(operationCtx, ctx, operation, oldCommitID, refFullName)
			if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
				defer finish()
			}
			preReceiveBranch(ourCtx, oldCommitID, newCommitID, refFullName)
			if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
				finish()
			}
		case refFullName.IsTag():
			preReceiveTag(ourCtx, refFullName)
		case git.DefaultFeatures().SupportProcReceive && refFullName.IsFor():
			preReceiveFor(ourCtx, refFullName)
			if ctx.Written() {
				outcome := authz_service.NativeFailed
				if ctx.WrittenStatus() == http.StatusForbidden || ctx.WrittenStatus() == http.StatusUnauthorized {
					outcome = authz_service.NativeDenied
				}
				observationCtx, observation := authz_service.BeginHookPullRequestObservation(operationCtx, ctx.Doer, ctx.Repo.Repository, "", string(refFullName))
				observation.Finish(observationCtx, outcome, authz_service.StagePreReceive)
			}
		default:
			ourCtx.assertCanWriteRef(refFullName)
		}
		if ctx.Written() {
			return
		}
	}
	if !admitReceiveBranches(operationCtx, ctx, operation, opts) {
		return
	}

	ctx.PlainText(http.StatusOK, "ok")
}

func (ctx *preReceiveContext) nativeContext() context.Context {
	if ctx.policyContext != nil {
		return ctx.policyContext
	}
	return ctx
}

type nativeReceiveError struct {
	status  int
	message string
}

func receiveBranchError(status int, format string, args ...any) *nativeReceiveError {
	return &nativeReceiveError{status: status, message: fmt.Sprintf(format, args...)}
}

func preReceiveBranch(ctx *preReceiveContext, oldCommitID, newCommitID string, refFullName git.RefName) {
	if err := checkPreReceiveBranch(ctx, oldCommitID, newCommitID, refFullName); err != nil {
		if err.status == http.StatusInternalServerError {
			ctx.PrivateInternalErrorf("%s", err.message)
		} else {
			ctx.PrivateUserErrorf(err.status, "%s", err.message)
		}
	}
}

func checkPreReceiveBranch(ctx *preReceiveContext, oldCommitID, newCommitID string, refFullName git.RefName) *nativeReceiveError {
	nativeCtx := ctx.nativeContext()
	branchName := refFullName.BranchName()

	if !ctx.canWriteCodeRef(refFullName) {
		return receiveBranchError(http.StatusForbidden, "User permission denied for writing.")
	}

	repo := ctx.Repo.Repository
	gitRepo := ctx.Repo.GitRepo
	objectFormat := ctx.Repo.GetObjectFormat()

	defaultBranch := repo.DefaultBranch
	if ctx.opts.IsWiki && repo.DefaultWikiBranch != "" {
		defaultBranch = repo.DefaultWikiBranch
	}
	if branchName == defaultBranch && newCommitID == objectFormat.EmptyObjectID().String() {
		return receiveBranchError(http.StatusForbidden, "Branch %s is the default branch and cannot be deleted", branchName)
	}

	protectBranch, err := git_model.GetFirstMatchProtectedBranchRule(nativeCtx, repo.ID, branchName)
	if err != nil {
		return receiveBranchError(http.StatusInternalServerError, "Unable to get protected branch: %v", err)
	}

	// Allow pushes to non-protected branches
	if protectBranch == nil {
		return nil
	}
	protectBranch.Repo = repo

	// This ref is a protected branch.
	//
	// First of all we need to enforce absolutely:
	//
	// 1. Detect and prevent deletion of the branch
	if newCommitID == objectFormat.EmptyObjectID().String() {
		return receiveBranchError(http.StatusForbidden, "Branch %s is protected from deletion", branchName)
	}

	isForcePush := false

	// 2. Disallow force pushes to protected branches
	if oldCommitID != objectFormat.EmptyObjectID().String() {
		output, _, err := gitcmd.NewCommand("rev-list", "--max-count=1").
			AddDynamicArguments(oldCommitID, "^"+newCommitID).
			WithEnv(ctx.env).WithRepo(repo).RunStdString(nativeCtx)
		if err != nil {
			return receiveBranchError(http.StatusInternalServerError, "Unable to detect force push between %s and %s in %s: %v", oldCommitID, newCommitID, repo.FullName(), err)
		} else if len(output) > 0 {
			if protectBranch.CanForcePush {
				isForcePush = true
			} else {
				return receiveBranchError(http.StatusForbidden, "Branch %s is protected from force push", branchName)
			}
		}
	}

	// 3. Enforce require signed commits
	if protectBranch.RequireSignedCommits {
		err := verifyCommits(nativeCtx, oldCommitID, newCommitID, gitRepo, ctx.env)
		if err != nil {
			errUnverified, ok := errors.AsType[*errUnverifiedCommit](err)
			if !ok {
				return receiveBranchError(http.StatusInternalServerError, "Unable to check commits from %s to %s: %v", oldCommitID, newCommitID, err)
			}
			return receiveBranchError(http.StatusForbidden, "Branch %s is protected from unverified commit %s", branchName, errUnverified.sha)
		}
	}

	// Now there are several tests which can be overridden:
	//
	// 4. Check protected file patterns - this is overridable from the UI
	changedProtectedfiles := false
	protectedFilePath := ""

	globs := protectBranch.GetProtectedFilePatterns()
	if len(globs) > 0 {
		_, err := pull_service.CheckFileProtection(nativeCtx, gitRepo, branchName, oldCommitID, newCommitID, globs, 1, ctx.env)
		if err != nil {
			errFilePathProtected, ok := errors.AsType[pull_service.ErrFilePathProtected](err)
			if !ok {
				return receiveBranchError(http.StatusInternalServerError, "Unable to check file protection for commits from %s to %s: %v", oldCommitID, newCommitID, err)
			}

			changedProtectedfiles = true
			protectedFilePath = errFilePathProtected.Path
		}
	}

	// 5. Check if the doer is allowed to push (and force-push if the incoming push is a force-push)
	var canPush bool
	if ctx.opts.UserID == user_model.DeployKeyUserID {
		// This flag is only ever true if protectBranch.CanForcePush is true
		if isForcePush {
			canPush = !changedProtectedfiles && protectBranch.CanPush && (!protectBranch.EnableForcePushAllowlist || protectBranch.ForcePushAllowlistDeployKeys)
		} else {
			canPush = !changedProtectedfiles && protectBranch.CanPush && (!protectBranch.EnableWhitelist || protectBranch.WhitelistDeployKeys)
		}
	} else {
		if isForcePush {
			canPush = !changedProtectedfiles && protectBranch.CanUserForcePush(nativeCtx, ctx.Doer)
		} else {
			canPush = !changedProtectedfiles && protectBranch.CanUserPush(nativeCtx, ctx.Doer)
		}
	}

	// 6. If we're not allowed to push directly
	if !canPush {
		// Is this is a merge from the UI/API?
		if ctx.opts.PullRequestID == 0 {
			// 6a. If we're not merging from the UI/API then there are two ways we got here:
			//
			// We are changing a protected file, and we're not allowed to do that
			if changedProtectedfiles {
				return receiveBranchError(http.StatusForbidden, "Branch %s is protected from changing file %s", branchName, protectedFilePath)
			}

			// Allow commits that only touch unprotected files
			globs := protectBranch.GetUnprotectedFilePatterns()
			if len(globs) > 0 {
				unprotectedFilesOnly, err := pull_service.CheckUnprotectedFiles(nativeCtx, gitRepo, branchName, oldCommitID, newCommitID, globs, ctx.env)
				if err != nil {
					return receiveBranchError(http.StatusInternalServerError, "Unable to check file protection for commits from %s to %s: %v", oldCommitID, newCommitID, err)
				}
				if unprotectedFilesOnly {
					// Commit only touches unprotected files, this is allowed
					return nil
				}
			}

			// Or we're simply not able to push to this protected branch
			if isForcePush {
				return receiveBranchError(http.StatusForbidden, "Not allowed to force-push to protected branch %s", branchName)
			}
			return receiveBranchError(http.StatusForbidden, "Not allowed to push to protected branch %s", branchName)
		}
		// 6b. Merge (from UI or API)

		// Get the PR, user and permissions for the user in the repository
		pr, err := issues_model.GetPullRequestByID(nativeCtx, ctx.opts.PullRequestID)
		if err != nil {
			return receiveBranchError(http.StatusInternalServerError, "Unable to get PullRequest %d Error: %v", ctx.opts.PullRequestID, err)
		}

		// Now check if the user is allowed to merge PRs for this repository
		// Note: we can use ctx.perm and ctx.user directly as they will have been loaded above
		allowedMerge, err := pull_service.IsUserAllowedToMerge(nativeCtx, pr, ctx.Repo.Permission, ctx.Doer)
		if err != nil {
			return receiveBranchError(http.StatusInternalServerError, "Error calculating if allowed to merge: %v", err)
		}

		if !allowedMerge {
			return receiveBranchError(http.StatusForbidden, "Not allowed to push to protected branch %s", branchName)
		}

		// If we can bypass branch protection we can ignore status checks, reviews and protected files
		if git_model.CanBypassBranchProtection(nativeCtx, protectBranch, ctx.Doer, ctx.Repo.Permission.IsAdmin()) {
			return nil
		}

		// Now if we're not an admin - we can't overwrite protected files so fail now
		if changedProtectedfiles {
			return receiveBranchError(http.StatusForbidden, "Branch %s is protected from changing file %s", branchName, protectedFilePath)
		}

		// Check all status checks and reviews are ok
		if err := pull_service.CheckPullBranchProtections(nativeCtx, pr, true); err != nil {
			if errors.Is(err, pull_service.ErrNotReadyToMerge) {
				return receiveBranchError(http.StatusForbidden, "Not allowed to push to protected branch %s and pr #%d is not ready to be merged: %s", branchName, ctx.opts.PullRequestID, err.Error())
			}
			return receiveBranchError(http.StatusInternalServerError, "Unable to get status of pull request %d: %v", ctx.opts.PullRequestID, err)
		}
	}
	return nil
}

func preReceiveTag(ctx *preReceiveContext, refFullName git.RefName) {
	if !ctx.assertCanWriteRef(refFullName) {
		return
	}

	tagName := refFullName.TagName()

	if ctx.protectedTags == nil {
		var err error
		ctx.protectedTags, err = git_model.GetProtectedTags(ctx, ctx.Repo.Repository.ID)
		if err != nil {
			ctx.PrivateInternalErrorf("Unable to get protected tags: %v", err)
			return
		}
		ctx.protectedTags = util.SliceNilAsEmpty(ctx.protectedTags)
	}

	isAllowed, err := git_model.IsUserAllowedToControlTag(ctx, ctx.protectedTags, tagName, ctx.opts.UserID)
	if err != nil {
		ctx.PrivateInternalErrorf("unable to check allowed tags: %v", err)
		return
	}
	if !isAllowed {
		ctx.PrivateUserErrorf(http.StatusForbidden, "Tag %s is protected", tagName)
		return
	}
}

func preReceiveFor(ctx *preReceiveContext, refFullName git.RefName) {
	if !ctx.AssertCreatePullRequest() {
		return
	}

	if ctx.Repo.Repository.IsEmpty {
		ctx.PrivateUserErrorf(http.StatusForbidden, "Can't create pull request for an empty repository.")
		return
	}

	if ctx.opts.IsWiki {
		ctx.PrivateUserErrorf(http.StatusForbidden, "Pull requests are not supported on the wiki.")
		return
	}

	_, _, err := agit.GetAgitBranchInfo(ctx, ctx.Repo.Repository.ID, refFullName.ForBranchName())
	if err != nil {
		if !errors.Is(err, util.ErrNotExist) {
			ctx.PrivateUserErrorf(http.StatusForbidden, "Unexpected ref: %s", refFullName)
		} else {
			ctx.PrivateInternalErrorf("Unable to get branch info for ref %s: %v", refFullName, err)
		}
	}
}

func generateGitEnv(opts *private.HookOptions) (env []string) {
	env = os.Environ()
	if opts.GitAlternativeObjectDirectories != "" {
		env = append(env,
			private.GitAlternativeObjectDirectories+"="+opts.GitAlternativeObjectDirectories)
	}
	if opts.GitObjectDirectory != "" {
		env = append(env,
			private.GitObjectDirectory+"="+opts.GitObjectDirectory)
	}
	if opts.GitQuarantinePath != "" {
		env = append(env,
			private.GitQuarantinePath+"="+opts.GitQuarantinePath)
	}
	return env
}
