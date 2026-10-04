// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	git_model "gitea.dev/models/git"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/git/gitrepo"
	repo_module "gitea.dev/modules/repository"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func beginBranchGitExecution(ctx context.Context, doer *user_model.User, repo *repo_model.Repository, action authz.Action, branch string, prepare func(context.Context) ([]authz_service.GitExecutionInput, error)) (context.Context, authz.HookOperationTicket, func(error), error) {
	noop := func(error) {}
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return ctx, authz_service.ManagedHookOperationTicket(ctx, doer, repo, branch, action), noop, nil
	}
	source, ceiling := authz_service.ExecutionAttributionForActor(ctx, doer, repo.ID)
	var inputs []authz_service.GitExecutionInput
	executionCtx, admission, err := authz_service.BeginPreparedGitExecution(ctx, func(bounded context.Context) (_ []authz_service.GitExecutionInput, err error) {
		defer func() {
			if bounded.Err() != nil {
				if ctx.Err() != nil {
					err = accessRejection("execution_canceled", http.StatusForbidden)
				} else {
					err = accessRejection("execution_timeout", http.StatusServiceUnavailable)
				}
			}
		}()
		inputs, err = prepare(bounded)
		for i := range inputs {
			inputs[i].Actor, inputs[i].Repo, inputs[i].Credential, inputs[i].Source = doer, repo, ceiling, source
		}
		return inputs, err
	})
	if err == nil {
		err = admission.Start(executionCtx)
	}
	if err != nil {
		return ctx, "", noop, err
	}
	release := func() {}
	if admission != nil {
		release, err = authz_service.RegisterGitExecution(executionCtx, admission, inputs)
		if err != nil {
			admission.Finish(executionCtx, authz_service.NativeFailed, authz_service.StageOperation)
			return ctx, "", noop, err
		}
	}
	ticket := authz_service.NewHookOperationTicket(executionCtx, authz_service.EvaluateInput{Actor: doer, Repo: repo, Credential: ceiling, Action: action, ConditionContext: authz.ConditionContext{Source: source}}, []authz_service.HookOwnedObservation{{Action: action, Branch: branch}})
	return executionCtx, ticket, func(err error) {
		defer release()
		admission.Finish(executionCtx, branchMutationOutcome(err), authz_service.StageOperation)
	}, nil
}

func checkBranchExecutionNative(ctx context.Context, actor *user_model.User, repo *repo_model.Repository, kind, from, to string, force bool) error {
	if actor == nil {
		return accessRejection("invalid_execution_context", http.StatusForbidden)
	}
	if err := repo.MustNotBeArchived(); err != nil {
		return accessRejection("native_visibility_denied", http.StatusForbidden)
	}
	permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
	if err != nil {
		return accessRejection("policy_read_failed", http.StatusServiceUnavailable)
	}
	if !permission.CanWrite(unit.TypeCode) {
		return accessRejection("native_visibility_denied", http.StatusForbidden)
	}
	if kind == "delete" {
		if err := CanDeleteBranch(ctx, repo, from, actor); err != nil {
			if errors.Is(err, util.ErrPermissionDenied) {
				return accessRejection("native_visibility_denied", http.StatusForbidden)
			}
			return accessRejection("policy_read_failed", http.StatusServiceUnavailable)
		}
		return nil
	}
	if kind == "rename" {
		if from == repo.DefaultBranch && !permission.IsAdmin() {
			return accessRejection("native_visibility_denied", http.StatusForbidden)
		}
		rule, err := git_model.GetProtectedBranchRuleByName(ctx, repo.ID, from)
		if err != nil {
			return accessRejection("policy_read_failed", http.StatusServiceUnavailable)
		}
		if rule != nil && !permission.IsAdmin() {
			return accessRejection("native_visibility_denied", http.StatusForbidden)
		}
		if rule == nil {
			protected, err := git_model.IsBranchProtected(ctx, repo.ID, from)
			if err != nil {
				return accessRejection("policy_read_failed", http.StatusServiceUnavailable)
			}
			if protected {
				return accessRejection("native_visibility_denied", http.StatusForbidden)
			}
		}
	}
	rule, err := git_model.GetFirstMatchProtectedBranchRule(ctx, repo.ID, to)
	if err != nil {
		return accessRejection("policy_read_failed", http.StatusServiceUnavailable)
	}
	if rule != nil && (force && !rule.CanUserForcePush(ctx, actor) || !force && !rule.CanUserPush(ctx, actor)) {
		return accessRejection("native_visibility_denied", http.StatusForbidden)
	}
	return nil
}

func branchEmptyID(repo *repo_model.Repository) string {
	format := git.ObjectFormatFromName(repo.ObjectFormatName)
	if repo.ObjectFormatName == "" {
		format = git.Sha1ObjectFormat
	}
	return format.EmptyObjectID().String()
}

func branchEnforcementEnabled() bool {
	return setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce
}

func renameBranchWithLease(ctx context.Context, repo *repo_model.Repository, from, to, old string) error {
	fromRef, toRef := git.BranchPrefix+from, git.BranchPrefix+to
	for _, ref := range []string{fromRef, toRef} {
		if err := gitcmd.NewCommand("check-ref-format").AddDynamicArguments(ref).Run(ctx); err != nil {
			return err
		}
	}
	logPath := func(ref string) (string, error) {
		path, _, err := gitcmd.NewCommand("rev-parse", "--git-path").AddDynamicArguments("logs/" + ref).WithRepo(repo).RunStdString(ctx)
		if err != nil {
			return "", err
		}
		path = strings.TrimSpace(path)
		if !filepath.IsAbs(path) {
			path = filepath.Join(gitrepo.RepoLocalPath(repo), path)
		}
		return path, nil
	}
	fromLog, err := logPath(fromRef)
	if err != nil {
		return err
	}
	oldLog, err := os.ReadFile(fromLog)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	toLog, err := logPath(toRef)
	if err != nil {
		return err
	}
	transaction := fmt.Sprintf("create %s %s\ndelete %s %s\n", toRef, old, fromRef, old)
	if err := gitcmd.NewCommand("update-ref", "--no-deref", "--stdin", "-m").AddDynamicArguments("Branch: renamed " + fromRef + " to " + toRef).WithStdinBytes([]byte(transaction)).WithRepo(repo).Run(ctx); err != nil {
		return err
	}
	if len(oldLog) > 0 {
		newLog, err := os.ReadFile(toLog)
		if err != nil {
			return err
		}
		entry := strings.TrimSuffix(string(newLog), "\n")
		if i := strings.LastIndexByte(entry, '\n'); i >= 0 {
			entry = entry[i+1:]
		}
		entry = strings.Replace(entry, branchEmptyID(repo)+" ", old+" ", 1)
		if err := os.WriteFile(toLog, append(oldLog, []byte(entry+"\n")...), 0o600); err != nil {
			return err
		}
	}
	if err := moveBranchConfig(ctx, repo, from, to); err != nil {
		return err
	}
	head, _, err := gitcmd.NewCommand("symbolic-ref", "-q", "HEAD").WithRepo(repo).RunStdString(ctx)
	if err == nil && strings.TrimSpace(head) == fromRef {
		return git.SetDefaultBranch(ctx, repo, to)
	}
	if err != nil && !gitcmd.IsErrorExitCode(err, 1) {
		return err
	}
	return nil
}

func moveBranchConfig(ctx context.Context, repo *repo_model.Repository, from, to string) error {
	_, _, err := gitcmd.NewCommand("config", "--local", "--get-regexp").AddDynamicArguments("^branch\\." + regexp.QuoteMeta(from) + "\\.").WithRepo(repo).RunStdString(ctx)
	if gitcmd.IsErrorExitCode(err, 1) {
		return nil
	}
	if err != nil {
		return err
	}
	command := gitcmd.NewCommand("config", "--local", "--rename-section").AddDynamicArguments("branch."+from, "branch."+to)
	if to == "" {
		command = gitcmd.NewCommand("config", "--local", "--remove-section").AddDynamicArguments("branch." + from)
	}
	return command.WithRepo(repo).Run(ctx)
}

func CreateForkBranchFromBase(ctx context.Context, actor *user_model.User, base *repo_model.Repository, baseBranch string, fork *repo_model.Repository, branch string) error {
	return pushForkBranch(ctx, actor, base, baseBranch, fork, branch, true)
}

func pushForkBranch(ctx context.Context, actor *user_model.User, base *repo_model.Repository, baseBranch string, fork *repo_model.Repository, branch string, creating bool) (err error) {
	if actor == nil {
		return accessRejection("invalid_execution_context", http.StatusForbidden)
	}
	if !branchEnforcementEnabled() {
		return git.PushManaged(ctx, base, fork, git.PushOptions{Branch: baseBranch + ":" + branch, Env: repo_module.WithAuthzOperation(repo_module.PushingEnvironment(actor, fork), string(authz_service.ManagedHookOperationTicket(ctx, actor, fork, branch, authz.PushBranch)))})
	}
	old, newID := branchEmptyID(fork), ""
	var outOfDate *git.ErrPushOutOfDate
	ctx, ticket, finish, err := beginBranchGitExecution(ctx, actor, fork, authz.PushBranch, branch, func(bounded context.Context) ([]authz_service.GitExecutionInput, error) {
		baseGit, err := git.OpenRepository(bounded, base)
		if err != nil {
			return nil, err
		}
		defer baseGit.Close()
		forkGit, err := git.OpenRepository(bounded, fork)
		if err != nil {
			return nil, err
		}
		defer forkGit.Close()
		newID, err = baseGit.GetBranchCommitID(bounded, baseBranch)
		if err != nil {
			return nil, err
		}
		if forkGit.IsBranchExist(bounded, branch) {
			if creating {
				return nil, git_model.ErrBranchAlreadyExists{BranchName: branch}
			}
			old, err = forkGit.GetBranchCommitID(bounded, branch)
			if err != nil {
				return nil, err
			}
		}
		objects, _, err := gitcmd.NewCommand("rev-parse", "--git-path", "objects").WithRepo(base).RunStdString(bounded)
		if err != nil {
			return nil, err
		}
		objects = strings.TrimSpace(objects)
		if !filepath.IsAbs(objects) {
			objects = filepath.Join(gitrepo.RepoLocalPath(base), objects)
		}
		env := append(os.Environ(), "GIT_ALTERNATE_OBJECT_DIRECTORIES="+objects)
		if old != branchEmptyID(fork) {
			if err := gitcmd.NewCommand("merge-base", "--is-ancestor").AddDynamicArguments(old, newID).WithRepo(fork).WithEnv(env).Run(bounded); err != nil {
				if gitcmd.IsErrorExitCode(err, 1) {
					outOfDate = &git.ErrPushOutOfDate{Err: util.ErrInvalidArgument}
					return nil, outOfDate
				}
				return nil, err
			}
		}
		return []authz_service.GitExecutionInput{{Ref: git.RefNameFromBranch(branch), OldCommitID: old, NewCommitID: newID, GitRepo: fork, Env: env, NativeGuard: func(ctx context.Context, currentActor *user_model.User, current *repo_model.Repository) error {
			if !current.IsFork || current.ForkID != base.ID {
				return accessRejection("invalid_execution_context", http.StatusForbidden)
			}
			currentBase, err := repo_model.GetRepositoryByID(ctx, base.ID)
			if err != nil {
				return accessRejection("policy_read_failed", http.StatusServiceUnavailable)
			}
			permission, err := access_model.GetDoerRepoPermission(ctx, currentBase, currentActor)
			if err != nil {
				return accessRejection("policy_read_failed", http.StatusServiceUnavailable)
			}
			if !permission.CanRead(unit.TypeCode) {
				return accessRejection("native_visibility_denied", http.StatusForbidden)
			}
			return checkBranchExecutionNative(ctx, currentActor, current, "update", branch, branch, false)
		}}}, nil
	})
	if err != nil {
		if outOfDate != nil {
			return outOfDate
		}
		return err
	}
	defer func() { finish(err) }()
	if err := validateBranchExecutionOwner(ctx, fork); err != nil {
		return err
	}
	return git.PushManaged(ctx, base, fork, git.PushOptions{Branch: newID + ":" + git.BranchPrefix + branch, ForceWithLease: git.BranchPrefix + branch + ":" + old, Env: repo_module.WithAuthzOperation(repo_module.PushingEnvironment(actor, fork), string(ticket))})
}

func validateBranchExecutionOwner(ctx context.Context, repo *repo_model.Repository) error {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return nil
	}
	current, err := repo_model.GetRepositoryByID(ctx, repo.ID)
	if err != nil {
		return accessRejection("policy_read_failed", http.StatusServiceUnavailable)
	}
	if current.OwnerID != repo.OwnerID {
		return accessRejection("invalid_execution_context", http.StatusForbidden)
	}
	return nil
}
