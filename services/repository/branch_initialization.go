// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"
	"net/http"
	"strings"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	git_model "gitea.dev/models/git"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/setting"
)

type repositoryGitInitializationKey struct{}

type repositoryGitInitialization struct {
	repoID, ownerID, creatorID int64
	branch, caller             string
}

func withRepositoryGitInitialization(ctx context.Context, marker repositoryGitInitialization) context.Context {
	return context.WithValue(ctx, repositoryGitInitializationKey{}, marker)
}

func initializeRepositoryGit(ctx context.Context, local string, repo *repo_model.Repository) error {
	marker, ok := ctx.Value(repositoryGitInitializationKey{}).(repositoryGitInitialization)
	if !ok || repo == nil || marker.repoID != repo.ID || marker.ownerID != repo.OwnerID || marker.creatorID <= 0 || marker.branch == "" || marker.branch != repo.DefaultBranch || (marker.caller != "create" && marker.caller != "generate") {
		return accessRejection("invalid_execution_context", http.StatusForbidden)
	}
	if err := gitcmd.NewCommand("check-ref-format").AddDynamicArguments(git.BranchPrefix + marker.branch).Run(ctx); err != nil {
		return accessRejection("invalid_execution_context", http.StatusForbidden)
	}
	commit, _, err := gitcmd.NewCommand("rev-parse", "--verify", "HEAD").WithDir(local).RunStdString(ctx)
	if err != nil {
		return err
	}
	commit = strings.TrimSpace(commit)
	return db.WithTx(ctx, func(ctx context.Context) error {
		current, err := repo_model.GetRepositoryByID(ctx, marker.repoID)
		if err != nil {
			return accessRejection("policy_read_failed", http.StatusServiceUnavailable)
		}
		if current.OwnerID != marker.ownerID || current.DefaultBranch != marker.branch {
			return accessRejection("invalid_execution_context", http.StatusForbidden)
		}
		if current.IsArchived || current.IsMirror || current.IsFork {
			return accessRejection("native_visibility_denied", http.StatusForbidden)
		}
		if setting.Audit.RecordOutput != setting.AuditRecordOutputDatabase {
			return accessRejection("evidence_persist_failed", http.StatusServiceUnavailable)
		}
		actor, err := user_model.GetUserByID(ctx, marker.creatorID)
		if err != nil {
			return accessRejection("policy_read_failed", http.StatusServiceUnavailable)
		}
		if !actor.IsIndividual() || !actor.IsActive || actor.ProhibitLogin {
			return accessRejection("invalid_execution_context", http.StatusForbidden)
		}
		permission, err := access_model.GetDoerRepoPermission(ctx, current, actor)
		if err != nil {
			return accessRejection("policy_read_failed", http.StatusServiceUnavailable)
		}
		if !permission.IsAdmin() {
			return accessRejection("native_visibility_denied", http.StatusForbidden)
		}
		checkEmpty := func() error {
			branches, err := db.Count[git_model.Branch](ctx, git_model.FindBranchOptions{RepoID: current.ID})
			if err != nil {
				return accessRejection("policy_read_failed", http.StatusServiceUnavailable)
			}
			refs, _, err := gitcmd.NewCommand("for-each-ref", "--format=%(refname)").WithRepo(current).RunStdString(ctx)
			if err != nil {
				return accessRejection("policy_read_failed", http.StatusServiceUnavailable)
			}
			if branches != 0 || strings.TrimSpace(refs) != "" {
				return accessRejection("invalid_execution_context", http.StatusForbidden)
			}
			return nil
		}
		if err := checkEmpty(); err != nil {
			return err
		}
		if err := recordAccessMaintenance(ctx, audit_model.RepositoryCreate, current, "repository-initial-git-"+marker.caller, "creator_id", actor.ID, "branch", marker.branch); err != nil {
			return accessRejection("evidence_persist_failed", http.StatusServiceUnavailable)
		}
		if err := gitcmd.NewCommand("fetch", "--no-tags").AddDynamicArguments(local, commit).WithRepo(current).Run(ctx); err != nil {
			return err
		}
		if err := checkEmpty(); err != nil {
			return err
		}
		return gitcmd.NewCommand("update-ref", "--no-deref").AddDynamicArguments(git.BranchPrefix+marker.branch, commit, branchEmptyID(current)).WithRepo(current).Run(ctx)
	})
}
