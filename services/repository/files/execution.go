// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package files

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"

	"gitea.dev/models/db"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/lfs"
	"gitea.dev/modules/log"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	asymkey_service "gitea.dev/services/asymkey"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func (t *TemporaryUploadRepository) beginPushExecution(ctx context.Context, actor *user_model.User, commit, branch string, force bool) (context.Context, *authz_service.Admission, []authz_service.GitExecutionInput, error) {
	var inputs []authz_service.GitExecutionInput
	executionCtx, admission, err := authz_service.BeginPreparedGitExecution(authz_service.ExecutionParentContext(ctx), func(bounded context.Context) ([]authz_service.GitExecutionInput, error) {
		old, err := git.GetBranchCommitID(bounded, t.repo, branch)
		if errors.Is(err, util.ErrNotExist) {
			format, formatErr := t.gitRepo.GetObjectFormat(bounded)
			if formatErr != nil {
				return nil, &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
			}
			old, err = format.EmptyObjectID().String(), nil
		}
		if err != nil {
			return nil, &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
		}
		if !force {
			newCommit, err := t.gitRepo.GetCommit(bounded, commit)
			if err != nil {
				return nil, &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
			}
			isForce, err := newCommit.IsForcePush(bounded, t.gitRepo, old)
			if err != nil {
				return nil, &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
			}
			if isForce {
				return nil, &authz_service.ExecutionError{Reason: "native_visibility_denied", Status: 403}
			}
		}
		source, ceiling := authz_service.ExecutionAttributionForActor(ctx, actor, t.repo.ID)
		if source == "web" {
			source = "file_editor"
		}
		inputs = []authz_service.GitExecutionInput{{Actor: actor, Repo: t.repo, Credential: ceiling, Source: source, Ref: git.RefNameFromBranch(branch), OldCommitID: old, NewCommitID: commit, GitRepo: t.gitRepo, NativeGuard: func(snapshot context.Context, current *user_model.User, repo *repo_model.Repository) error {
			return t.checkPushNative(snapshot, current, repo, old, commit, branch)
		}}}
		return inputs, nil
	})
	return executionCtx, admission, inputs, err
}

func (t *TemporaryUploadRepository) checkPushNative(ctx context.Context, actor *user_model.User, original *repo_model.Repository, old, commit, branch string) error {
	denied := &authz_service.ExecutionError{Reason: "native_visibility_denied", Status: 403}
	failure := &authz_service.ExecutionError{Reason: "policy_read_failed", Status: 503}
	repo, err := repo_model.GetRepositoryByID(ctx, original.ID)
	if repo_model.IsErrRepoNotExist(err) || err == nil && repo.OwnerID != original.OwnerID {
		return &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
	}
	if err != nil {
		return failure
	}
	if actor.IsAdmin {
		trusted, err := access_model.HasSystemManagementAuthority(ctx, actor)
		if err != nil {
			return failure
		}
		actor.IsAdmin = trusted
	}
	permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
	if err != nil {
		return failure
	}
	if !permission.CanWrite(unit.TypeCode) && !issues_model.CanMaintainerWriteToBranch(ctx, permission, branch, actor) {
		return denied
	}
	rule, err := git_model.GetFirstMatchProtectedBranchRule(ctx, repo.ID, branch)
	if err != nil {
		return failure
	}
	if rule == nil {
		return nil
	}
	rule.Repo = repo
	newCommit, err := t.gitRepo.GetCommit(ctx, commit)
	if err != nil {
		return &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
	}
	isForce, err := newCommit.IsForcePush(ctx, t.gitRepo, old)
	if err != nil {
		return &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
	}
	if isForce && !rule.CanForcePush {
		return denied
	}
	canPush := rule.CanUserPush(ctx, actor)
	if isForce {
		canPush = rule.CanUserForcePush(ctx, actor)
	}
	if !canPush && len(rule.GetUnprotectedFilePatterns()) == 0 {
		return denied
	}
	var paths []string
	if !canPush || len(rule.GetProtectedFilePatterns()) > 0 {
		paths, err = t.pushChangedPaths(ctx, old, commit, branch)
		if err != nil {
			return err
		}
	}
	protectedPatterns, unprotectedPatterns := rule.GetProtectedFilePatterns(), rule.GetUnprotectedFilePatterns()
	for _, path := range paths {
		if rule.IsProtectedFile(protectedPatterns, path) || !canPush && !rule.IsUnprotectedFile(unprotectedPatterns, path) {
			return denied
		}
	}
	if rule.RequireSignedCommits {
		return t.checkPushSignatures(ctx, old, commit)
	}
	return nil
}

func (t *TemporaryUploadRepository) pushChangedPaths(ctx context.Context, old, commit, branch string) ([]string, error) {
	invalid := &authz_service.ExecutionError{Reason: "invalid_execution_context", Status: 403}
	format, err := t.gitRepo.GetObjectFormat(ctx)
	if err != nil {
		return nil, invalid
	}
	if old == format.EmptyObjectID().String() {
		old, err = t.gitRepo.GetCommitBranchStart(ctx, nil, branch, commit)
		if err != nil || old == "" {
			return nil, invalid
		}
	}
	cmd := gitcmd.NewCommand("diff", "--no-ext-diff", "--no-textconv", "--name-only", "--no-renames", "-z").AddDynamicArguments(old, commit).AddArguments("--")
	reader, closeReader := cmd.MakeStdoutPipe()
	defer closeReader()
	var paths []string
	err = cmd.WithRepo(t.gitRepo).WithPipelineFunc(func(gitCtx gitcmd.Context) error {
		scanner := bufio.NewScanner(reader)
		scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
			if i := bytes.IndexByte(data, 0); i >= 0 {
				return i + 1, data[:i], nil
			}
			if atEOF && len(data) != 0 {
				return 0, nil, invalid
			}
			return 0, nil, nil
		})
		for scanner.Scan() {
			if len(paths) >= authz.MaxContextPaths {
				return gitCtx.CancelPipeline(&authz_service.ExecutionError{Reason: "context_limit_exceeded", Status: 403})
			}
			paths = append(paths, scanner.Text())
		}
		return gitCtx.CancelPipeline(scanner.Err())
	}).Run(ctx)
	if err != nil {
		if typed, ok := errors.AsType[*authz_service.ExecutionError](err); ok {
			return nil, typed
		}
		return nil, invalid
	}
	return paths, nil
}

func (t *TemporaryUploadRepository) checkPushSignatures(ctx context.Context, old, commit string) error {
	failure := &authz_service.ExecutionError{Reason: "policy_read_failed", Status: 503}
	format, err := t.gitRepo.GetObjectFormat(ctx)
	if err != nil {
		return failure
	}
	cmd := gitcmd.NewCommand("rev-list")
	if old == format.EmptyObjectID().String() {
		cmd.AddDynamicArguments(commit).AddArguments("--not", "--all")
	} else {
		cmd.AddDynamicArguments(old + "..." + commit)
	}
	reader, closeReader := cmd.MakeStdoutPipe()
	defer closeReader()
	err = cmd.WithRepo(t.gitRepo).WithPipelineFunc(func(gitCtx gitcmd.Context) error {
		scanner := bufio.NewScanner(reader)
		for scanner.Scan() {
			candidate, err := t.gitRepo.GetCommit(ctx, scanner.Text())
			if err != nil {
				return gitCtx.CancelPipeline(failure)
			}
			if !asymkey_service.ParseCommitWithSignature(ctx, candidate).Verified {
				return gitCtx.CancelPipeline(&authz_service.ExecutionError{Reason: "native_visibility_denied", Status: 403})
			}
		}
		return gitCtx.CancelPipeline(scanner.Err())
	}).Run(ctx)
	if err != nil {
		if typed, ok := errors.AsType[*authz_service.ExecutionError](err); ok {
			return typed
		}
		return failure
	}
	return nil
}

type stagedLFSObject struct {
	pointer lfs.Pointer
	path    string
	store   *lfs.ContentStore
}

func (t *TemporaryUploadRepository) stageLFS(pointer lfs.Pointer, reader io.Reader, store *lfs.ContentStore) error {
	file, err := os.CreateTemp(t.basePath, "authz-lfs-*")
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(file, reader)
	closeErr := file.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	t.pendingLFS = append(t.pendingLFS, stagedLFSObject{pointer: pointer, path: file.Name(), store: store})
	return nil
}

func (t *TemporaryUploadRepository) flushStagedLFS(ctx context.Context) error {
	for _, object := range t.pendingLFS {
		file, err := os.Open(object.path)
		if err != nil {
			return err
		}
		err = t.storeStagedLFS(ctx, object.pointer, file, object.store)
		closeErr := file.Close()
		if err := errors.Join(err, closeErr); err != nil {
			return err
		}
	}
	t.pendingLFS = nil
	return nil
}

func (t *TemporaryUploadRepository) storeStagedLFS(ctx context.Context, pointer lfs.Pointer, reader io.Reader, store *lfs.ContentStore) error {
	_, err := git_model.GetLFSMetaObjectByOid(ctx, t.repo.ID, pointer.Oid)
	if errors.Is(err, git_model.ErrLFSObjectNotExist) {
		meta := &git_model.LFSMetaObject{Pointer: pointer, RepositoryID: t.repo.ID}
		if err := db.Insert(ctx, meta); err != nil {
			return err
		}
		t.createdLFSMetaIDs = append(t.createdLFSMetaIDs, meta.ID)
	} else if err != nil {
		return err
	}
	if exists, err := store.Exists(pointer); err != nil || exists {
		return err
	}
	return store.Put(pointer, reader)
}

func (t *TemporaryUploadRepository) removeCreatedLFSMeta(ctx context.Context) {
	for _, id := range t.createdLFSMetaIDs {
		if _, err := db.DeleteByID[git_model.LFSMetaObject](ctx, id); err != nil {
			log.Error("Unable to clean newly created LFS metadata: %v", err)
		}
	}
}

func storeFileLFS(ctx context.Context, repoID int64, pointer lfs.Pointer, reader io.Reader, contentStore *lfs.ContentStore) error {
	meta, err := git_model.NewLFSMetaObject(ctx, repoID, pointer)
	if err != nil {
		return err
	}
	exists, err := contentStore.Exists(meta.Pointer)
	if err != nil || exists {
		return err
	}
	if err := contentStore.Put(meta.Pointer, reader); err != nil {
		_, removeErr := git_model.RemoveLFSMetaObjectByOid(ctx, repoID, meta.Oid)
		return errors.Join(err, removeErr)
	}
	return nil
}

func (t *TemporaryUploadRepository) storeOrStageLFS(ctx context.Context, repoID int64, pointer lfs.Pointer, reader io.Reader, store *lfs.ContentStore) error {
	if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
		return t.stageLFS(pointer, reader, store)
	}
	return storeFileLFS(ctx, repoID, pointer, reader, store)
}
