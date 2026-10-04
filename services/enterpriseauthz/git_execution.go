// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"strings"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/git/gitrepo"
)

type GitExecutionInput struct {
	Actor                    *user_model.User
	Repo                     *repo_model.Repository
	Credential               CredentialCeiling
	Source                   string
	Ref                      git.RefName
	OldCommitID, NewCommitID string
	GitRepo                  gitrepo.RepositoryFacade
	Env                      []string
	Merge                    bool
	NativeGuard              func(context.Context, *user_model.User, *repo_model.Repository) error
}

type diffPathBuffer struct{ bytes.Buffer }

func (w *diffPathBuffer) Write(data []byte) (int, error) {
	if w.Len()+len(data) > authz.MaxBodyBytes {
		return 0, &ExecutionError{Reason: "context_limit_exceeded", Status: http.StatusForbidden}
	}
	return w.Buffer.Write(data)
}

func gitExecutionIntent(input GitExecutionInput) string {
	hash := sha256.Sum256([]byte(string(input.Ref)))
	kind := "push"
	if input.Merge {
		kind = "merge"
	}
	return "git:" + kind + ":" + hex.EncodeToString(hash[:]) + ":" + input.OldCommitID + ":" + input.NewCommitID
}

func BeginGitExecution(ctx context.Context, inputs []GitExecutionInput) (context.Context, *Admission, error) {
	return BeginPreparedGitExecution(ctx, func(context.Context) ([]GitExecutionInput, error) { return inputs, nil })
}

func BeginPreparedGitExecution(ctx context.Context, prepare func(context.Context) ([]GitExecutionInput, error)) (context.Context, *Admission, error) {
	return BeginPreparedExecution(ctx, func(bounded context.Context) ([]ExecutionInput, error) {
		inputs, err := prepare(bounded)
		if err != nil {
			return nil, err
		}
		return gitExecutionEntries(inputs), nil
	})
}

func gitExecutionEntries(inputs []GitExecutionInput) []ExecutionInput {
	entries := make([]ExecutionInput, 0, len(inputs))
	for _, input := range inputs {
		input.Env = slices.Clone(input.Env)
		entries = append(entries, ExecutionInput{EvaluateInput: EvaluateInput{Actor: input.Actor, Repo: input.Repo, Credential: input.Credential, Action: authz.PushBranch, ConditionContext: authz.ConditionContext{Source: input.Source}}, Intent: gitExecutionIntent(input), resolve: func(snapshot context.Context, base ExecutionInput) ([]ExecutionInput, error) {
			input.Actor, input.Repo, input.Credential = base.Actor, base.Repo, base.Credential
			return gitMutationActions(snapshot, input)
		}})
	}
	return entries
}

func gitMutationActions(ctx context.Context, input GitExecutionInput) ([]ExecutionInput, error) {
	invalid := &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	if input.Repo == nil || input.GitRepo == nil || !input.Ref.IsBranch() || input.Ref.BranchName() == "" {
		return nil, invalid
	}
	format := git.ObjectFormatFromName(input.Repo.ObjectFormatName)
	if input.Repo.ObjectFormatName == "" {
		format = git.Sha1ObjectFormat
	}
	old, newID := input.OldCommitID, input.NewCommitID
	for _, id := range []string{old, newID} {
		if len(id) != format.FullLength() {
			return nil, invalid
		}
		if _, err := hex.DecodeString(id); err != nil {
			return nil, invalid
		}
	}
	if old == format.EmptyObjectID().String() {
		old = format.EmptyTree().String()
	}
	if newID == format.EmptyObjectID().String() {
		newID = format.EmptyTree().String()
	}
	paths, err := gitChangedPaths(ctx, input, old, newID, true)
	if err != nil {
		return nil, err
	}
	rule, err := git_model.GetFirstMatchProtectedBranchRule(ctx, input.Repo.ID, input.Ref.BranchName())
	if err != nil {
		return nil, &ExecutionError{Reason: "policy_read_failed", Status: http.StatusServiceUnavailable}
	}
	actions := make([]authz.Action, 0, 2)
	if input.Merge {
		actions = append(actions, authz.MergePullRequest)
	} else if rule != nil {
		actions = append(actions, authz.PushProtectedBranch)
	}
	if len(paths) > 0 {
		actions = append(actions, authz.ManageCodeowners)
	}
	if len(actions) == 0 {
		return nil, nil
	}
	if input.Actor == nil || input.Actor.ID == 0 || !authz.ValidSource(input.Source) || input.Source == "system" || input.Source == "diagnostic" {
		return nil, invalid
	}
	if input.NativeGuard != nil {
		actor := input.Actor
		if actor.ID > 0 {
			actor, err = user_model.GetUserByID(ctx, actor.ID)
			if err != nil {
				if user_model.IsErrUserNotExist(err) {
					return nil, invalid
				}
				return nil, &ExecutionError{Reason: "policy_read_failed", Status: http.StatusServiceUnavailable}
			}
		}
		if err := input.NativeGuard(ctx, actor, input.Repo); err != nil {
			if _, typed := errors.AsType[*ExecutionError](err); typed {
				return nil, err
			}
			return nil, &ExecutionError{Reason: "policy_read_failed", Status: http.StatusServiceUnavailable}
		}
	}
	complete, err := gitNeedsPathContext(ctx, input, actions)
	if err != nil {
		return nil, err
	}
	if complete {
		paths, err = gitChangedPaths(ctx, input, old, newID, false)
		if err != nil {
			return nil, err
		}
	}
	entries := make([]ExecutionInput, 0, len(actions))
	for _, action := range actions {
		entries = append(entries, ExecutionInput{EvaluateInput: EvaluateInput{Actor: input.Actor, Repo: input.Repo, Credential: input.Credential, Action: action, ConditionContext: authz.ConditionContext{Source: input.Source, Branch: input.Ref.BranchName(), BranchKnown: true, Paths: paths, PathsComplete: complete}}, Intent: gitExecutionIntent(input)})
	}
	return entries, nil
}

func gitChangedPaths(ctx context.Context, input GitExecutionInput, old, newID string, controlledOnly bool) ([]string, error) {
	command := gitcmd.NewCommand("diff", "--no-ext-diff", "--no-textconv", "--name-only", "--no-renames", "-z").AddDynamicArguments(old, newID).AddArguments("--")
	if controlledOnly {
		command.AddArguments("CODEOWNERS", "docs/CODEOWNERS", ".gitea/CODEOWNERS")
	}
	buffer := new(diffPathBuffer)
	if err := command.WithRepo(input.GitRepo).WithEnv(input.Env).WithStdoutCopy(buffer).RunWithStderr(ctx); err != nil {
		if limit, ok := errors.AsType[*ExecutionError](err); ok {
			return nil, limit
		}
		return nil, &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	}
	output := buffer.String()
	if output == "" {
		return nil, nil
	}
	if !strings.HasSuffix(output, "\x00") {
		return nil, &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	}
	paths := strings.Split(strings.TrimSuffix(output, "\x00"), "\x00")
	if len(paths) > authz.MaxContextPaths {
		return nil, &ExecutionError{Reason: "context_limit_exceeded", Status: http.StatusForbidden}
	}
	slices.Sort(paths)
	return slices.Compact(paths), nil
}

func gitNeedsPathContext(ctx context.Context, input GitExecutionInput, actions []authz.Action) (bool, error) {
	if input.Credential.NativeOnly {
		return false, nil
	}
	actor, err := user_model.GetUserByID(ctx, input.Actor.ID)
	if err != nil {
		if user_model.IsErrUserNotExist(err) {
			return false, &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
		}
		return false, &ExecutionError{Reason: "policy_read_failed", Status: http.StatusServiceUnavailable}
	}
	actor.ExtDoerData = input.Actor.ExtDoerData
	if actor.IsAdmin {
		trusted, err := access_model.HasSystemManagementAuthority(ctx, actor)
		if err != nil {
			return false, &ExecutionError{Reason: "policy_read_failed", Status: http.StatusServiceUnavailable}
		}
		actor.IsAdmin = trusted
	}
	repo, err := repo_model.GetRepositoryByID(ctx, input.Repo.ID)
	if err != nil {
		if repo_model.IsErrRepoNotExist(err) {
			return false, &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
		}
		return false, &ExecutionError{Reason: "policy_read_failed", Status: http.StatusServiceUnavailable}
	}
	permission, err := access_model.GetDoerRepoPermission(ctx, repo, actor)
	if err != nil {
		return false, &ExecutionError{Reason: "policy_read_failed", Status: http.StatusServiceUnavailable}
	}
	native := NativeActions(repo, &permission, input.Credential)
	required := slices.DeleteFunc(slices.Clone(actions), func(action authz.Action) bool { return slices.Contains(native, action) })
	if len(required) == 0 || input.Credential.NativeOnly || !roleEligible(actor) {
		return false, nil
	}
	_, roles, err := resolveRoles(ctx, actor, repo)
	if err != nil {
		return false, errors.New("policy_read_failed")
	}
	roleIDs := make([]int64, 0, len(roles))
	for id := range roles {
		roleIDs = append(roleIDs, id)
	}
	if len(roleIDs) == 0 {
		return false, nil
	}
	var permissions []authz_model.RolePermission
	if err := db.GetEngine(ctx).In("role_id", roleIDs).In("action", required).Find(&permissions); err != nil {
		return false, errors.New("policy_read_failed")
	}
	for _, permission := range permissions {
		condition, _, hash, err := authz.ParseCondition([]byte(permission.ConditionJSON))
		if err != nil || hash != permission.ConditionHash {
			return false, errors.New("policy_read_failed")
		}
		if len(condition.PathPattern) > 0 {
			return true, nil
		}
	}
	return false, nil
}
