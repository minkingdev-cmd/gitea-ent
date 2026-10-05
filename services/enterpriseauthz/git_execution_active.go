// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"sync"

	packages_model "gitea.dev/models/packages"
	repo_model "gitea.dev/models/repo"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/setting"
)

type activeGitExecution struct {
	admission           *Admission
	keys                [][32]byte
	claimed             map[[32]byte]bool
	postClaimed         map[[32]byte]bool
	cargoCleanupOwnerID int64
	cleanupClaimed      map[[32]byte]bool
}

var activeGitExecutions = struct {
	sync.Mutex
	operations map[string][]*activeGitExecution
}{operations: make(map[string][]*activeGitExecution)}

func gitPreparedKey(input GitExecutionInput) [32]byte {
	return executionKey(ExecutionInput{EvaluateInput: EvaluateInput{Actor: input.Actor, Repo: input.Repo, Credential: input.Credential, Action: authz.PushBranch, ConditionContext: authz.ConditionContext{Source: input.Source}}, Intent: gitExecutionIntent(input)})
}

func RegisterGitExecution(ctx context.Context, admission *Admission, inputs []GitExecutionInput) (func(), error) {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return func() {}, nil
	}
	invalid := &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	if admission == nil || ctx.Value(admissionKey{}) != admission || len(inputs) == 0 {
		return func() {}, invalid
	}
	admission.mutex.Lock()
	if !admission.started || admission.finished {
		admission.mutex.Unlock()
		return func() {}, invalid
	}
	entry := &activeGitExecution{admission: admission, claimed: make(map[[32]byte]bool), postClaimed: make(map[[32]byte]bool), cleanupClaimed: make(map[[32]byte]bool)}
	for _, input := range inputs {
		if input.Actor == nil || input.Repo == nil {
			admission.mutex.Unlock()
			return func() {}, invalid
		}
		if input.Repo.InternalUsage == repo_model.InternalUsageCargoIndex && packages_model.CleanupIndexReadAllowed(ctx, input.Repo.OwnerID, packages_model.TypeCargo) {
			if entry.cargoCleanupOwnerID != 0 && entry.cargoCleanupOwnerID != input.Repo.OwnerID {
				admission.mutex.Unlock()
				return func() {}, invalid
			}
			entry.cargoCleanupOwnerID = input.Repo.OwnerID
		}
		key := gitPreparedKey(input)
		if !slices.Contains(admission.preparedKeys, key) || slices.Contains(entry.keys, key) {
			admission.mutex.Unlock()
			return func() {}, invalid
		}
		entry.keys = append(entry.keys, key)
	}
	operationID := admission.operationID
	admission.mutex.Unlock()
	activeGitExecutions.Lock()
	activeGitExecutions.operations[operationID] = append(activeGitExecutions.operations[operationID], entry)
	activeGitExecutions.Unlock()
	return sync.OnceFunc(func() {
		activeGitExecutions.Lock()
		defer activeGitExecutions.Unlock()
		entries := slices.DeleteFunc(activeGitExecutions.operations[operationID], func(other *activeGitExecution) bool { return other == entry })
		if len(entries) == 0 {
			delete(activeGitExecutions.operations, operationID)
		} else {
			activeGitExecutions.operations[operationID] = entries
		}
	}), nil
}

func ReuseActiveGitExecution(ctx context.Context, operation *HookOperation, inputs []GitExecutionInput) bool {
	if operation == nil || len(inputs) == 0 {
		return false
	}
	activeGitExecutions.Lock()
	defer activeGitExecutions.Unlock()
	for _, entry := range activeGitExecutions.operations[operation.payload.OperationID] {
		entry.admission.mutex.Lock()
		live := entry.admission.started && !entry.admission.finished
		entry.admission.mutex.Unlock()
		if !live {
			continue
		}
		keys := make([][32]byte, 0, len(inputs))
		for _, input := range inputs {
			if input.Actor == nil || input.Repo == nil || !validHookInput(operation, EvaluateInput{Actor: input.Actor, Repo: input.Repo, Credential: input.Credential, ConditionContext: authz.ConditionContext{Source: input.Source}}) {
				break
			}
			input.Merge = false
			key := gitPreparedKey(input)
			if !slices.Contains(entry.keys, key) {
				input.Merge = true
				key = gitPreparedKey(input)
			}
			if !slices.Contains(entry.keys, key) || entry.claimed[key] || slices.Contains(keys, key) {
				break
			}
			keys = append(keys, key)
		}
		if len(keys) == len(inputs) {
			for _, key := range keys {
				entry.claimed[key] = true
			}
			return true
		}
	}
	return false
}

func AttachActiveGitExecution(ctx context.Context, operation *HookOperation, inputs []GitExecutionInput) (context.Context, bool) {
	if operation == nil || len(inputs) == 0 {
		return ctx, false
	}
	for _, input := range inputs {
		if input.Actor == nil || input.Repo == nil || input.GitRepo == nil || !input.Ref.IsBranch() || !validHookInput(operation, EvaluateInput{Actor: input.Actor, Repo: input.Repo, Credential: input.Credential, ConditionContext: authz.ConditionContext{Source: input.Source}}) {
			return ctx, false
		}
		actual, err := git.GetBranchCommitID(ctx, input.GitRepo, input.Ref.BranchName())
		if err != nil || actual != input.NewCommitID {
			return ctx, false
		}
	}
	activeGitExecutions.Lock()
	defer activeGitExecutions.Unlock()
	for _, entry := range activeGitExecutions.operations[operation.payload.OperationID] {
		entry.admission.mutex.Lock()
		live := entry.admission.started && !entry.admission.finished
		entry.admission.mutex.Unlock()
		if !live {
			continue
		}
		keys := make([][32]byte, 0, len(inputs))
		for _, input := range inputs {
			input.Merge = false
			key := gitPreparedKey(input)
			if !slices.Contains(entry.keys, key) {
				input.Merge = true
				key = gitPreparedKey(input)
			}
			if !slices.Contains(entry.keys, key) || !entry.claimed[key] || entry.postClaimed[key] || slices.Contains(keys, key) {
				break
			}
			keys = append(keys, key)
		}
		if len(keys) == len(inputs) {
			for _, key := range keys {
				entry.postClaimed[key] = true
			}
			return context.WithValue(ctx, admissionKey{}, entry.admission), true
		}
	}
	return ctx, false
}

func RequireGitMergeExecution(ctx context.Context, actor, repoID int64, branch, newCommit string) error {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return nil
	}
	invalid := &ExecutionError{Reason: "invalid_execution_context", Status: http.StatusForbidden}
	a, ok := ctx.Value(admissionKey{}).(*Admission)
	if !ok || a == nil {
		return invalid
	}
	a.mutex.Lock()
	defer a.mutex.Unlock()
	if !a.started || a.finished || branch == "" || newCommit == "" {
		return invalid
	}
	for _, input := range a.inputs {
		if actor == actorID(input.EvaluateInput) && repoID == input.Repo.ID && input.Action == authz.MergePullRequest && input.ConditionContext.BranchKnown && input.ConditionContext.Branch == branch && strings.HasSuffix(input.Intent, ":"+newCommit) {
			return nil
		}
	}
	if a.fallback {
		prefix := "git:merge:" + hookBranchHash(branch) + ":"
		for _, input := range a.preparedInputs {
			if actor == actorID(input.EvaluateInput) && repoID == input.Repo.ID && input.resolve != nil && strings.HasPrefix(input.Intent, prefix) && strings.HasSuffix(input.Intent, ":"+newCommit) {
				return nil
			}
		}
	}
	return invalid
}

func ReuseCargoIndexCleanupExecution(_ context.Context, operation *HookOperation, inputs []GitExecutionInput) bool {
	if operation == nil || len(inputs) != 1 {
		return false
	}
	input := inputs[0]
	if input.Actor == nil || input.Repo == nil || input.Repo.InternalUsage != repo_model.InternalUsageCargoIndex || !input.Ref.IsBranch() || input.Merge || !validHookInput(operation, EvaluateInput{Actor: input.Actor, Repo: input.Repo, Credential: input.Credential, ConditionContext: authz.ConditionContext{Source: input.Source}}) {
		return false
	}
	key := gitPreparedKey(input)
	activeGitExecutions.Lock()
	defer activeGitExecutions.Unlock()
	for _, entry := range activeGitExecutions.operations[operation.payload.OperationID] {
		entry.admission.mutex.Lock()
		live := entry.admission.started && !entry.admission.finished
		entry.admission.mutex.Unlock()
		if live && entry.cargoCleanupOwnerID == input.Repo.OwnerID && entry.cargoCleanupOwnerID > 0 && slices.Contains(entry.keys, key) && !entry.cleanupClaimed[key] {
			entry.cleanupClaimed[key] = true
			return true
		}
	}
	return false
}
