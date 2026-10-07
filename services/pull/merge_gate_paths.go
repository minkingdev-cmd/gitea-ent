// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"bytes"
	"context"
	"errors"
	"io"
	"slices"
	"strconv"
	"strings"

	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/git/gitrepo"
)

var errMergeGatePathsIncomplete = errors.New("merge_gate_paths_incomplete")

func collectMergeGatePaths(ctx context.Context, repo gitrepo.RepositoryFacade, mergeBaseSHA, headSHA string) ([]string, error) {
	if repo == nil || len(mergeBaseSHA) != len(headSHA) || !git.IsStringValidObjectID(nil, mergeBaseSHA) || !git.IsStringValidObjectID(nil, headSHA) || git.IsEmptyCommitID(mergeBaseSHA) || git.IsEmptyCommitID(headSHA) {
		return nil, errMergeGatePathsIncomplete
	}
	cmd := gitcmd.NewCommand("diff", "--no-ext-diff", "--no-textconv", "--ignore-submodules=none", "--name-status", "-z", "--find-renames", "--find-copies", "--find-copies-harder").
		AddDynamicArguments(mergeBaseSHA, headSHA).AddArguments("--").WithRepo(repo)
	stdout, closeStdout := cmd.MakeStdoutPipe()
	defer closeStdout()
	var paths []string
	err := cmd.WithPipelineFunc(func(ctx gitcmd.Context) error {
		const maxBytes = 4 * 1024 * 1024
		raw, err := io.ReadAll(io.LimitReader(stdout, maxBytes+1))
		if err != nil {
			return ctx.CancelPipeline(err)
		}
		if len(raw) > maxBytes {
			return ctx.CancelPipeline(errMergeGatePathsIncomplete)
		}
		paths, err = parseMergeGatePaths(raw)
		if err != nil {
			return ctx.CancelPipeline(err)
		}
		return nil
	}).RunWithStderr(ctx)
	if err != nil {
		return nil, err
	}
	return paths, nil
}

func parseMergeGatePaths(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return []string{}, nil
	}
	if raw[len(raw)-1] != 0 {
		return nil, errMergeGatePathsIncomplete
	}
	records := bytes.Split(raw[:len(raw)-1], []byte{0})
	paths := make(map[string]struct{})
	for i := 0; i < len(records); {
		status := string(records[i])
		i++
		count := 1
		if len(status) > 1 && (status[0] == 'R' || status[0] == 'C') {
			score, err := strconv.Atoi(status[1:])
			if err != nil || score < 0 || score > 100 || strings.ContainsAny(status[1:], "+-") {
				return nil, errMergeGatePathsIncomplete
			}
			count = 2
		} else if len(status) != 1 || !strings.ContainsAny(status, "AMDT") {
			return nil, errMergeGatePathsIncomplete
		}
		if len(records)-i < count {
			return nil, errMergeGatePathsIncomplete
		}
		for range count {
			path := string(records[i])
			i++
			if !authz.ValidMergeGatePath(path) {
				return nil, errMergeGatePathsIncomplete
			}
			paths[path] = struct{}{}
			if len(paths) > authz.MaxContextPaths {
				return nil, errMergeGatePathsIncomplete
			}
		}
	}
	result := make([]string, 0, len(paths))
	for path := range paths {
		result = append(result, path)
	}
	slices.Sort(result)
	return result, nil
}
