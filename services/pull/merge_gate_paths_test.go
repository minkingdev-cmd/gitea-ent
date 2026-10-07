// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/git/gitrepo"

	"github.com/stretchr/testify/require"
)

func TestMergeGatePathRecords(t *testing.T) {
	paths, err := parseMergeGatePaths([]byte("R100\x00sensitive/old\x00public/new\x00C100\x00sensitive/source\x00public/copy\x00D\x00deleted\x00A\x00.gitea/CODEOWNERS\x00M\x00public/new\x00"))
	require.NoError(t, err)
	require.Equal(t, []string{".gitea/CODEOWNERS", "deleted", "public/copy", "public/new", "sensitive/old", "sensitive/source"}, paths)
	for _, raw := range []string{
		"M\x00path", "R100\x00old\x00", "X\x00path\x00", "R101\x00old\x00new\x00", "Cbad\x00old\x00new\x00",
		"A\x00/absolute\x00", "M\x00a/../b\x00", "D\x00a//b\x00", "M\x00a\\b\x00", "M\x00bad\npath\x00", "M\x00\xff\x00",
	} {
		paths, err := parseMergeGatePaths([]byte(raw))
		require.Error(t, err, "%q", raw)
		require.Nil(t, paths)
	}
	var overflow strings.Builder
	for i := range authz.MaxContextPaths + 1 {
		fmt.Fprintf(&overflow, "A\x00file%d\x00", i)
	}
	paths, err = parseMergeGatePaths([]byte(overflow.String()))
	require.Error(t, err)
	require.Nil(t, paths)
}

func TestMergeGateTrustedGitPaths(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	require.NoError(t, git.InitRepositoryLocal(ctx, dir, false, "sha1"))
	repo := gitrepo.RepositoryUnmanaged(dir)
	commit := func(stage bool) string {
		t.Helper()
		if stage {
			require.NoError(t, gitcmd.NewCommand("add", "--all").WithRepo(repo).Run(ctx))
		}
		require.NoError(t, gitcmd.NewCommand("-c", "user.name=Gate test", "-c", "user.email=gate@example.invalid", "-c", "commit.gpgsign=false", "commit", "-m", "test").WithRepo(repo).Run(ctx))
		sha, _, err := gitcmd.NewCommand("rev-parse", "HEAD").WithRepo(repo).RunStdString(ctx)
		require.NoError(t, err)
		return strings.TrimSpace(sha)
	}
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "sensitive"), 0o755))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "public"), 0o755))
	for name, content := range map[string]string{"sensitive/old": "rename content\n", "sensitive/source": "copy content\n", "deleted": "deleted content\n"} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	base := commit(true)
	require.NoError(t, os.Rename(filepath.Join(dir, "sensitive/old"), filepath.Join(dir, "public/new")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "public/copy"), []byte("copy content\n"), 0o600))
	require.NoError(t, os.Remove(filepath.Join(dir, "deleted")))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "CODEOWNERS"), []byte(".* @reviewer\n"), 0o600))
	head := commit(true)
	paths, err := collectMergeGatePaths(ctx, repo, base, head)
	require.NoError(t, err)
	require.Equal(t, []string{"CODEOWNERS", "deleted", "public/copy", "public/new", "sensitive/old", "sensitive/source"}, paths)
	for _, invalid := range []string{"", "HEAD", "--stat", strings.Repeat("0", 40), strings.Repeat("a", 40)} {
		paths, err := collectMergeGatePaths(ctx, repo, base, invalid)
		require.Error(t, err)
		require.Nil(t, paths)
	}
	require.NoError(t, gitcmd.NewCommand("update-index", "--add", "--cacheinfo").AddDynamicArguments("160000,"+base+",sensitive-module").WithRepo(repo).Run(ctx))
	moduleBase := commit(false)
	require.NoError(t, gitcmd.NewCommand("update-index", "--cacheinfo").AddDynamicArguments("160000,"+head+",sensitive-module").WithRepo(repo).Run(ctx))
	moduleHead := commit(false)
	require.NoError(t, gitcmd.NewCommand("config", "diff.ignoreSubmodules", "all").WithRepo(repo).Run(ctx))
	paths, err = collectMergeGatePaths(ctx, repo, moduleBase, moduleHead)
	require.NoError(t, err)
	require.Equal(t, []string{"sensitive-module"}, paths)
	require.NoError(t, os.Mkdir(filepath.Join(dir, "bulk"), 0o755))
	for i := range authz.MaxContextPaths + 1 {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "bulk", fmt.Sprintf("file%d", i)), []byte("change\n"), 0o600))
	}
	overflowHead := commit(true)
	paths, err = collectMergeGatePaths(ctx, repo, moduleHead, overflowHead)
	require.Error(t, err, "a complete Git diff exceeding the path budget must not become a truncated allow")
	require.Nil(t, paths)
}
