// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package mirror

import (
	"context"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitcmd"
	"gitea.dev/modules/git/gitrepo"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/services/audit"
	repo_service "gitea.dev/services/repository"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	unittest.MainTest(m, &unittest.TestOptions{SetUp: func() error {
		if err := repo_service.InitLicenseClassifier(); err != nil {
			return err
		}
		return repo_service.Init(context.Background())
	}})
}

func preparePullMirrorMaintenance(t *testing.T) (*repo_model.Mirror, string) {
	t.Helper()
	unittest.PrepareTestEnv(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	m := unittest.AssertExistsAndLoadBean(t, &repo_model.Mirror{ID: 1})
	repo := m.GetRepository(t.Context())
	require.NotNil(t, repo)
	require.True(t, repo.IsMirror)
	repo.DefaultBranch = "master"
	require.NoError(t, repo_model.UpdateRepositoryColsNoAutoTime(t.Context(), repo, "default_branch"))
	source := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	sha, err := git.GetFullCommitID(t.Context(), source, git.BranchPrefix+source.DefaultBranch)
	require.NoError(t, err)
	ref := git.BranchPrefix + "maintenance-audit-probe"
	require.NoError(t, gitcmd.NewCommand("update-ref").AddDynamicArguments(ref, sha).WithRepo(source).RunWithStderr(t.Context()))
	require.NoError(t, gitcmd.NewCommand("config", "remote.origin.url").AddDynamicArguments(gitrepo.RepoLocalPath(source)).WithRepo(repo).RunWithStderr(t.Context()))
	require.NoError(t, gitcmd.NewCommand("config", "--replace-all", "remote.origin.fetch").AddDynamicArguments("+refs/*:refs/*").WithRepo(repo).RunWithStderr(t.Context()))
	require.False(t, git.IsReferenceExist(t.Context(), repo, ref))
	return m, ref
}

func TestPullMirrorMaintenanceRejectsBeforeFetch(t *testing.T) {
	for _, invalid := range []string{"audit-fault", "audit-disabled", "non-mirror", "unknown-caller", "nil-mirror", "stale-mirror", "replaced-mirror", "stale-owner", "transaction", "cancelled"} {
		t.Run(invalid, func(t *testing.T) {
			m, ref := preparePullMirrorMaintenance(t)
			before := *m
			ctx := t.Context()
			marker := &pullMirrorSyncMaintenance{mirrorID: m.ID, repoID: m.RepoID, ownerID: m.Repo.OwnerID}
			knownCtx := context.WithValue(ctx, pullMirrorSyncKey{}, marker)
			switch invalid {
			case "audit-fault":
				setting.EnterpriseAuthz.FailClosedOnError = false
				_, err := db.Exec(t.Context(), "ALTER TABLE audit_event RENAME TO mirror_audit_fault")
				require.NoError(t, err)
				t.Cleanup(func() {
					_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE mirror_audit_fault RENAME TO audit_event")
					require.NoError(t, err)
				})
			case "non-mirror":
				_, err := db.GetEngine(t.Context()).ID(m.RepoID).Cols("is_mirror").Update(&repo_model.Repository{IsMirror: false})
				require.NoError(t, err)
			case "audit-disabled":
				setting.Audit.RecordOutput = setting.AuditRecordOutputDisabled
			case "stale-mirror":
				marker.mirrorID++
			case "replaced-mirror":
				_, err := db.Exec(ctx, "UPDATE mirror SET id = 1000 WHERE id = ?", m.ID)
				require.NoError(t, err)
			case "stale-owner":
				_, err := db.GetEngine(ctx).ID(m.RepoID).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 2})
				require.NoError(t, err)
			case "cancelled":
				cancelCtx, cancel := context.WithCancel(knownCtx)
				cancel()
				knownCtx = cancelCtx
			}
			ok := false
			switch invalid {
			case "unknown-caller":
				_, ok = runSync(audit.WithOrigin(t.Context(), audit_model.OriginSystem), m)
			case "nil-mirror":
				_, ok = runSync(knownCtx, nil)
			case "stale-mirror", "replaced-mirror", "stale-owner", "cancelled":
				_, ok = runSync(knownCtx, m)
			case "transaction":
				require.NoError(t, db.WithTx(knownCtx, func(tx context.Context) error {
					_, ok = runSync(tx, m)
					return nil
				}))
			default:
				ok = SyncPullMirror(t.Context(), m.RepoID)
			}
			assert.False(t, ok)
			require.False(t, git.IsReferenceExist(t.Context(), m.Repo, ref))
			current := unittest.AssertExistsAndLoadBean(t, &repo_model.Mirror{RepoID: m.RepoID})
			require.Equal(t, before.UpdatedUnix, current.UpdatedUnix)
			require.Equal(t, before.LastSyncUnix, current.LastSyncUnix)
			require.Equal(t, before.NextUpdateUnix, current.NextUpdateUnix)
		})
	}
}

func TestPullMirrorMaintenanceRecordsSystemBeforeFetch(t *testing.T) {
	m, ref := preparePullMirrorMaintenance(t)
	require.True(t, SyncPullMirror(t.Context(), m.RepoID))
	require.True(t, git.IsReferenceExist(t.Context(), m.Repo, ref))
	row := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.RepositoryMirrorSync, ScopeID: m.RepoID, Origin: audit_model.OriginSystem})
	require.Equal(t, int64(0), row.ActorID)
	require.Equal(t, "mirror-pull-sync", row.ActorName)
	require.Contains(t, row.Metadata, "mirror-pull-sync")
	require.NotContains(t, row.Metadata, gitrepo.RepoLocalPath(m.Repo))
	require.Contains(t, row.Message, "Started pull mirror synchronization")
	require.True(t, audit_model.IsActionFilter(audit_model.RepositoryMirrorSync))
}

func TestPullMirrorMaintenanceKeepsShadowAndDisabled(t *testing.T) {
	for _, mode := range []string{"shadow", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			m, ref := preparePullMirrorMaintenance(t)
			setting.EnterpriseAuthz.Enforce = false
			setting.EnterpriseAuthz.Enabled = mode == "shadow"
			setting.Audit.RecordOutput = setting.AuditRecordOutputDisabled
			require.True(t, SyncPullMirror(t.Context(), m.RepoID))
			require.True(t, git.IsReferenceExist(t.Context(), m.Repo, ref))
			unittest.AssertNotExistsBean(t, &audit_model.Event{Action: audit_model.RepositoryMirrorSync})
		})
	}
}

func TestPullMirrorMaintenanceReloadsOptionsAndIsOneShot(t *testing.T) {
	m, _ := preparePullMirrorMaintenance(t)
	marker := &pullMirrorSyncMaintenance{mirrorID: m.ID, repoID: m.RepoID, ownerID: m.Repo.OwnerID}
	ctx := context.WithValue(t.Context(), pullMirrorSyncKey{}, marker)
	m.LFS, m.LFSEndpoint, m.EnablePrune = true, "https://stale.invalid/secret", true
	require.NoError(t, requirePullMirrorSyncMaintenance(ctx, m))
	require.True(t, marker.admitted)
	require.False(t, m.LFS)
	require.Empty(t, m.LFSEndpoint)
	require.False(t, m.EnablePrune)
	require.Error(t, requirePullMirrorSyncMaintenance(ctx, m))
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.RepositoryMirrorSync}, 1)
}
