// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
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
	"gitea.dev/services/migrations"
	mirror_service "gitea.dev/services/mirror"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzMirrorMaintenance(t *testing.T) {
	for _, condition := range []string{"sync", "audit-fault", "audit-disabled", "non-mirror", "native-url", "shadow", "disabled"} {
		t.Run(condition, func(t *testing.T) {
			defer tests.PrepareTestEnv(t)()
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
			t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
			setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, false
			m := unittest.AssertExistsAndLoadBean(t, &repo_model.Mirror{ID: 1})
			target := m.GetRepository(t.Context())
			require.NotNil(t, target)
			source := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
			sha, err := git.GetFullCommitID(t.Context(), source, git.BranchPrefix+source.DefaultBranch)
			require.NoError(t, err)
			ref := git.BranchPrefix + "maintenance-audit-probe"
			require.NoError(t, gitcmd.NewCommand("update-ref").AddDynamicArguments(ref, sha).WithRepo(source).RunWithStderr(t.Context()))
			require.NoError(t, gitcmd.NewCommand("config", "remote.origin.url").AddDynamicArguments(gitrepo.RepoLocalPath(source)).WithRepo(target).RunWithStderr(t.Context()))
			require.NoError(t, gitcmd.NewCommand("config", "--replace-all", "remote.origin.fetch").AddDynamicArguments("+refs/*:refs/*").WithRepo(target).RunWithStderr(t.Context()))
			require.False(t, git.IsReferenceExist(t.Context(), target, ref))
			var reached atomic.Bool
			switch condition {
			case "audit-fault":
				_, err := db.Exec(t.Context(), "ALTER TABLE audit_event RENAME TO mirror_audit_fault")
				require.NoError(t, err)
				t.Cleanup(func() {
					_, err := db.Exec(context.WithoutCancel(t.Context()), "ALTER TABLE mirror_audit_fault RENAME TO audit_event")
					require.NoError(t, err)
				})
			case "audit-disabled":
				setting.Audit.RecordOutput = setting.AuditRecordOutputDisabled
			case "non-mirror":
				_, err := db.GetEngine(t.Context()).ID(target.ID).Cols("is_mirror").Update(&repo_model.Repository{IsMirror: false})
				require.NoError(t, err)
			case "native-url":
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					reached.Store(true)
					w.WriteHeader(http.StatusNotFound)
				}))
				t.Cleanup(server.Close)
				restoreNetworks := test.MockVariableValue(&setting.Migrations.AllowLocalNetworks, false)
				require.NoError(t, migrations.Init())
				t.Cleanup(func() {
					restoreNetworks()
					require.NoError(t, migrations.Init())
				})
				require.NoError(t, gitcmd.NewCommand("config", "remote.origin.url").AddDynamicArguments(server.URL+"/repo.git").WithRepo(target).RunWithStderr(t.Context()))
			case "shadow":
				setting.EnterpriseAuthz.Enforce = false
				setting.Audit.RecordOutput = setting.AuditRecordOutputDisabled
			case "disabled":
				setting.EnterpriseAuthz.Enabled = false
				setting.Audit.RecordOutput = setting.AuditRecordOutputDisabled
			}
			allowed := condition == "sync" || condition == "shadow" || condition == "disabled"
			require.Equal(t, allowed, mirror_service.SyncPullMirror(t.Context(), target.ID))
			require.Equal(t, allowed, git.IsReferenceExist(t.Context(), target, ref))
			require.False(t, reached.Load())
			current := unittest.AssertExistsAndLoadBean(t, &repo_model.Mirror{ID: m.ID})
			if !allowed && condition != "native-url" {
				require.Equal(t, m.UpdatedUnix, current.UpdatedUnix)
				require.Equal(t, m.LastSyncUnix, current.LastSyncUnix)
				require.Equal(t, m.NextUpdateUnix, current.NextUpdateUnix)
			}
			if condition == "sync" || condition == "native-url" {
				row := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.RepositoryMirrorSync, ScopeID: target.ID, Origin: audit_model.OriginSystem})
				require.Zero(t, row.ActorID)
				require.Equal(t, "mirror-pull-sync", row.ActorName)
				require.Contains(t, row.Metadata, "mirror-pull-sync")
				require.NotContains(t, row.Metadata, gitrepo.RepoLocalPath(source))
			}
		})
	}
}
