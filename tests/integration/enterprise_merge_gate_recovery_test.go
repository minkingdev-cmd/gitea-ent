// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	issues_model "gitea.dev/models/issues"
	repo_model "gitea.dev/models/repo"
	system_model "gitea.dev/models/system"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/cache"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/graceful"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/setting/config"
	"gitea.dev/modules/storage"
	"gitea.dev/modules/system"
	"gitea.dev/modules/test"
	"gitea.dev/modules/testlogger"
	"gitea.dev/modules/translation"
	"gitea.dev/modules/web"
	"gitea.dev/routers/common"
	"gitea.dev/routers/private"
	authz_service "gitea.dev/services/enterpriseauthz"
	pull_service "gitea.dev/services/pull"
	repo_service "gitea.dev/services/repository"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

func mergeGateProcessMain(m *testing.M) int {
	testlogger.Init()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	graceful.InitManager(ctx)
	setting.SetupGiteaTestEnv()
	setting.LoadSettings()
	setting.LoadDBSetting()
	for _, init := range []func() error{git.InitFull, cache.Init, storage.Init, func() error { return db.InitEngine(ctx) }, system.Init} {
		if err := init(); err != nil {
			return testlogger.MainErrorf("merge gate subprocess initialization: %v", err)
		}
	}
	defer db.UnsetDefaultEngine()
	config.SetDynGetter(system_model.NewDatabaseDynKeyGetter())
	return m.Run()
}

type mergeGateProcessCrash struct{}

func (*mergeGateProcessCrash) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if strings.HasPrefix(c.SQL, "INSERT INTO") && strings.Contains(c.SQL, "audit_event") {
		for _, arg := range c.Args {
			if fmt.Sprint(arg) == string(audit_model.EnterpriseMergeGateExecution) {
				os.Exit(86)
			}
		}
	}
	return c.Ctx, nil
}

func (*mergeGateProcessCrash) AfterProcess(*contexts.ContextHook) error { return nil }

func TestEnterpriseMergeGateRecoveryProcess(t *testing.T) {
	step := os.Getenv("GITEA_TEST_MERGE_GATE_PROCESS")
	if step == "" {
		t.Skip("isolated subprocess helper")
	}
	setting.EnterpriseAuthz = setting.EnterpriseAuthzConfig{Enabled: true, Enforce: true}
	setting.EnterpriseMergeGate = setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}
	setting.Audit.RecordOutput = setting.AuditRecordOutputDatabase
	switch step {
	case "merge":
		translation.InitLocales(t.Context())
		require.NoError(t, repo_service.Init(t.Context()))
		router := web.NewRouter()
		router.BeforeRouting(common.ProtocolMiddlewares()...)
		router.Mount("/api/internal", private.Routes())
		endpoint, err := url.Parse(setting.LocalURL)
		require.NoError(t, err)
		listener, err := net.Listen("tcp", endpoint.Host)
		require.NoError(t, err)
		server := &http.Server{Handler: router}
		go server.Serve(listener)
		t.Cleanup(func() { require.NoError(t, server.Close()) })
		pr, err := issues_model.GetPullRequestByID(t.Context(), 2)
		require.NoError(t, err)
		actor, err := user_model.GetUserByID(t.Context(), 2)
		require.NoError(t, err)
		require.NoError(t, pr.LoadBaseRepo(t.Context()))
		db.GetXORMEngineForTesting().AddHook(&mergeGateProcessCrash{})
		ctx, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
		err = pull_service.Merge(ctx, pr, actor, repo_model.MergeStyleMerge, "", "restart recovery", false)
		t.Fatalf("terminal crash boundary was not reached: %v", err)
	case "reconcile":
		require.NoError(t, pull_service.ReconcileMergeGateEvaluations(t.Context()))
	default:
		t.Fatalf("unknown subprocess step: %s", step)
	}
}

func TestEnterpriseMergeGateRestartAfterGitSuccess(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux server restart acceptance")
	}
	t.Cleanup(func() {
		require.NoError(t, unittest.InitFixtures(unittest.FixturesOptions{Dir: filepath.Join(setting.GetGiteaTestSourceRoot(), "models", "fixtures")})) // 子进程写入不触发父进程的 fixture dirty tracking。
	})
	func() {
		defer tests.PrepareTestEnv(t)()
		featureTestMode(t)
		setting.EnterpriseAuthz.Enforce = true
		t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
		pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
		require.NoError(t, pr.LoadBaseRepo(t.Context()))
		before, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
		require.NoError(t, err)
		binary, err := os.Executable()
		require.NoError(t, err)
		run := func(step string, code int) {
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "-test.run=^TestEnterpriseMergeGateRecoveryProcess$", "-test.v")
			cmd.Env = append(os.Environ(), "GITEA_TEST_MERGE_GATE_PROCESS="+step)
			output, err := cmd.CombinedOutput()
			t.Logf("subprocess %s: %s", step, output)
			require.NoError(t, ctx.Err(), string(output))
			if code == 0 {
				require.NoError(t, err, string(output))
			} else {
				var exited *exec.ExitError
				require.ErrorAs(t, err, &exited, string(output))
				require.Equal(t, code, exited.ExitCode(), string(output))
			}
		}
		run("merge", 86)
		current := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
		require.True(t, current.HasMerged)
		written, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
		require.NoError(t, err)
		require.NotEqual(t, before, written)
		record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID})
		require.Equal(t, "started", record.ExecutionState)
		require.Empty(t, record.MergedSHA)
		unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateExecution}, 0)
		_, err = db.GetEngine(t.Context()).ID(record.ID).Cols("started_unix").Update(&authz_model.MergeGateEvaluation{StartedUnix: 1}) // 跨过生产 10 分钟保护窗口，不等待墙钟。
		require.NoError(t, err)
		for range 2 {
			run("reconcile", 0)
			fresh := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{ID: record.ID})
			require.Equal(t, "succeeded", fresh.ExecutionState)
			require.Equal(t, current.MergedCommitID, fresh.MergedSHA)
			require.Equal(t, record.OperationID, fresh.OperationID)
			require.Equal(t, record.SnapshotJSON, fresh.SnapshotJSON)
			unittest.AssertCount(t, &authz_model.MergeGateEvaluation{PullID: pr.ID}, 1)
			unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateExecution}, 1)
			after, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
			require.NoError(t, err)
			require.Equal(t, written, after)
		}
	}()
}

type mergeGateRequestCancellation struct {
	enabled atomic.Bool
	request context.Context
	cancel  context.CancelFunc
	timeout bool
}

func (h *mergeGateRequestCancellation) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if strings.HasPrefix(c.SQL, "INSERT INTO") && strings.Contains(c.SQL, "audit_event") {
		for _, arg := range c.Args {
			if fmt.Sprint(arg) == string(audit_model.EnterpriseMergeGateMarker) && h.enabled.CompareAndSwap(true, false) {
				if h.timeout {
					<-h.request.Done()
				} else {
					h.cancel()
				}
			}
		}
	}
	return c.Ctx, nil
}

func (*mergeGateRequestCancellation) AfterProcess(*contexts.ContextHook) error { return nil }

func TestEnterpriseMergeGateRequestCancellationKeepsOutcome(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(strconv.FormatBool(timeout), func(t *testing.T) {
			onGiteaRun(t, func(t *testing.T, _ *url.URL) {
				featureTestMode(t)
				setting.EnterpriseAuthz.Enforce = true
				t.Cleanup(test.MockVariableValue(&setting.EnterpriseMergeGate, setting.EnterpriseMergeGateConfig{Enabled: true, Enforce: true}))
				pr := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: 2})
				actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
				require.NoError(t, pr.LoadBaseRepo(t.Context()))
				ctx, _ := authz_service.WithObservationContext(t.Context(), authz_service.EvaluateInput{Actor: actor, Repo: pr.BaseRepo, Action: authz.MergePullRequest, Credential: authz_service.CredentialCeiling{Read: true, Write: true}, ConditionContext: authz.ConditionContext{Source: "api", Branch: pr.BaseBranch, BranchKnown: true}})
				request, cancel := context.WithCancel(ctx)
				if timeout {
					cancel()
					request, cancel = context.WithTimeout(ctx, time.Second)
				}
				defer cancel()
				hook := &mergeGateRequestCancellation{request: request, cancel: cancel, timeout: timeout}
				hook.enabled.Store(true)
				t.Cleanup(func() { hook.enabled.Store(false) })
				db.GetXORMEngineForTesting().AddHook(hook)
				var terminal *authz_service.ExecutionError
				require.ErrorAs(t, pull_service.Merge(request, pr, actor, repo_model.MergeStyleMerge, "", "detached request completion", false), &terminal)
				require.Equal(t, "merge_gate_terminal_unknown", terminal.Reason)
				require.False(t, hook.enabled.Load(), "cancellation must happen after the real Git push")
				if timeout {
					require.ErrorIs(t, request.Err(), context.DeadlineExceeded)
				} else {
					require.ErrorIs(t, request.Err(), context.Canceled)
				}
				current := unittest.AssertExistsAndLoadBean(t, &issues_model.PullRequest{ID: pr.ID})
				require.True(t, current.HasMerged)
				record := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{PullID: pr.ID})
				require.Equal(t, "unknown", record.ExecutionState)
				require.Empty(t, record.MergedSHA)
				after, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
				require.NoError(t, err)
				require.Equal(t, current.MergedCommitID, after)
				_, err = db.GetEngine(t.Context()).ID(record.ID).Cols("started_unix").Update(&authz_model.MergeGateEvaluation{StartedUnix: 1})
				require.NoError(t, err)
				for range 2 {
					require.NoError(t, pull_service.ReconcileMergeGateEvaluations(t.Context()))
				}
				fresh := unittest.AssertExistsAndLoadBean(t, &authz_model.MergeGateEvaluation{ID: record.ID})
				require.Equal(t, "succeeded", fresh.ExecutionState)
				require.Equal(t, after, fresh.MergedSHA)
				require.Equal(t, record.SnapshotJSON, fresh.SnapshotJSON)
				require.Error(t, pull_service.Merge(ctx, pr, actor, repo_model.MergeStyleMerge, "", "must not repeat completed merge", false))
				afterRetry, err := git.GetFullCommitID(t.Context(), pr.BaseRepo, git.BranchPrefix+pr.BaseBranch)
				require.NoError(t, err)
				require.Equal(t, after, afterRetry)
				unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseMergeGateExecution}, 2)
			})
		})
	}
}
