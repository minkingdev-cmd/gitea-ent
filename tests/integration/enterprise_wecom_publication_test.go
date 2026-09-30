// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package integration

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/timeutil"
	wecom_service "gitea.dev/services/enterprisewecom"
	repo_service "gitea.dev/services/repository"
	"gitea.dev/tests"

	"github.com/stretchr/testify/require"
)

type governancePublicationClient struct {
	entered chan struct{}
	release chan struct{}
	empty   bool
}

func (c governancePublicationClient) ListDepartments(ctx context.Context) ([]wecom_service.DepartmentInfo, error) {
	if db.InTransaction(ctx) {
		return nil, errors.New("provider called in transaction")
	}
	if c.entered != nil {
		close(c.entered)
		select {
		case <-c.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if c.empty {
		return []wecom_service.DepartmentInfo{}, nil
	}
	return []wecom_service.DepartmentInfo{{ID: 42, Name: "Portable", LeaderUserIDs: []string{"leader"}}}, nil
}

func (c governancePublicationClient) ListMembers(context.Context, int64) ([]wecom_service.MemberInfo, error) {
	return []wecom_service.MemberInfo{{UserID: "leader"}, {UserID: "member"}}, nil
}

func (c governancePublicationClient) ListTags(context.Context) ([]wecom_service.TagInfo, error) {
	return nil, nil
}

func (c governancePublicationClient) ListTagMembers(context.Context, int64) ([]string, error) {
	return nil, nil
}

func (c governancePublicationClient) ListAppAdmins(ctx context.Context) ([]wecom_service.AppAdminInfo, error) {
	if db.InTransaction(ctx) {
		return nil, errors.New("provider called in transaction")
	}
	if c.empty {
		return []wecom_service.AppAdminInfo{}, nil
	}
	return []wecom_service.AppAdminInfo{{UserID: "leader", AuthType: 1}}, nil
}

func TestEnterpriseWeComPublicationCoordinationPortable(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "portable", AgentID: "1000002", ManagedOrgID: 3, SyncDepartments: true})()
	for _, bind := range []struct {
		userID   int64
		external string
	}{{1, "leader"}, {2, "member"}} {
		_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: bind.userID, CorpID: "portable", WeComUserID: bind.external, Status: wecom_model.IdentityStatusActive})
		require.NoError(t, err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := wecom_service.RunAutomationPipeline(t.Context(), governancePublicationClient{entered: entered, release: release}, wecom_service.AutomationRunOptions{RunID: "portable-running"})
		done <- err
	}()
	<-entered
	_, err := wecom_service.RefreshAdminAuthoritySnapshot(t.Context(), governancePublicationClient{}, wecom_service.AdminAuthorityRefreshOptions{RunID: "portable-busy", Trigger: "login"})
	require.ErrorContains(t, err, "writer_busy")
	close(release)
	require.NoError(t, <-done)
	coordinator := unittest.AssertExistsAndLoadBean(t, &wecom_model.GovernanceCoordinator{CorpID: "portable", AgentID: "1000002"})
	require.EqualValues(t, 1, coordinator.PublishedRevision)
	generated := unittest.AssertExistsAndLoadBean(t, &wecom_model.GeneratedTeam{CorpID: "portable", AgentID: "1000002"})
	member, err := organization.IsTeamMember(t.Context(), 3, generated.TeamID, 2)
	require.NoError(t, err)
	require.True(t, member)
	staleEntered, staleRelease := make(chan struct{}), make(chan struct{})
	go func() {
		_, err := wecom_service.RunAutomationPipeline(t.Context(), governancePublicationClient{entered: staleEntered, release: staleRelease, empty: true}, wecom_service.AutomationRunOptions{RunID: "portable-stale"})
		done <- err
	}()
	<-staleEntered
	_, err = db.GetEngine(t.Context()).ID(coordinator.ID).Cols("fencing_generation", "lease_owner", "lease_until_unix").Update(&wecom_model.GovernanceCoordinator{FencingGeneration: coordinator.FencingGeneration + 2, LeaseOwner: "takeover", LeaseUntilUnix: 0})
	require.NoError(t, err)
	close(staleRelease)
	require.ErrorContains(t, <-done, "stale_candidate")
	member, err = organization.IsTeamMember(t.Context(), 3, generated.TeamID, 2)
	require.NoError(t, err)
	require.True(t, member)
	storedCoordinator := unittest.AssertExistsAndLoadBean(t, &wecom_model.GovernanceCoordinator{ID: coordinator.ID})
	require.EqualValues(t, 1, storedCoordinator.PublishedRevision)
	require.Equal(t, "takeover", storedCoordinator.LeaseOwner)
	staleRun := unittest.AssertExistsAndLoadBean(t, &wecom_model.ReconcileRun{RunID: "portable-stale"})
	require.Equal(t, wecom_model.ReconcileRunStatusFailed, staleRun.Status)
	require.Zero(t, staleRun.AddedMemberships)
	require.Zero(t, staleRun.RemovedMemberships)
	require.NoError(t, db.Insert(t.Context(), &wecom_model.ReconcileRun{CorpID: "portable", AgentID: "1000002", RunID: "portable-interrupted", Status: wecom_model.ReconcileRunStatusRunning}))
	run, err := wecom_service.RunAutomationPipeline(t.Context(), governancePublicationClient{empty: true}, wecom_service.AutomationRunOptions{RunID: "portable-empty"})
	require.NoError(t, err)
	require.EqualValues(t, 2, run.PublishedRevision)
	recovered := unittest.AssertExistsAndLoadBean(t, &wecom_model.ReconcileRun{RunID: "portable-interrupted"})
	require.Equal(t, wecom_model.ReconcileRunStatusFailed, recovered.Status)
	require.Equal(t, "interrupted", recovered.Reason)

	member, err = organization.IsTeamMember(t.Context(), 3, generated.TeamID, 2)
	require.NoError(t, err)
	require.False(t, member)
	authority := unittest.AssertExistsAndLoadBean(t, &wecom_model.AdminAuthority{CorpID: "portable", AgentID: "1000002", WeComUserID: "leader"})
	require.False(t, authority.IsActive)
}

func TestEnterpriseWeComPublicationLeaseRenewalPostgreSQL(t *testing.T) {
	if os.Getenv("GITEA_TEST_GOVERNANCE_LEASE_RENEWAL") != "1" || !setting.Database.Type.IsPostgreSQL() {
		t.Skip("真实 30 秒续租演练仅在显式开启的 PostgreSQL 验收中运行")
	}
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "renewal", AgentID: "1000002", ManagedOrgID: 3, SyncDepartments: true})()
	ctx, cancel := context.WithTimeout(t.Context(), 45*time.Second)
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		_, err := wecom_service.RunAutomationPipeline(ctx, governancePublicationClient{entered: entered, release: release, empty: true}, wecom_service.AutomationRunOptions{RunID: "renewal-running"})
		done <- err
	}()
	defer func() {
		cancel()
		<-finished
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("候选抓取未进入")
	}
	initial := unittest.AssertExistsAndLoadBean(t, &wecom_model.GovernanceCoordinator{CorpID: "renewal", AgentID: "1000002"})
	require.Eventually(t, func() bool {
		row := &wecom_model.GovernanceCoordinator{ID: initial.ID}
		has, err := db.GetEngine(ctx).Get(row)
		return err == nil && has && row.LeaseOwner == initial.LeaseOwner && row.FencingGeneration == initial.FencingGeneration && row.LeaseUntilUnix > initial.LeaseUntilUnix
	}, 40*time.Second, 100*time.Millisecond)
	_, err := wecom_service.RefreshAdminAuthoritySnapshot(ctx, governancePublicationClient{}, wecom_service.AdminAuthorityRefreshOptions{RunID: "renewal-busy", Trigger: "login"})
	require.ErrorContains(t, err, "writer_busy")
	close(release)
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("续租后的发布未完成")
	}
	stored := unittest.AssertExistsAndLoadBean(t, &wecom_model.GovernanceCoordinator{ID: initial.ID})
	require.EqualValues(t, 1, stored.PublishedRevision)
	require.Empty(t, stored.LeaseOwner)
	require.Zero(t, stored.LeaseUntilUnix)
}

func TestEnterpriseWeComRepositoryQuotaCoordinationPortable(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
	count, err := repo_model.CountRepositories(t.Context(), repo_model.CountRepositoryOptions{OwnerID: owner.ID})
	require.NoError(t, err)
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, PersonalRepoQuota: int(count) + 1})()
	start, results := make(chan struct{}), make(chan error, 2)
	for _, name := range []string{"portable-quota-one", "portable-quota-two"} {
		go func() {
			<-start
			_, err := repo_service.CreateRepository(t.Context(), owner, owner, repo_service.CreateRepoOptions{Name: name})
			results <- err
		}()
	}
	close(start)
	success, denied := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			success++
		} else {
			require.ErrorIs(t, err, repo_service.ErrEnterprisePersonalRepoQuotaExceeded)
			denied++
		}
	}
	require.Equal(t, 1, success)
	require.Equal(t, 1, denied)
	after, err := repo_model.CountRepositories(t.Context(), repo_model.CountRepositoryOptions{OwnerID: owner.ID})
	require.NoError(t, err)
	require.Equal(t, count+1, after)
}

func TestEnterpriseWeComCallbackReceiptCoordinationPortable(t *testing.T) {
	defer tests.PrepareTestEnv(t)()
	now := timeutil.TimeStampNow()
	var wg sync.WaitGroup
	ids := make(chan int64, 8)
	errs := make(chan error, 8)
	for range 8 {
		wg.Go(func() {
			receipt, _, err := wecom_model.AcceptCallbackReceipt(t.Context(), &wecom_model.CallbackReceipt{CorpID: "portable", AgentID: "1000002", Event: wecom_service.WeComChangeAppAdminEvent, DedupKey: "portable-event"}, now)
			if err != nil {
				errs <- err
				return
			}
			ids <- receipt.ID
		})
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	var id int64
	for received := range ids {
		if id == 0 {
			id = received
		}
		require.Equal(t, id, received)
	}
	require.NotZero(t, id)
	var mu sync.Mutex
	claimedCount := 0
	for range 8 {
		wg.Go(func() {
			receipt, err := wecom_model.ClaimCallbackReceiptForScope(t.Context(), "portable", "1000002", id, "portable-claim", now, 90)
			require.NoError(t, err)
			if receipt != nil {
				mu.Lock()
				claimedCount++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	require.Equal(t, 1, claimedCount)
	receipt, err := wecom_model.ClaimCallbackReceiptForScope(t.Context(), "portable", "other", id, "other-claim", now+91, 90)
	require.NoError(t, err)
	require.Nil(t, receipt)
	receipt, err = wecom_model.ClaimCallbackReceiptForScope(t.Context(), "portable", "1000002", id, "replacement-claim", now+91, 90)
	require.NoError(t, err)
	require.NotNil(t, receipt)
	require.Equal(t, 2, receipt.Attempts)
	require.ErrorIs(t, wecom_model.FinishCallbackReceipt(t.Context(), id, "portable-claim", wecom_model.CallbackReceiptSuccess, "", now+92, 0), wecom_model.ErrCallbackClaimLost)
	require.NoError(t, wecom_model.FinishCallbackReceipt(t.Context(), id, "replacement-claim", wecom_model.CallbackReceiptSuccess, "", now+92, 0))
}

func TestEnterpriseWeComPublicationCommitFailurePostgreSQL(t *testing.T) {
	if !setting.Database.Type.IsPostgreSQL() {
		t.Skip("最终 commit 故障使用 PostgreSQL deferred constraint trigger")
	}
	defer tests.PrepareTestEnv(t)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "portable", AgentID: "1000002", ManagedOrgID: 3, SyncDepartments: true})()
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 1, CorpID: "portable", WeComUserID: "leader", Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	_, err = wecom_service.RunAutomationPipeline(t.Context(), governancePublicationClient{}, wecom_service.AutomationRunOptions{RunID: "portable-commit-baseline"})
	require.NoError(t, err)
	snapshot := func() map[string][]map[string][]byte {
		state := make(map[string][]map[string][]byte)
		for _, table := range []string{"wecom_department", "wecom_tag", "wecom_membership", "wecom_identity", "wecom_admin_authority", "enterprise_wecom_authz_mapping", "enterprise_wecom_generated_mapping", "enterprise_wecom_generated_team", "enterprise_wecom_generated_team_admin", "enterprise_wecom_managed_membership", "user", "team", "team_unit", "team_user", "team_repo", "org_user", "access", "collaboration", "repository", "public_key", "access_token"} {
			rows, err := db.GetEngine(t.Context()).Query(fmt.Sprintf(`SELECT * FROM "%s" ORDER BY id`, table))
			require.NoError(t, err)
			state[table] = rows
		}
		return state
	}
	before := snapshot()
	coordinator := unittest.AssertExistsAndLoadBean(t, &wecom_model.GovernanceCoordinator{CorpID: "portable", AgentID: "1000002"})
	_, err = db.GetEngine(t.Context()).Exec(`CREATE FUNCTION wecom_governance_commit_fault() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'private-token suite-token oauth-code user@example.org'; END; $$`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.GetEngine(context.WithoutCancel(t.Context())).Exec(`DROP FUNCTION wecom_governance_commit_fault() CASCADE`)
		require.NoError(t, err)
	})
	_, err = db.GetEngine(t.Context()).Exec(`CREATE CONSTRAINT TRIGGER wecom_governance_commit_fault AFTER UPDATE ON enterprise_wecom_reconcile_run DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.status = 'success' AND NEW.run_id = 'portable-commit-failure') EXECUTE FUNCTION wecom_governance_commit_fault()`)
	require.NoError(t, err)
	run, err := wecom_service.RunAutomationPipeline(t.Context(), governancePublicationClient{empty: true}, wecom_service.AutomationRunOptions{RunID: "portable-commit-failure"})
	require.Error(t, err)
	require.NotContains(t, err.Error(), "private-token")
	require.NotContains(t, err.Error(), "user@example.org")
	require.Equal(t, before, snapshot())
	require.Equal(t, wecom_model.ReconcileRunStatusFailed, run.Status)
	for _, count := range []int{run.GeneratedTeams, run.GeneratedMappings, run.AddedMemberships, run.RemovedMemberships, run.AddedTeamAdmins, run.ProtectedCount} {
		require.Zero(t, count)
	}
	storedCoordinator := unittest.AssertExistsAndLoadBean(t, &wecom_model.GovernanceCoordinator{ID: coordinator.ID})
	require.Equal(t, coordinator.PublishedRevision, storedCoordinator.PublishedRevision)
	storedRun := unittest.AssertExistsAndLoadBean(t, &wecom_model.ReconcileRun{RunID: "portable-commit-failure"})
	require.Equal(t, wecom_model.ReconcileRunStatusFailed, storedRun.Status)
	require.Zero(t, storedRun.PublishedRevision)
}
