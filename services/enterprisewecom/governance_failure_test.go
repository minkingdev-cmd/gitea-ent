// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestAutomationPublishDatabaseFailuresAtomic(t *testing.T) {
	cases := []struct{ name, stage, trigger string }{
		{"second_team_insert", "teams", `BEFORE INSERT ON team WHEN NEW.lower_name = 'dept-43-latesecond' AND EXISTS (SELECT 1 FROM team WHERE lower_name = 'dept-42-latefirst')`},
		{"member_insert", "memberships", `BEFORE INSERT ON team_user WHEN NEW.uid = 4`},
		{"member_delete", "memberships", `BEFORE DELETE ON team_user WHEN OLD.uid = 2`},
		{"admin_promotion", "authority", `BEFORE UPDATE OF is_admin ON "user" WHEN NEW.id = 4 AND NEW.is_admin = 1 AND OLD.is_admin = 0`},
		{"run_success_update", "evidence", `BEFORE UPDATE OF status ON enterprise_wecom_reconcile_run WHEN NEW.status = 'success'`},
		{"success_audit_insert", "evidence", `BEFORE INSERT ON audit_event WHEN NEW.action = 'enterprise:wecom:automation:finish' AND NEW.metadata LIKE '%"outcome":"success"%'`},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			fixture := seedGovernanceFailureBaseline(t)
			if !setting.Database.Type.IsSQLite3() {
				t.Skip("SQLite trigger 故障注入；跨数据库尚未验证")
			}
			before := snapshotGovernanceAuthorization(t)
			beforeAudit := latestGovernanceFailureAuditID(t)
			_, err := db.GetEngine(t.Context()).Exec("CREATE TRIGGER governance_fault " + tt.trigger + " BEGIN SELECT RAISE(ABORT, 'injected-late-database-failure'); END")
			require.NoError(t, err)
			t.Cleanup(func() {
				_, err := db.GetEngine(context.WithoutCancel(t.Context())).Exec("DROP TRIGGER IF EXISTS governance_fault")
				require.NoError(t, err)
			})
			run, err := RunAutomationPipeline(t.Context(), fixture.candidate, AutomationRunOptions{RunID: "fault-" + tt.name, OrgID: setting.EnterpriseWeCom.ManagedOrgID})
			assertGovernanceFailurePreserved(t, before, beforeAudit, run, err)
			require.Equal(t, tt.stage, run.Stage, "injection must reach the intended late stage")
		})
	}
}

type governanceFailureClient struct {
	fakeAutomationClient
	directoryError  error
	beforeAuthority func(context.Context)
	test            *testing.T
}

func (f governanceFailureClient) ListDepartments(ctx context.Context) ([]DepartmentInfo, error) {
	require.False(f.test, db.InTransaction(ctx), "provider directory fetch must not hold the publication transaction")
	if f.directoryError != nil {
		return nil, f.directoryError
	}
	return f.fakeAutomationClient.ListDepartments(ctx)
}

func (f governanceFailureClient) ListAppAdmins(ctx context.Context) ([]AppAdminInfo, error) {
	require.False(f.test, db.InTransaction(ctx), "provider authority fetch must not hold the publication transaction")
	if f.beforeAuthority != nil {
		f.beforeAuthority(ctx)
	}
	return f.fakeAutomationClient.ListAppAdmins(ctx)
}

type governanceFailureFixture struct{ candidate governanceFailureClient }

func seedGovernanceFailureBaseline(t *testing.T) governanceFailureFixture {
	t.Helper()
	require.NoError(t, unittest.PrepareTestDatabase())
	if !setting.Database.Type.IsSQLite3() {
		t.Skip("SQLite 故障矩阵与完整 SQL 快照；跨数据库尚未验证")
	}
	mockAutomationSettings(t)
	setting.EnterpriseWeCom.SyncTags = true
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	for _, row := range []struct {
		userID  int64
		wecomID string
	}{{1, "protected"}, {2, "oldmember"}, {4, "newadmin"}} {
		_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: row.userID, CorpID: "corp-auto", WeComUserID: row.wecomID, LoginSourceID: 1, Status: wecom_model.IdentityStatusActive})
		require.NoError(t, err)
	}
	baseline := governanceFailureClient{test: t, fakeAutomationClient: fakeAutomationClient{
		fakeDirectoryClient: fakeDirectoryClient{
			departments: []DepartmentInfo{{ID: 41, Name: "Baseline", LeaderUserIDs: []string{"protected"}}},
			members:     map[int64][]MemberInfo{41: {{UserID: "protected"}, {UserID: "oldmember"}}},
			tags:        []TagInfo{{ID: 88, Name: "Capability"}}, tagMembers: map[int64][]string{88: {"oldmember"}},
		}, admins: []AppAdminInfo{{UserID: "protected", AuthType: 1}},
	}}
	run, err := RunAutomationPipeline(t.Context(), baseline, AutomationRunOptions{RunID: "failure-baseline", OrgID: setting.EnterpriseWeCom.ManagedOrgID})
	require.NoError(t, err)
	require.Equal(t, wecom_model.ReconcileRunStatusSuccess, run.Status)
	require.Positive(t, run.GeneratedMappings)
	require.Positive(t, run.AddedMemberships)
	require.Positive(t, unittest.GetCount(t, new(wecom_model.GeneratedTeamAdmin)))
	require.Positive(t, unittest.GetCount(t, new(wecom_model.ManagedMembership)))
	protected, err := wecom_model.IsActiveManagementAuthorityBoundUser(t.Context(), "corp-auto", "1000002", 1)
	require.NoError(t, err)
	require.True(t, protected)
	require.False(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}).IsAdmin)
	candidate := governanceFailureClient{test: t, fakeAutomationClient: fakeAutomationClient{
		fakeDirectoryClient: fakeDirectoryClient{
			departments: []DepartmentInfo{{ID: 41, Name: "Changed", LeaderUserIDs: []string{"newadmin"}}, {ID: 42, Name: "LateFirst", LeaderUserIDs: []string{"newadmin"}}, {ID: 43, Name: "LateSecond", LeaderUserIDs: []string{"newadmin"}}},
			members:     map[int64][]MemberInfo{41: {{UserID: "newadmin"}}, 42: {{UserID: "newadmin"}}, 43: {{UserID: "newadmin"}}},
			tags:        []TagInfo{{ID: 88, Name: "ChangedCapability"}}, tagMembers: map[int64][]string{88: {"newadmin"}},
		}, admins: []AppAdminInfo{{UserID: "newadmin", AuthType: 1}},
	}}
	return governanceFailureFixture{candidate: candidate}
}

type governanceAuthorizationSnapshot struct {
	tables            map[string][]map[string][]byte
	publishedRevision int64
	managedOrgID      int64
	baselineRun       wecom_model.ReconcileRun
}

func snapshotGovernanceAuthorization(t *testing.T) governanceAuthorizationSnapshot {
	t.Helper()
	state := governanceAuthorizationSnapshot{tables: make(map[string][]map[string][]byte)}
	for _, table := range []string{"wecom_department", "wecom_tag", "wecom_membership", "wecom_identity", "wecom_admin_authority", "enterprise_wecom_authz_mapping", "enterprise_wecom_generated_mapping", "enterprise_wecom_generated_team", "enterprise_wecom_generated_team_admin", "enterprise_wecom_managed_membership", "user", "team", "team_unit", "team_user", "team_repo", "org_user", "access", "collaboration", "repository", "public_key", "access_token"} {
		rows, err := db.GetEngine(t.Context()).Query(fmt.Sprintf(`SELECT * FROM "%s" ORDER BY id`, table))
		require.NoError(t, err, table)
		state.tables[table] = rows
	}
	coordinator := unittest.AssertExistsAndLoadBean(t, &wecom_model.GovernanceCoordinator{CorpID: "corp-auto", AgentID: "1000002"})
	state.publishedRevision = coordinator.PublishedRevision
	state.managedOrgID = coordinator.ManagedOrgID
	state.baselineRun = *unittest.AssertExistsAndLoadBean(t, &wecom_model.ReconcileRun{RunID: "failure-baseline"})
	return state
}

func latestGovernanceFailureAuditID(t *testing.T) int64 {
	t.Helper()
	var maxID int64
	_, err := db.GetEngine(t.Context()).Table(new(audit_model.Event)).Select("MAX(id)").Get(&maxID)
	require.NoError(t, err)
	return maxID
}

func assertGovernanceFailurePreserved(t *testing.T, before governanceAuthorizationSnapshot, beforeAudit int64, run *wecom_model.ReconcileRun, runErr error) {
	t.Helper()
	require.Error(t, runErr)
	require.NotNil(t, run)
	require.Equal(t, wecom_model.ReconcileRunStatusFailed, run.Status)
	persisted := unittest.AssertExistsAndLoadBean(t, &wecom_model.ReconcileRun{RunID: run.RunID})
	require.Equal(t, wecom_model.ReconcileRunStatusFailed, persisted.Status)
	require.NotEmpty(t, persisted.Stage)
	require.NotEmpty(t, persisted.Reason)
	require.NotZero(t, persisted.FinishedUnix)
	for _, count := range []int{persisted.GeneratedMappings, persisted.GeneratedTeams, persisted.AddedMemberships, persisted.RemovedMemberships, persisted.AddedTeamAdmins, persisted.RemovedTeamAdmins, persisted.ProtectedCount} {
		require.Zero(t, count)
	}
	require.Zero(t, persisted.PublishedRevision)
	after := snapshotGovernanceAuthorization(t)
	for table, rows := range before.tables {
		require.Equal(t, rows, after.tables[table], "partial publication leaked into %s", table)
	}
	require.Equal(t, before.publishedRevision, after.publishedRevision)
	require.Equal(t, before.managedOrgID, after.managedOrgID)
	require.Equal(t, before.baselineRun, after.baselineRun)
	protected, err := wecom_model.IsActiveManagementAuthorityBoundUser(t.Context(), "corp-auto", "1000002", 1)
	require.NoError(t, err)
	require.True(t, protected)
	var events []*audit_model.Event
	require.NoError(t, db.GetEngine(t.Context()).Where("id > ?", beforeAudit).Find(&events))
	require.NotEmpty(t, events, "failed run must retain independent audit evidence")
	foundFailure := false
	for _, event := range events {
		metadata := audit_model.DecodeMetadata(event.Metadata)
		require.NotEqual(t, "success", metadata["outcome"], "success audit escaped the rolled-back publication")
		require.NotEqual(t, "promoted", metadata["outcome"], "promotion audit escaped the rolled-back publication")
		require.NotContains(t, event.Metadata, "sensitive-failure-canary")
		if event.Action == audit_model.EnterpriseWeComAutomationFinish && metadata["run_id"] == run.RunID {
			foundFailure = true
			require.EqualValues(t, "failed", metadata["outcome"])
		}
	}
	require.True(t, foundFailure)
	require.NotContains(t, persisted.ErrorMessage, "sensitive-failure-canary")
	require.NotContains(t, runErr.Error(), "sensitive-failure-canary")
}

func TestAutomationCandidateFailuresAtomic(t *testing.T) {
	for _, name := range []string{"directory_fetch", "authority_fetch", "cancel_after_fetch", "stale_fencing", "busy_writer", "missing_target", "personal_target", "foreign_target"} {
		t.Run(name, func(t *testing.T) {
			fixture := seedGovernanceFailureBaseline(t)
			before := snapshotGovernanceAuthorization(t)
			beforeAudit := latestGovernanceFailureAuditID(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			switch name {
			case "directory_fetch":
				fixture.candidate.directoryError = errors.New("access_token=sensitive-failure-canary")
			case "authority_fetch":
				fixture.candidate.adminErr = errors.New("secret=sensitive-failure-canary")
			case "cancel_after_fetch":
				fixture.candidate.beforeAuthority = func(context.Context) { cancel() }
			case "stale_fencing":
				fixture.candidate.beforeAuthority = func(ctx context.Context) {
					_, err := db.GetEngine(ctx).Where("corp_id = ? AND agent_id = ?", "corp-auto", "1000002").Incr("fencing_generation").Update(new(wecom_model.GovernanceCoordinator))
					require.NoError(t, err)
				}
			case "busy_writer":
				_, err := db.GetEngine(t.Context()).Where("corp_id = ? AND agent_id = ?", "corp-auto", "1000002").Cols("lease_owner", "lease_until_unix").Update(&wecom_model.GovernanceCoordinator{LeaseOwner: "other-instance", LeaseUntilUnix: time.Now().Unix() + 120})
				require.NoError(t, err)
			case "missing_target":
				setting.EnterpriseWeCom.ManagedOrgID = 0
			case "personal_target":
				setting.EnterpriseWeCom.ManagedOrgID = 1
			case "foreign_target":
				setting.EnterpriseWeCom.ManagedOrgID = 7
			}
			run, err := RunAutomationPipeline(ctx, fixture.candidate, AutomationRunOptions{RunID: "candidate-" + name})
			assertGovernanceFailurePreserved(t, before, beforeAudit, run, err)
		})
	}
}

func TestAutomationFailureCandidateCanPublishWithoutInjection(t *testing.T) {
	fixture := seedGovernanceFailureBaseline(t)
	before := snapshotGovernanceAuthorization(t)
	run, err := RunAutomationPipeline(t.Context(), fixture.candidate, AutomationRunOptions{RunID: "candidate-no-fault"})
	require.NoError(t, err)
	require.Equal(t, wecom_model.ReconcileRunStatusSuccess, run.Status)
	require.Equal(t, before.publishedRevision+1, run.PublishedRevision)
	require.Equal(t, 4, run.GeneratedTeams)
	require.Positive(t, run.AddedMemberships)
	require.Positive(t, run.RemovedMemberships)
	require.True(t, unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}).IsAdmin)
	protected, err := wecom_model.IsActiveManagementAuthorityBoundUser(t.Context(), "corp-auto", "1000002", 1)
	require.NoError(t, err)
	require.False(t, protected)
}
