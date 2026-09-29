// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/require"
)

func TestAuthenticateOAuthLoginAuditsWeComOutcomesWithoutSecrets(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:          true,
		LoginOnly:        true,
		CorpID:           "corp-audit",
		AgentID:          "1000002",
		CorpSecret:       "corp-secret-value",
		UsernameTemplate: "{userid}",
		AutoCreateUser:   true,
	})()
	deleteWeComAuditEvents(t)

	authSource := wecomAuthSource(30)
	successUser := goth.User{
		UserID: "audit-user",
		Name:   "审计用户",
		Email:  "private-mail@example.com",
		RawData: map[string]any{
			"wecom_corp_id":  "corp-audit",
			"wecom_agent_id": "1000002",
			"wecom_userid":   "audit-user",
		},
	}

	_, err := AuthenticateOAuthLogin(t.Context(), authSource, nil, nil, successUser)
	require.NoError(t, err)
	_, err = AuthenticateOAuthLogin(t.Context(), authSource, nil, nil, successUser)
	require.NoError(t, err)

	_, _, err = wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{
		UserID:        1,
		CorpID:        "corp-audit",
		WeComUserID:   "inactive-user",
		LoginSourceID: authSource.ID,
		Status:        wecom_model.IdentityStatusInactive,
	})
	require.NoError(t, err)
	_, err = AuthenticateOAuthLogin(t.Context(), authSource, nil, nil, goth.User{
		UserID: "inactive-user",
		RawData: map[string]any{
			"wecom_corp_id":  "corp-audit",
			"wecom_agent_id": "1000002",
			"wecom_userid":   "inactive-user",
		},
	})
	require.ErrorIs(t, err, ErrWeComDenied)

	events := weComAuditEvents(t)
	for _, action := range []audit_model.Action{
		audit_model.EnterpriseWeComIdentityBind,
		audit_model.EnterpriseWeComIdentityUpdate,
		audit_model.EnterpriseWeComLoginSuccess,
		audit_model.EnterpriseWeComLoginDeny,
	} {
		require.True(t, slices.ContainsFunc(events, func(event *audit_model.Event) bool {
			return event.Action == action
		}), "missing audit action %s", action)
	}

	assertNoWeComAuditSecretLeak(t, events)
}

func TestSyncDirectoryAuditsFailureWithoutSecrets(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:         true,
		CorpID:          "corp-audit",
		AgentID:         "1000002",
		CorpSecret:      "corp-secret-value",
		SyncDepartments: true,
		SyncTags:        true,
	})()
	deleteWeComAuditEvents(t)

	err := SyncDirectory(t.Context(), leakingDirectoryClient{})
	require.Error(t, err)

	events := weComAuditEvents(t)
	for _, action := range []audit_model.Action{
		audit_model.EnterpriseWeComSyncStart,
		audit_model.EnterpriseWeComSyncFinish,
	} {
		require.True(t, slices.ContainsFunc(events, func(event *audit_model.Event) bool {
			return event.Action == action
		}), "missing audit action %s", action)
	}
	assertNoWeComAuditSecretLeak(t, events)
}

func TestRefreshAdminAuthorityAuditsOutcomeWithoutSecrets(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:    true,
		CorpID:     "corp-audit-authority",
		AgentID:    "1000002",
		CorpSecret: "corp-secret-value",
	})()
	deleteWeComAuditEvents(t)

	_, err := RefreshAdminAuthoritySnapshot(t.Context(), fakeAdminAuthorityClient{err: errors.New("access_token=suite-access-token&code=authorization-code&mobile=13800138000")}, AdminAuthorityRefreshOptions{RunID: "authority-audit"})
	require.Error(t, err)

	events := weComAuditEvents(t)
	event := findWeComAuditEvent(t, events, audit_model.EnterpriseWeComAuthorityRefresh)
	metadata := audit_model.DecodeMetadata(event.Metadata)
	require.Equal(t, "error", metadata["outcome"])
	require.Equal(t, "provider_error", metadata["reason"])
	assertNoWeComAuditSecretLeak(t, events)
}

type leakingDirectoryClient struct{}

func (leakingDirectoryClient) ListDepartments(context.Context) ([]DepartmentInfo, error) {
	return nil, errors.New("Get https://qyapi.weixin.qq.com/cgi-bin/department/list?access_token=access-token&code=authorization-code&corpsecret=corp-secret-value: dial tcp")
}

func (leakingDirectoryClient) ListMembers(context.Context, int64) ([]MemberInfo, error) {
	return nil, nil
}

func (leakingDirectoryClient) ListTags(context.Context) ([]TagInfo, error) {
	return nil, nil
}

func (leakingDirectoryClient) ListTagMembers(context.Context, int64) ([]string, error) {
	return nil, nil
}

func deleteWeComAuditEvents(t *testing.T) {
	t.Helper()
	_, err := db.GetEngine(t.Context()).Where("action LIKE ?", "enterprise:wecom:%").Delete(new(audit_model.Event))
	require.NoError(t, err)
}

func weComAuditEvents(t *testing.T) []*audit_model.Event {
	t.Helper()
	events, _, err := audit_model.FindEvents(t.Context(), &audit_model.EventSearchOptions{
		ActionPrefix: audit_model.Action("enterprise:wecom"),
		Sort:         audit_model.SortTimestampAsc,
	})
	require.NoError(t, err)
	require.NotEmpty(t, events)
	return events
}

func assertNoWeComAuditSecretLeak(t *testing.T, events []*audit_model.Event) {
	t.Helper()
	for _, event := range events {
		metadata := audit_model.DecodeMetadata(event.Metadata)
		for forbidden := range metadata {
			for _, sensitiveKey := range []string{"secret", "token", "code", "email", "mobile"} {
				require.NotContains(t, strings.ToLower(forbidden), sensitiveKey, "sensitive key leaked in %s", event.Action)
			}
		}
		raw := strings.ToLower(event.Metadata)
		for _, forbidden := range []string{"corp-secret-value", "access-token", "authorization-code", "private-mail@example.com"} {
			require.NotContains(t, raw, forbidden, "sensitive value leaked in %s", event.Action)
		}
	}
}

func TestApplyAuthzMappingsAuditsSummaryWithoutSecrets(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:    true,
		CorpID:     "corp-audit-map",
		AgentID:    "1000002",
		CorpSecret: "corp-secret-value",
	})()
	deleteWeComAuditEvents(t)

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 1, CorpID: "corp-audit-map", WeComUserID: "audit-map-user", LoginSourceID: 1, Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	_, err = CreateAuthzMapping(t.Context(), AuthzMappingOptions{SourceType: wecom_model.AuthzSourceUser, SourceID: "audit-map-user", TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID, ActorID: 1})
	require.NoError(t, err)
	_, err = ApplyAuthzMappings(t.Context(), AuthzReconcileOptions{ActorID: 1, ApplyID: "audit-manual"})
	require.NoError(t, err)

	events := weComAuditEvents(t)
	applyEvent := findWeComAuditEvent(t, events, audit_model.EnterpriseWeComMappingApply)
	metadata := audit_model.DecodeMetadata(applyEvent.Metadata)
	require.Equal(t, "applied", metadata["outcome"])
	require.EqualValues(t, 1, metadata["additions"])
	require.EqualValues(t, 0, metadata["errors"])
	assertNoWeComAuditSecretLeak(t, events)
}

func TestSyncDirectoryPostSyncApplyAuditsSummaryWithoutSecrets(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:                  true,
		CorpID:                   "corp-audit-sync",
		AgentID:                  "1000002",
		CorpSecret:               "corp-secret-value",
		SyncDepartments:          true,
		ApplyAuthzMappingsOnSync: true,
	})()
	deleteWeComAuditEvents(t)

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 1, CorpID: "corp-audit-sync", WeComUserID: "audit-sync-user", LoginSourceID: 1, Status: wecom_model.IdentityStatusOutOfScope})
	require.NoError(t, err)
	require.NoError(t, wecom_model.UpsertDepartment(t.Context(), &wecom_model.Department{CorpID: "corp-audit-sync", DepartmentID: 2, Name: "研发"}))
	_, err = CreateAuthzMapping(t.Context(), AuthzMappingOptions{SourceType: wecom_model.AuthzSourceDepartment, SourceID: "2", TargetType: wecom_model.AuthzTargetTeam, OrgID: team.OrgID, TeamID: team.ID, ActorID: 1})
	require.NoError(t, err)

	require.NoError(t, SyncDirectory(t.Context(), fakeDirectoryClient{
		departments: []DepartmentInfo{{ID: 2, Name: "研发"}},
		members:     map[int64][]MemberInfo{2: {{UserID: "audit-sync-user"}}},
	}))

	events := weComAuditEvents(t)
	applyEvent := findWeComAuditEvent(t, events, audit_model.EnterpriseWeComMappingApply)
	metadata := audit_model.DecodeMetadata(applyEvent.Metadata)
	require.Equal(t, "applied", metadata["outcome"])
	require.EqualValues(t, 1, metadata["additions"])
	assertNoWeComAuditSecretLeak(t, events)
}

func findWeComAuditEvent(t *testing.T, events []*audit_model.Event, action audit_model.Action) *audit_model.Event {
	t.Helper()
	for _, event := range events {
		if event.Action == action {
			return event
		}
	}
	require.Failf(t, "missing audit action", "missing audit action %s", action)
	return nil
}
