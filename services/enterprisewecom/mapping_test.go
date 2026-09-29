// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"slices"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestAuthzMappingCRUDValidatesSourcesAndTargets(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockMappingSettings(t)
	seedMappingDirectory(t)

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	mapping, err := CreateAuthzMapping(t.Context(), AuthzMappingOptions{
		SourceType: wecom_model.AuthzSourceDepartment,
		SourceID:   "100",
		TargetType: wecom_model.AuthzTargetTeam,
		OrgID:      team.OrgID,
		TeamID:     team.ID,
		ActorID:    1,
	})
	require.NoError(t, err)
	require.NotZero(t, mapping.ID)
	require.True(t, mapping.IsActive)
	require.Equal(t, setting.EnterpriseWeCom.CorpID, mapping.CorpID)

	fetched, err := GetAuthzMapping(t.Context(), mapping.ID)
	require.NoError(t, err)
	require.Equal(t, wecom_model.AuthzSourceDepartment, fetched.SourceType)

	listed, err := ListAuthzMappings(t.Context(), AuthzMappingListOptions{CorpID: setting.EnterpriseWeCom.CorpID})
	require.NoError(t, err)
	require.Len(t, listed, 1)

	updated, err := UpdateAuthzMapping(t.Context(), mapping.ID, AuthzMappingOptions{
		SourceType: wecom_model.AuthzSourceTag,
		SourceID:   "8",
		TargetType: wecom_model.AuthzTargetTeam,
		OrgID:      team.OrgID,
		TeamID:     team.ID,
		ActorID:    1,
	})
	require.NoError(t, err)
	require.Equal(t, wecom_model.AuthzSourceTag, updated.SourceType)
	require.Equal(t, "8", updated.SourceID)

	require.NoError(t, DisableAuthzMapping(t.Context(), mapping.ID, 1))
	disabled, err := GetAuthzMapping(t.Context(), mapping.ID)
	require.NoError(t, err)
	require.False(t, disabled.IsActive)
}

func TestAuthzMappingRejectsInvalidSourceAndTarget(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockMappingSettings(t)
	seedMappingDirectory(t)

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})

	_, err := CreateAuthzMapping(t.Context(), AuthzMappingOptions{
		SourceType: wecom_model.AuthzSourceDepartment,
		SourceID:   "404",
		TargetType: wecom_model.AuthzTargetTeam,
		OrgID:      team.OrgID,
		TeamID:     team.ID,
		ActorID:    1,
	})
	require.ErrorIs(t, err, ErrInvalidAuthzMapping)

	_, err = CreateAuthzMapping(t.Context(), AuthzMappingOptions{
		SourceType: wecom_model.AuthzSourceTag,
		SourceID:   "not-a-number",
		TargetType: wecom_model.AuthzTargetTeam,
		OrgID:      team.OrgID,
		TeamID:     team.ID,
		ActorID:    1,
	})
	require.ErrorIs(t, err, ErrInvalidAuthzMapping)

	_, err = CreateAuthzMapping(t.Context(), AuthzMappingOptions{
		SourceType: wecom_model.AuthzSourceUser,
		SourceID:   "wecom-user-1",
		TargetType: wecom_model.AuthzTargetTeam,
		OrgID:      team.OrgID + 1,
		TeamID:     team.ID,
		ActorID:    1,
	})
	require.ErrorIs(t, err, ErrInvalidAuthzMapping)
}

func TestAuthzMappingAuditsChangesAndFailuresWithoutSecrets(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockMappingSettings(t)
	seedMappingDirectory(t)
	defer test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase)()
	deleteWeComAuditEvents(t)

	team := unittest.AssertExistsAndLoadBean(t, &organization.Team{ID: 2})
	mapping, err := CreateAuthzMapping(t.Context(), AuthzMappingOptions{
		SourceType: wecom_model.AuthzSourceUser,
		SourceID:   "wecom-user-1",
		TargetType: wecom_model.AuthzTargetTeam,
		OrgID:      team.OrgID,
		TeamID:     team.ID,
		ActorID:    1,
	})
	require.NoError(t, err)
	require.NoError(t, DisableAuthzMapping(t.Context(), mapping.ID, 1))

	_, err = CreateAuthzMapping(t.Context(), AuthzMappingOptions{
		SourceType: wecom_model.AuthzSourceUser,
		SourceID:   "missing-user",
		TargetType: wecom_model.AuthzTargetTeam,
		OrgID:      team.OrgID,
		TeamID:     team.ID,
		ActorID:    1,
	})
	require.ErrorIs(t, err, ErrInvalidAuthzMapping)

	events := weComAuditEvents(t)
	require.True(t, slices.ContainsFunc(events, func(event *audit_model.Event) bool {
		return event.Action == audit_model.EnterpriseWeComMappingUpdate
	}), "missing mapping update audit event")
	assertNoWeComAuditSecretLeak(t, events)
}

func mockMappingSettings(t *testing.T) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:         true,
		CorpID:          "corp-map",
		AgentID:         "1000002",
		CorpSecret:      "corp-secret-value",
		SyncDepartments: true,
		SyncTags:        true,
	}))
}

func seedMappingDirectory(t *testing.T) {
	t.Helper()
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{
		UserID:        2,
		CorpID:        "corp-map",
		WeComUserID:   "wecom-user-1",
		LoginSourceID: 1,
		Status:        wecom_model.IdentityStatusActive,
	})
	require.NoError(t, err)
	require.NoError(t, wecom_model.UpsertDepartment(t.Context(), &wecom_model.Department{CorpID: "corp-map", DepartmentID: 100, Name: "R&D"}))
	require.NoError(t, wecom_model.UpsertTag(t.Context(), &wecom_model.Tag{CorpID: "corp-map", TagID: 8, Name: "Maintainers"}))
	count, err := db.GetEngine(t.Context()).Count(new(wecom_model.AuthzMapping))
	require.NoError(t, err)
	require.Zero(t, count)
}
