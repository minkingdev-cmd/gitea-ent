// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"testing"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestGeneratedMappingReadsIsolateConfiguredScope(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-read", AgentID: "agent-read", ManagedOrgID: 3}))
	rows := []*wecom_model.AuthzMapping{
		{CorpID: "corp-read", AgentID: "agent-read", Origin: "generated", SourceID: "active", OrgID: 3, IsActive: true},
		{CorpID: "corp-read", AgentID: "agent-read", Origin: "generated", SourceID: "inactive", OrgID: 3, IsActive: false},
		{CorpID: "other-corp", AgentID: "agent-read", Origin: "generated", SourceID: "other-corp", OrgID: 3, IsActive: true},
		{CorpID: "corp-read", AgentID: "other-agent", Origin: "generated", SourceID: "other-agent", OrgID: 3, IsActive: true},
		{CorpID: "corp-read", AgentID: "agent-read", Origin: "generated", SourceID: "other-org", OrgID: 7, IsActive: true},
		{CorpID: "corp-read", AgentID: "agent-read", Origin: "legacy", SourceID: "legacy", OrgID: 3, IsActive: true},
		{CorpID: "corp-read", AgentID: "agent-read", Origin: "generated", SourceID: "personal-owner", OrgID: 1, IsActive: true},
	}
	for _, row := range rows {
		row.SourceType = wecom_model.AuthzSourceUser
		row.TargetType = wecom_model.AuthzTargetOrg
		require.NoError(t, db.Insert(t.Context(), row))
	}
	// xorm 的插入默认值可能覆盖 false。
	_, err := db.GetEngine(t.Context()).ID(rows[1].ID).Cols("is_active").Update(&wecom_model.AuthzMapping{IsActive: false})
	require.NoError(t, err)
	listed, err := ListGeneratedAuthzMappings(t.Context(), AuthzMappingListOptions{CorpID: "other-corp"})
	require.NoError(t, err)
	require.Len(t, listed, 1)
	require.Equal(t, rows[0].ID, listed[0].ID)
	listed, err = ListGeneratedAuthzMappings(t.Context(), AuthzMappingListOptions{IncludeInactive: true})
	require.NoError(t, err)
	require.Len(t, listed, 2)
	for _, row := range rows[:2] {
		got, err := GetGeneratedAuthzMapping(t.Context(), row.ID)
		require.NoError(t, err)
		require.Equal(t, row.ID, got.ID)
	}
	for _, row := range rows[2:] {
		_, err := GetGeneratedAuthzMapping(t.Context(), row.ID)
		require.ErrorIs(t, err, ErrInvalidAuthzMapping)
	}
	for _, id := range []int64{0, -1, 999999} {
		_, err := GetGeneratedAuthzMapping(t.Context(), id)
		require.ErrorIs(t, err, ErrInvalidAuthzMapping)
	}
	for _, target := range []int64{0, -1, 1, 999999} {
		setting.EnterpriseWeCom.ManagedOrgID = target
		listed, err = ListGeneratedAuthzMappings(t.Context(), AuthzMappingListOptions{IncludeInactive: true})
		require.NoError(t, err)
		require.Empty(t, listed)
		_, err = GetGeneratedAuthzMapping(t.Context(), rows[0].ID)
		require.ErrorIs(t, err, ErrInvalidAuthzMapping)
	}
}
