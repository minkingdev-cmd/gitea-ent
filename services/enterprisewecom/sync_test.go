// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"errors"
	"testing"
	"time"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/unittest"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func mockSyncSettings(t *testing.T, departments, tags bool) {
	t.Helper()
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{
		Enabled:         true,
		LoginSourceName: "enterprise-wecom",
		CorpID:          "corp-1",
		AgentID:         "1000002",
		CorpSecret:      "secret",
		SyncDepartments: departments,
		SyncTags:        tags,
		HTTPTimeout:     15 * time.Second,
	}))
}

func TestSyncDirectoryIsIdempotent(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockSyncSettings(t, true, true)

	client := fakeDirectoryClient{
		departments: []DepartmentInfo{{ID: 1, ParentID: 0, Name: "总部"}, {ID: 2, ParentID: 1, Name: "研发"}},
		members: map[int64][]MemberInfo{
			2: {{UserID: "zhangsan", Name: "张三", Email: "zhangsan@example.com"}},
		},
		tags:       []TagInfo{{ID: 8, Name: "Maintainers"}},
		tagMembers: map[int64][]string{8: {"zhangsan"}},
	}

	require.NoError(t, SyncDirectory(t.Context(), client))
	require.NoError(t, SyncDirectory(t.Context(), client))

	deptCount, err := db.GetEngine(t.Context()).Count(new(wecom_model.Department))
	require.NoError(t, err)
	require.Equal(t, int64(2), deptCount)
	tagCount, err := db.GetEngine(t.Context()).Count(new(wecom_model.Tag))
	require.NoError(t, err)
	require.Equal(t, int64(1), tagCount)
	membershipCount, err := db.GetEngine(t.Context()).Count(new(wecom_model.Membership))
	require.NoError(t, err)
	require.Equal(t, int64(2), membershipCount)

	identity, has, err := wecom_model.GetIdentityByCorpAndUserID(t.Context(), "corp-1", "zhangsan")
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, wecom_model.IdentityStatusActive, identity.Status)
}

func TestSyncDirectoryReconcilesMissingMembers(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockSyncSettings(t, true, true)

	initial := fakeDirectoryClient{
		departments: []DepartmentInfo{{ID: 1, Name: "总部"}},
		members:     map[int64][]MemberInfo{1: {{UserID: "zhangsan", Name: "张三"}}},
		tags:        []TagInfo{{ID: 8, Name: "Maintainers"}},
		tagMembers:  map[int64][]string{8: {"zhangsan"}},
	}
	require.NoError(t, SyncDirectory(t.Context(), initial))

	empty := fakeDirectoryClient{
		departments: []DepartmentInfo{{ID: 1, Name: "总部"}},
		members:     map[int64][]MemberInfo{},
		tags:        []TagInfo{{ID: 8, Name: "Maintainers"}},
		tagMembers:  map[int64][]string{},
	}
	require.NoError(t, SyncDirectory(t.Context(), empty))

	identity, has, err := wecom_model.GetIdentityByCorpAndUserID(t.Context(), "corp-1", "zhangsan")
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, wecom_model.IdentityStatusOutOfScope, identity.Status)
	membershipCount, err := db.GetEngine(t.Context()).Count(new(wecom_model.Membership))
	require.NoError(t, err)
	require.Zero(t, membershipCount)
}

func TestSyncDirectoryCreatesTagOnlyIdentity(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockSyncSettings(t, false, true)

	client := fakeDirectoryClient{
		tags:       []TagInfo{{ID: 8, Name: "Maintainers"}},
		tagMembers: map[int64][]string{8: {"tag-user"}},
	}
	require.NoError(t, SyncDirectory(t.Context(), client))

	identity, has, err := wecom_model.GetIdentityByCorpAndUserID(t.Context(), "corp-1", "tag-user")
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, wecom_model.IdentityStatusActive, identity.Status)
}

func TestSyncDirectoryDoesNotPersistPartialSnapshot(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	mockSyncSettings(t, true, true)

	client := fakeDirectoryClient{
		departments: []DepartmentInfo{{ID: 1, Name: "总部"}},
		members:     map[int64][]MemberInfo{1: {{UserID: "zhangsan"}}},
		listTagsErr: errors.New("tag request failed"),
	}
	require.Error(t, SyncDirectory(t.Context(), client))

	identity, has, err := wecom_model.GetIdentityByCorpAndUserID(t.Context(), "corp-1", "zhangsan")
	require.NoError(t, err)
	require.False(t, has)
	require.Zero(t, identity.ID)
}

func TestSyncDirectoryRejectsDisabledIntegration(t *testing.T) {
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	require.ErrorIs(t, SyncDirectory(t.Context(), fakeDirectoryClient{}), ErrWeComDisabled)
}

type fakeDirectoryClient struct {
	departments []DepartmentInfo
	members     map[int64][]MemberInfo
	tags        []TagInfo
	tagMembers  map[int64][]string
	listTagsErr error
}

func (f fakeDirectoryClient) ListDepartments(context.Context) ([]DepartmentInfo, error) {
	return f.departments, nil
}

func (f fakeDirectoryClient) ListMembers(_ context.Context, departmentID int64) ([]MemberInfo, error) {
	return f.members[departmentID], nil
}

func (f fakeDirectoryClient) ListTags(context.Context) ([]TagInfo, error) {
	return f.tags, f.listTagsErr
}

func (f fakeDirectoryClient) ListTagMembers(_ context.Context, tagID int64) ([]string, error) {
	return f.tagMembers[tagID], nil
}
