// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"testing"

	"gitea.dev/models/db"
	"gitea.dev/models/organization"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"

	"github.com/stretchr/testify/require"
)

func TestNativeActionMappingKeepsIndependentCodeAndPullPermissions(t *testing.T) {
	for _, tt := range []struct {
		name        string
		code, pulls perm.AccessMode
		want, deny  []authz.Action
	}{
		{"PR writer", perm.AccessModeRead, perm.AccessModeWrite, []authz.Action{authz.CreatePullRequest, authz.ReviewPullRequest}, []authz.Action{authz.PushBranch, authz.MergePullRequest}},
		{"code writer", perm.AccessModeWrite, perm.AccessModeRead, []authz.Action{authz.PushBranch, authz.MergePullRequest}, []authz.Action{authz.CreatePullRequest, authz.ReviewPullRequest}},
		{"hidden code", perm.AccessModeNone, perm.AccessModeWrite, []authz.Action{authz.ReviewPullRequest}, []authz.Action{authz.ReadCode, authz.Clone, authz.CreatePullRequest, authz.MergePullRequest}},
		{"hidden PR", perm.AccessModeWrite, perm.AccessModeNone, []authz.Action{authz.PushBranch}, []authz.Action{authz.CreatePullRequest, authz.ReviewPullRequest, authz.MergePullRequest}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.NoError(t, unittest.PrepareTestDatabase())
			_, err := db.GetEngine(t.Context()).ID(2).Cols("authorize").Update(&organization.Team{AccessMode: perm.AccessModeNone})
			require.NoError(t, err)
			_, err = db.GetEngine(t.Context()).ID(3).Cols("is_private").Update(&repo_model.Repository{IsPrivate: true})
			require.NoError(t, err)
			for typ, mode := range map[unit.Type]perm.AccessMode{unit.TypeCode: tt.code, unit.TypePullRequests: tt.pulls} {
				_, err := db.GetEngine(t.Context()).Where("team_id = ? AND type = ?", 2, typ).Cols("access_mode").Update(&organization.TeamUnit{AccessMode: mode})
				require.NoError(t, err)
			}
			repository := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 3})
			actor := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4})
			permission, err := access_model.GetDoerRepoPermission(t.Context(), repository, actor)
			require.NoError(t, err)
			require.Equal(t, perm.AccessModeWrite, permission.AccessMode)
			actions := NativeActions(repository, &permission, CredentialCeiling{Read: true, Write: true})
			for _, action := range tt.want {
				require.Contains(t, actions, action)
			}
			for _, action := range tt.deny {
				require.NotContains(t, actions, action)
			}
		})
	}
}

func TestNativeActionMapping(t *testing.T) {
	for _, tc := range []struct {
		name         string
		mode         perm.AccessMode
		units        []unit.Type
		ceiling      CredentialCeiling
		archived     bool
		want, absent []authz.Action
	}{
		{name: "reader", mode: perm.AccessModeRead, units: []unit.Type{unit.TypeCode, unit.TypePullRequests}, ceiling: CredentialCeiling{Read: true, Write: true}, want: []authz.Action{authz.ViewMetadata, authz.ReadCode, authz.Clone}, absent: []authz.Action{authz.PushBranch, authz.CreatePullRequest, authz.ReviewPullRequest, authz.MergePullRequest}},
		{name: "writer", mode: perm.AccessModeWrite, units: []unit.Type{unit.TypeCode, unit.TypePullRequests}, ceiling: CredentialCeiling{Read: true, Write: true}, want: []authz.Action{authz.PushBranch, authz.CreateBranch, authz.CreatePullRequest, authz.ReviewPullRequest, authz.MergePullRequest}, absent: []authz.Action{authz.PushProtectedBranch, authz.ManageSecret, authz.Delete}},
		{name: "admin not owner", mode: perm.AccessModeAdmin, units: []unit.Type{unit.TypeCode, unit.TypePullRequests, unit.TypeActions}, ceiling: CredentialCeiling{Read: true, Write: true}, want: []authz.Action{authz.ManageCodeowners, authz.ManageBranchProtection, authz.ManageCI, authz.ManageWebhook}, absent: []authz.Action{authz.Delete, authz.Archive, authz.Transfer, authz.Migrate, authz.PushProtectedBranch, authz.ManageSecret}},
		{name: "required checks without Actions unit", mode: perm.AccessModeAdmin, units: []unit.Type{unit.TypeCode}, ceiling: CredentialCeiling{Read: true, Write: true}, want: []authz.Action{authz.ManageCI}, absent: []authz.Action{authz.ManageSecret}},
		{name: "owner", mode: perm.AccessModeOwner, units: []unit.Type{unit.TypeCode, unit.TypePullRequests, unit.TypeActions}, ceiling: CredentialCeiling{Read: true, Write: true}, want: []authz.Action{authz.Delete, authz.ManageSecret, authz.Transfer, authz.ManageFeatureGrant}},
		{name: "hidden code", mode: perm.AccessModeWrite, units: []unit.Type{unit.TypeIssues}, ceiling: CredentialCeiling{Read: true, Write: true}, want: []authz.Action{authz.ViewMetadata}, absent: []authz.Action{authz.ReadCode, authz.Clone, authz.PushBranch, authz.CreatePullRequest}},
		{name: "read-only credential", mode: perm.AccessModeOwner, units: []unit.Type{unit.TypeCode, unit.TypePullRequests, unit.TypeActions}, ceiling: CredentialCeiling{Read: true}, want: []authz.Action{authz.Clone}, absent: []authz.Action{authz.PushBranch, authz.Delete, authz.ManageSecret}},
		{name: "no credential scope", mode: perm.AccessModeOwner, units: []unit.Type{unit.TypeCode}, absent: []authz.Action{authz.ViewMetadata, authz.Clone, authz.Delete}},
		{name: "archived", mode: perm.AccessModeOwner, units: []unit.Type{unit.TypeCode}, ceiling: CredentialCeiling{Read: true, Write: true}, archived: true, want: []authz.Action{authz.Clone, authz.Archive}, absent: []authz.Action{authz.PushBranch, authz.CreateBranch, authz.MergePullRequest}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			permission := access_model.Permission{AccessMode: tc.mode}
			var units []*repo_model.RepoUnit
			for _, typ := range tc.units {
				units = append(units, &repo_model.RepoUnit{Type: typ})
			}
			permission.SetUnitsWithDefaultAccessMode(units, tc.mode)
			repo := &repo_model.Repository{ID: 1, OwnerID: 2, IsArchived: tc.archived}
			actions := NativeActions(repo, &permission, tc.ceiling)
			for _, key := range tc.want {
				require.Contains(t, actions, key)
			}
			for _, key := range tc.absent {
				require.NotContains(t, actions, key)
			}
		})
	}
}

func TestSubjectsCannotEscapeNativeBoundaries(t *testing.T) {
	require.False(t, roleEligible(nil))
	require.False(t, roleEligible(user_model.NewActionsUserWithTaskID(1)))
	require.False(t, roleEligible(user_model.NewDeployKeyUserWithKeyID(1)))
	require.False(t, roleEligible(&user_model.User{ID: 2, Type: user_model.UserTypeOrganization, IsActive: true}))
	require.False(t, roleEligible(&user_model.User{ID: 2, ProhibitLogin: true, IsActive: true}))
	require.False(t, roleEligible(&user_model.User{ID: 2, IsActive: false}))
	require.False(t, roleEligible(&user_model.User{ID: 2, IsActive: true, IsRestricted: true}))
	require.False(t, roleEligible(&user_model.User{ID: 2, IsActive: true, ExtDoerData: user_model.NewActionsUserWithTaskID(1).ExtDoerData}))
}
