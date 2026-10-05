// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	package_model "gitea.dev/models/packages"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/util"

	"github.com/stretchr/testify/require"
)

func TestAdoptCargoIndexAuthorityAndIdentity(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	setting.EnterpriseAuthz.Enabled = false
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	require.ErrorIs(t, AdoptCargoIndex(t.Context(), owner, repo.ID, false), util.ErrPermissionDenied)
	require.ErrorIs(t, AdoptCargoIndex(t.Context(), admin, repo.ID, false), util.ErrInvalidArgument)
	require.NoError(t, AdoptCargoIndex(t.Context(), admin, repo.ID, true))
	fresh := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: repo.ID})
	require.Equal(t, repo_model.InternalUsageCargoIndex, fresh.InternalUsage)
	require.NoError(t, AdoptCargoIndex(t.Context(), admin, repo.ID, true))
	count, err := db.GetEngine(t.Context()).Where("action=?", audit_model.EnterpriseCargoIndexAdopt).Count(new(audit_model.Event))
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	other := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
	require.Equal(t, repo.OwnerID, other.OwnerID)
	require.ErrorIs(t, AdoptCargoIndex(t.Context(), admin, other.ID, true), util.ErrAlreadyExist)
	require.Empty(t, unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: other.ID}).InternalUsage)
}

func TestCargoIndexPreflightRequiresExplicitAdoption(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	repo := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1})
	repo.Name = "_cargo-index"
	repo.LowerName = repo.Name
	require.NoError(t, repo_model.UpdateRepositoryColsWithAutoTime(t.Context(), repo, "name", "lower_name"))
	require.NoError(t, db.Insert(t.Context(), &package_model.Package{OwnerID: repo.OwnerID, Type: package_model.TypeCargo, Name: "trusted-preflight-crate", LowerName: "trusted-preflight-crate"}))
	require.EqualError(t, authz_model.CheckReady(t.Context()), "cargo_index_purpose_unresolved")
	setting.EnterpriseAuthz.Enabled = false
	require.NoError(t, authz_model.CheckReady(t.Context()))
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	require.NoError(t, AdoptCargoIndex(t.Context(), admin, repo.ID, true))
	setting.EnterpriseAuthz.Enabled = true
	require.NoError(t, authz_model.CheckCargoIndexPurposes(t.Context()))
}

func TestCargoIndexHistorySourcesRemainHidden(t *testing.T) {
	enableObservation(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
	setting.EnterpriseAuthz.Enforce = true
	admin := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 1})
	require.NoError(t, AdoptCargoIndex(t.Context(), admin, 2, true, 1))
	_, err := PutFeatureGrant(t.Context(), admin, authz_model.Scope{Type: authz_model.ScopeSystem}, authz.FeaturePackages, FeatureGrantInput{State: authz.FeatureEnabled, Config: []byte(`{}`)})
	require.NoError(t, err)
	owner := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	_, err = PutFeatureGrant(t.Context(), owner, authz_model.Scope{Type: authz_model.ScopeRepo, ID: 1}, authz.FeaturePackages, FeatureGrantInput{State: authz.FeatureDisabled, Config: []byte(`{}`)})
	require.NoError(t, err)
	index := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
	require.ErrorContains(t, RequireCargoIndexFeature(t.Context(), index), "feature_disabled")
	ids, err := authz_model.DeniedCargoIndexRepositoryIDs(t.Context())
	require.NoError(t, err)
	require.Equal(t, []int64{2}, ids)
	setting.EnterpriseAuthz.Enforce = false
	require.NoError(t, RequireCargoIndexFeature(t.Context(), index))
	ids, err = authz_model.DeniedCargoIndexRepositoryIDs(t.Context())
	require.NoError(t, err)
	require.Empty(t, ids)
}
