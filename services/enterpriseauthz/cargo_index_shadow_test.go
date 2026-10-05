// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"
	"strings"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	package_model "gitea.dev/models/packages"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"

	"github.com/stretchr/testify/require"
	"xorm.io/xorm/contexts"
)

func TestCargoIndexShadowObservesLinkedAndHistoricalSources(t *testing.T) {
	for _, source := range []string{"linked", "historical", "deleted", "current_owner"} {
		t.Run(source, func(t *testing.T) {
			enableObservation(t)
			setting.EnterpriseAuthz.Enforce = false
			_, err := db.GetEngine(t.Context()).ID(2).Cols("internal_usage").Update(&repo_model.Repository{InternalUsage: repo_model.InternalUsageCargoIndex})
			require.NoError(t, err)
			if source == "linked" {
				require.NoError(t, db.Insert(t.Context(), &package_model.Package{OwnerID: 2, RepoID: 1, Type: package_model.TypeCargo, Name: "shadow-crate", LowerName: "shadow-crate"}))
			} else {
				sourceID := int64(1)
				if source == "deleted" {
					sourceID = 999999
				}
				require.NoError(t, db.Insert(t.Context(), &authz_model.CargoIndexSource{IndexRepoID: 2, SourceRepoID: sourceID}))
			}
			if source == "current_owner" {
				_, err := db.GetEngine(t.Context()).ID(1).Cols("owner_id").Update(&repo_model.Repository{OwnerID: 3})
				require.NoError(t, err)
				require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeOrg, ScopeID: 3, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
			} else if source != "deleted" {
				require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
			}
			idx := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
			hook := &cargoCandidateQueries{enabled: true}
			db.GetXORMEngineForTesting().AddHook(hook)
			t.Cleanup(func() { hook.enabled = false })
			require.NoError(t, RequireCargoIndexFeature(t.Context(), idx))
			var events []*audit_model.Event
			require.NoError(t, db.GetEngine(t.Context()).Where("action=? AND scope_id=?", audit_model.EnterpriseFeatureDecision, idx.ID).Find(&events))
			var candidates []*audit_model.Event
			for _, event := range events {
				if strings.Contains(event.Metadata, `"candidate_decision":"deny"`) {
					candidates = append(candidates, event)
				}
			}
			require.Len(t, candidates, 1)
			require.Contains(t, candidates[0].Metadata, `"actual_decision":"native"`)
			require.Contains(t, candidates[0].Metadata, `"mode":"shadow"`)
			require.Equal(t, 1, hook.sourceQueries)
		})
	}
}

func TestCargoIndexDisabledSkipsFeatureQueries(t *testing.T) {
	enableObservation(t)
	setting.EnterpriseAuthz.Enabled = false
	hook := &cargoCandidateQueries{enabled: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	t.Cleanup(func() { hook.enabled = false })
	require.NoError(t, RequireCargoIndexFeature(t.Context(), &repo_model.Repository{ID: 2, InternalUsage: repo_model.InternalUsageCargoIndex}))
	require.Zero(t, hook.featureQueries)
	require.False(t, authz_model.RepoFeatureEnabledCond(t.Context(), authz.FeaturePackages, "repository.id").IsValid())
	require.False(t, authz_model.PackageFeatureEnabledCond(t.Context()).IsValid())
}

func TestCargoIndexShadowCandidateSurvivesOuterTransaction(t *testing.T) {
	for _, outcome := range []string{"commit", "rollback", "audit_failure"} {
		t.Run(outcome, func(t *testing.T) {
			enableObservation(t)
			setting.EnterpriseAuthz.Enforce = false
			_, err := db.GetEngine(t.Context()).ID(2).Cols("internal_usage").Update(&repo_model.Repository{InternalUsage: repo_model.InternalUsageCargoIndex})
			require.NoError(t, err)
			require.NoError(t, db.Insert(t.Context(), &authz_model.CargoIndexSource{IndexRepoID: 2, SourceRepoID: 1}, &authz_model.FeatureGrant{FeatureKey: authz.FeaturePackages, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
			idx := unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
			before := idx.Description
			hook := &cargoAuditFailure{enabled: outcome == "audit_failure"}
			db.GetXORMEngineForTesting().AddHook(hook)
			t.Cleanup(func() { hook.enabled = false })
			abort := errors.New("native rollback")
			err = db.WithTx(t.Context(), func(tx context.Context) error {
				require.NoError(t, RequireCargoIndexFeature(tx, idx))
				_, err := db.GetEngine(tx).ID(idx.ID).Cols("description").Update(&repo_model.Repository{Description: "native committed"})
				if err != nil {
					return err
				}
				if outcome == "rollback" {
					return abort
				}
				return nil
			})
			if outcome == "rollback" {
				require.ErrorIs(t, err, abort)
			} else {
				require.NoError(t, err)
			}
			idx = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
			if outcome == "rollback" {
				require.Equal(t, before, idx.Description)
			} else {
				require.Equal(t, "native committed", idx.Description)
			}
			var events []*audit_model.Event
			require.NoError(t, db.GetEngine(t.Context()).Where("action=? AND scope_id=?", audit_model.EnterpriseFeatureDecision, idx.ID).Find(&events))
			count := 0
			for _, event := range events {
				if strings.Contains(event.Metadata, `"derived_index":"cargo"`) {
					count++
				}
			}
			if outcome == "audit_failure" {
				require.Zero(t, count)
			} else {
				require.Equal(t, 1, count)
			}
		})
	}
}

type cargoAuditFailure struct{ enabled bool }

func (h *cargoAuditFailure) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.enabled && strings.HasPrefix(c.SQL, "INSERT") && strings.Contains(c.SQL, "audit_event") {
		return c.Ctx, errors.New("audit storage unavailable")
	}
	return c.Ctx, nil
}
func (*cargoAuditFailure) AfterProcess(*contexts.ContextHook) error { return nil }

type cargoCandidateQueries struct {
	enabled        bool
	sourceQueries  int
	featureQueries int
}

func (h *cargoCandidateQueries) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.enabled {
		if strings.HasPrefix(c.SQL, "SELECT") && strings.Contains(c.SQL, "enterprise_cargo_index_source") {
			h.sourceQueries++
		}
		if strings.Contains(c.SQL, "enterprise_feature_") || strings.Contains(c.SQL, "enterprise_cargo_index_source") {
			h.featureQueries++
		}
	}
	return c.Ctx, nil
}

func (*cargoCandidateQueries) AfterProcess(*contexts.ContextHook) error { return nil }
