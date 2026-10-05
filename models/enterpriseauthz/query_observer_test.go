// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"gitea.dev/models/db"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"
	"xorm.io/builder"
	"xorm.io/xorm/contexts"
)

func TestObserveFeatureQueryModesAndErrors(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true}))
	candidate := RepoFeatureCandidateCond(t.Context(), authz.FeatureIssues, "issue.repo_id")
	counter := authz.FeatureQueryCandidate.WithLabelValues(string(authz.FeatureIssues), "error")
	before := queryCounter(counter)
	calls := 0
	probe := func(ctx context.Context, denied builder.Cond) (bool, error) {
		calls++
		deadline, ok := ctx.Deadline()
		require.True(t, ok)
		require.LessOrEqual(t, time.Until(deadline), time.Second)
		require.True(t, denied.IsValid())
		return false, errors.New("candidate infrastructure unavailable")
	}
	ObserveFeatureQuery(t.Context(), authz.FeatureIssues, candidate, probe)
	require.Equal(t, 1, calls)
	require.InDelta(t, before+1, queryCounter(counter), 0)
	for _, mode := range []setting.EnterpriseAuthzConfig{{}, {Enabled: true, Enforce: true}} {
		setting.EnterpriseAuthz = mode
		ObserveFeatureQuery(t.Context(), authz.FeatureIssues, candidate, probe)
	}
	require.Equal(t, 1, calls)
	require.InDelta(t, before+1, queryCounter(counter), 0)
	setting.EnterpriseAuthz = setting.EnterpriseAuthzConfig{Enabled: true}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	ObserveFeatureQuery(canceled, authz.FeatureIssues, candidate, probe)
	require.Equal(t, 1, calls)
	require.InDelta(t, before+2, queryCounter(counter), 0)
	_, err := db.GetEngine(t.Context()).Where("key=?", authz.FeatureIssues).Delete(new(FeatureDefinition))
	require.NoError(t, err)
	ObserveFeatureQuery(t.Context(), authz.FeatureIssues, candidate, probe)
	require.Equal(t, 1, calls)
	require.InDelta(t, before+3, queryCounter(counter), 0)
}

func queryCounter(counter prometheus.Counter) float64 {
	var metric dto.Metric
	if err := counter.Write(&metric); err != nil {
		panic(err)
	}
	return metric.GetCounter().GetValue()
}

func TestObserveFeatureQueryDoesNotReadWhenDisabled(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{}))
	hook := &queryObserverReadHook{enabled: true}
	db.GetXORMEngineForTesting().AddHook(hook)
	t.Cleanup(func() { hook.enabled = false })
	ObserveFeatureQuery(t.Context(), authz.FeatureIssues, RepoFeatureCandidateCond(t.Context(), authz.FeatureIssues, "issue.repo_id"), func(context.Context, builder.Cond) (bool, error) { t.Fatal("disabled probe"); return false, nil })
	require.Zero(t, hook.reads)
}

type queryObserverReadHook struct {
	enabled bool
	reads   int
}

func (h *queryObserverReadHook) BeforeProcess(c *contexts.ContextHook) (context.Context, error) {
	if h.enabled && strings.Contains(c.SQL, "enterprise_feature_") {
		h.reads++
	}
	return c.Ctx, nil
}
func (*queryObserverReadHook) AfterProcess(*contexts.ContextHook) error { return nil }

func TestObserveFeatureQueryInTransactionPreservesNative(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz, setting.EnterpriseAuthzConfig{Enabled: true}))
	counter := authz.FeatureQueryCandidate.WithLabelValues(string(authz.FeatureIssues), "error")
	before := queryCounter(counter)
	require.NoError(t, db.WithTx(t.Context(), func(tx context.Context) error {
		ObserveFeatureQuery(tx, authz.FeatureIssues, RepoFeatureCandidateCond(tx, authz.FeatureIssues, "issue.repo_id"), func(context.Context, builder.Cond) (bool, error) {
			t.Fatal("business transaction must not be independently observed")
			return false, nil
		})
		_, err := db.GetEngine(tx).Table("repository").Where("id=?", 1).Update(map[string]any{"description": "native observation unchanged"})
		return err
	}))
	require.InDelta(t, before+1, queryCounter(counter), 0)
	var row struct{ Description string }
	found, err := db.GetEngine(t.Context()).Table("repository").Where("id=?", 1).Get(&row)
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "native observation unchanged", row.Description)
}
