// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var EnterpriseAuthzObservationFailed = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "enterprise_authz_observation_failed_total",
	Help: "Enterprise authorization shadow observation gaps by bounded safe reason.",
}, []string{"reason"})

var EnterpriseAuthzExecutionFailed = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "enterprise_authz_execution_failed_total",
	Help: "Enterprise authorization execution rejections and evidence gaps by bounded safe reason.",
}, []string{"reason"})

var EnterpriseAuthzExecutionDecision = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "enterprise_authz_execution_decision_total",
	Help: "Enterprise authorization admission decisions by action and actual authorization result.",
}, []string{"action", "decision"})

var EnterpriseAuthzExecutionDuration = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "enterprise_authz_execution_duration_seconds",
	Help:    "High-risk admission preparation, snapshot evaluation and evidence persistence duration.",
	Buckets: []float64{0.01, 0.05, 0.1, 0.2, 0.5, 1},
})

var EnterpriseFeatureDecision = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "enterprise_feature_decision_total", Help: "Feature admission decisions by bounded catalog key, mode and decision.",
}, []string{"feature_key", "mode", "decision"})

var EnterpriseFeatureFailure = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "enterprise_feature_failure_total", Help: "Feature policy infrastructure failures and unavailable evidence by bounded reason.",
}, []string{"reason"})
