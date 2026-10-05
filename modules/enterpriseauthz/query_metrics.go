// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var FeatureQueryFallback = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "enterprise_feature_query_fallback_total",
	Help: "Aggregate feature query native fallbacks by bounded infrastructure reason, not per-object admission evidence.",
}, []string{"reason"})

var FeatureQueryCandidate = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "enterprise_feature_query_candidate_total",
	Help: "Shadow aggregate query candidates by bounded feature and result; not per-object authorization evidence.",
}, []string{"feature_key", "result"})
