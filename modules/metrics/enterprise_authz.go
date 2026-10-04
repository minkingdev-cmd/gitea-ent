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
