// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"time"

	"gitea.dev/models/db"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"

	"xorm.io/builder"
)

// ObserveFeatureQuery 不改变原生查询，也不产生逐对象授权证据。
func ObserveFeatureQuery(ctx context.Context, key authz.FeatureKey, candidate builder.Cond, probe func(context.Context, builder.Cond) (bool, error)) {
	if !setting.EnterpriseAuthz.Enabled || setting.EnterpriseAuthz.Enforce {
		return
	}
	if _, ok := authz.LookupFeature(key); !ok {
		return
	}
	result := "would_allow"
	observed, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	err := db.WithIndependentReadTx(observed, func(tx context.Context) error {
		definition, exists, err := db.Get[FeatureDefinition](tx, builder.Eq{"key": key})
		if err != nil || !exists || definition.Validate() != nil {
			return ErrFeatureQueryUnavailable
		}
		denied, err := probe(tx, builder.Not{candidate})
		if denied {
			result = "would_deny"
		}
		return err
	})
	if err != nil || observed.Err() != nil {
		result = "error"
	}
	authz.FeatureQueryCandidate.WithLabelValues(string(key), result).Inc()
}
