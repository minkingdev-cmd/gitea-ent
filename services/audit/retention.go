// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package audit

import (
	"context"
	"time"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
)

func DeleteOldEvents(ctx context.Context, olderThan time.Duration) error {
	if olderThan <= 0 {
		return nil
	}
	cutoff := time.Now().Add(-olderThan).Unix()
	for {
		removed := 0
		err := db.WithTx(ctx, func(tx context.Context) error {
			for _, table := range []struct {
				bean      any
				timestamp string
			}{
				{new(audit_model.Event), "timestamp_unix"},
				{new(authz_model.DecisionRecord), "created_unix"},
			} {
				var ids []int64
				if err := db.GetEngine(tx).Table(table.bean).Cols("id").Where(table.timestamp+" < ?", cutoff).OrderBy("id").Limit(1000).Find(&ids); err != nil {
					return err
				}
				if len(ids) == 0 {
					continue
				}
				if _, err := db.GetEngine(tx).In("id", ids).Delete(table.bean); err != nil {
					return err
				}
				removed += len(ids)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if removed == 0 {
			return nil
		}
	}
}
