// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package mirror

import (
	"context"
	"fmt"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/util"
	"gitea.dev/services/audit"
)

type pullMirrorSyncKey struct{}

type pullMirrorSyncMaintenance struct {
	mirrorID, repoID, ownerID int64
	admitted                  bool
}

func pullMirrorEnforceEnabled() bool {
	return setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce
}

func requirePullMirrorSyncMaintenance(ctx context.Context, m *repo_model.Mirror) error {
	if !pullMirrorEnforceEnabled() {
		return nil
	}
	marker, ok := ctx.Value(pullMirrorSyncKey{}).(*pullMirrorSyncMaintenance)
	if !ok || marker == nil || marker.admitted || m == nil || m.Repo == nil ||
		marker.mirrorID <= 0 || marker.repoID <= 0 || marker.ownerID <= 0 ||
		marker.mirrorID != m.ID || marker.repoID != m.RepoID || marker.repoID != m.Repo.ID || marker.ownerID != m.Repo.OwnerID {
		return util.ErrPermissionDenied
	}
	var current *repo_model.Mirror
	err := db.WithIndependentTx(ctx, func(tx context.Context) error {
		var err error
		current, err = repo_model.GetMirrorByRepoID(tx, marker.repoID)
		if err != nil {
			return err
		}
		if current.ID != marker.mirrorID {
			return util.ErrPermissionDenied
		}
		current.Repo, err = repo_model.GetRepositoryByID(tx, marker.repoID)
		if err != nil {
			return err
		}
		if !current.Repo.IsMirror || current.Repo.OwnerID != marker.ownerID {
			return util.ErrPermissionDenied
		}
		return audit.RecordEvent(audit.WithOrigin(tx, audit_model.OriginSystem), audit.RecordParams{
			Action:          audit_model.RepositoryMirrorSync,
			Actor:           audit_model.EntityRef{Type: audit_model.ScopeSystem, Name: "mirror-pull-sync"},
			ActorCredential: fmt.Sprintf("mirror:%d", current.ID),
			Scope:           audit.ScopeFromRepository(current.Repo),
			Metadata: map[string]any{
				"maintenance": "mirror-pull-sync", "mirror_id": current.ID,
				"repo_id": current.RepoID, "owner_id": current.Repo.OwnerID,
			},
		})
	})
	if err != nil {
		return err
	}
	*m = *current
	marker.admitted = true
	return nil
}
