// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"slices"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/timeutil"
	"gitea.dev/modules/util"

	"xorm.io/builder"
)

type DecisionListOptions struct {
	PolicyListOptions
	ActorID           *int64
	RepoID            int64
	Action            authz.Action
	CandidateDecision string
	Since, Until      timeutil.TimeStamp
}

func ListDecisions(ctx context.Context, actor *user_model.User, scope authz_model.Scope, options DecisionListOptions) ([]authz_model.DecisionRecord, int64, error) {
	if _, err := authorizePolicy(ctx, actor, scope); err != nil {
		return nil, 0, safePolicyError(err)
	}
	limit, offset, err := options.pagination()
	if err != nil {
		return nil, 0, err
	}
	if err := options.validate(); err != nil {
		return nil, 0, err
	}
	records := make([]authz_model.DecisionRecord, 0)
	var total int64
	err = db.WithIndependentReadTx(ctx, func(tx context.Context) error {
		resolved, err := authorizePolicy(tx, actor, scope)
		if err != nil {
			return err
		}
		cond, err := decisionScope(tx, resolved, options.RepoID)
		if err != nil {
			return err
		}
		if options.ActorID != nil {
			cond = cond.And(builder.Eq{"actor_id": *options.ActorID})
		}
		if options.Action != "" {
			cond = cond.And(builder.Eq{"action": options.Action})
		}
		if options.CandidateDecision != "" {
			cond = cond.And(builder.Eq{"candidate_decision": options.CandidateDecision})
		}
		if options.Since != 0 {
			cond = cond.And(builder.Gte{"created_unix": options.Since})
		}
		if options.Until != 0 {
			cond = cond.And(builder.Lte{"created_unix": options.Until})
		}
		total, err = db.GetEngine(tx).Where(cond).OrderBy("created_unix DESC, id DESC").Limit(limit, offset).FindAndCount(&records)
		return err
	})
	if err != nil {
		return nil, 0, safePolicyError(err)
	}
	return records, total, nil
}

func GetDecision(ctx context.Context, actor *user_model.User, scope authz_model.Scope, id int64) (*authz_model.DecisionRecord, error) {
	if _, err := authorizePolicy(ctx, actor, scope); err != nil {
		return nil, safePolicyError(err)
	}
	if id <= 0 {
		return nil, ErrInvalidPolicy
	}
	var record *authz_model.DecisionRecord
	err := db.WithIndependentReadTx(ctx, func(tx context.Context) error {
		resolved, err := authorizePolicy(tx, actor, scope)
		if err != nil {
			return err
		}
		cond, err := decisionScope(tx, resolved, 0)
		if err != nil {
			return err
		}
		var exists bool
		record, exists, err = db.Get[authz_model.DecisionRecord](tx, cond.And(builder.Eq{"id": id}))
		if err != nil {
			return err
		}
		if !exists {
			return util.ErrNotExist
		}
		return nil
	})
	if err != nil {
		return nil, safePolicyError(err)
	}
	return record, nil
}

func (o DecisionListOptions) validate() error {
	if o.RepoID < 0 || o.Since < 0 || o.Until < 0 || o.Since != 0 && o.Until != 0 && o.Since > o.Until {
		return ErrInvalidPolicy
	}
	if o.ActorID != nil && *o.ActorID < 0 && !slices.Contains([]int64{user_model.GhostUserID, user_model.ActionsUserID, user_model.DeployKeyUserID, user_model.CliUserID, user_model.AuthSourceUserID}, *o.ActorID) {
		return ErrInvalidPolicy
	}
	if o.Action != "" {
		if _, exists := authz.LookupAction(o.Action); !exists {
			return ErrInvalidPolicy
		}
	}
	if o.CandidateDecision != "" && !slices.Contains([]string{"allow", "deny", "error"}, o.CandidateDecision) {
		return ErrInvalidPolicy
	}
	return nil
}

func decisionScope(ctx context.Context, resolved *managementScope, repoID int64) (builder.Cond, error) {
	cond := builder.NewCond()
	switch resolved.scope.Type {
	case authz_model.ScopeRepo:
		if repoID != 0 && repoID != resolved.repo.ID {
			return nil, util.ErrNotExist
		}
		cond = builder.Eq{"repo_id": resolved.repo.ID}
	case authz_model.ScopeOrg:
		if repoID != 0 {
			exists, err := db.GetEngine(ctx).Where("id = ? AND owner_id = ?", repoID, resolved.ownerID).Exist(new(repo_model.Repository))
			if err != nil {
				return nil, err
			}
			if !exists {
				return nil, util.ErrNotExist
			}
		}
		cond = builder.In("repo_id", builder.Select("id").From("repository").Where(builder.Eq{"owner_id": resolved.ownerID}))
	}
	if repoID != 0 {
		cond = cond.And(builder.Eq{"repo_id": repoID})
	}
	return cond, nil
}
