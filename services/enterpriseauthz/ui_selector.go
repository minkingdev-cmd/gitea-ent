// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"slices"
	"strconv"
	"strings"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/organization"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/optional"
	"gitea.dev/modules/util"

	"xorm.io/builder"
)

type UISelectorItem struct {
	ID      int64              `json:"id"`
	Label   string             `json:"label"`
	Scope   *authz_model.Scope `json:"scope,omitempty"`
	Context string             `json:"context,omitempty"`
	Missing bool               `json:"missing,omitempty"`
}

func (ui *ManagementUI) Select(kind, keyword string, options PolicyListOptions) ([]UISelectorItem, int64, error) {
	return ui.selectItems(kind, keyword, options, nil)
}

func (ui *ManagementUI) Selection(kind string, id int64) (*UISelectorItem, error) {
	rows, _, err := ui.selectItems(kind, "", PolicyListOptions{Limit: 1}, &id)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, util.ErrNotExist
	}
	return &rows[0], nil
}

func (ui *ManagementUI) selectItems(kind, keyword string, options PolicyListOptions, id *int64) ([]UISelectorItem, int64, error) {
	if err := ui.authorize(); err != nil {
		return nil, 0, err
	}
	limit, offset, err := options.pagination()
	if err != nil || len(keyword) > 128 {
		return nil, 0, ErrInvalidPolicy
	}
	resolved, err := resolveManagementScope(ui.ctx, ui.actor, ui.scope)
	if err != nil {
		return nil, 0, safePolicyError(err)
	}
	items := make([]UISelectorItem, 0)
	list := db.ListOptions{Page: max(1, options.Page), PageSize: limit}
	var total int64
	switch kind {
	case "user", "org":
		typ := user_model.UserTypeIndividual
		if kind == "org" {
			typ = user_model.UserTypeOrganization
		}
		opts := user_model.SearchUserOptions{ListOptions: list, Actor: resolved.actor, Types: []user_model.UserType{typ}, Keyword: keyword, OrderBy: db.SearchOrderByID}
		if kind == "user" {
			opts.IsActive = optional.Some(true)
			opts.IsProhibitLogin = optional.Some(false)
			opts.IsRestricted = optional.Some(false)
		}
		if kind == "org" && ui.scope.Type != authz_model.ScopeSystem {
			opts.UID = resolved.ownerID
		}
		if id != nil {
			if *id <= 0 || opts.UID != 0 && opts.UID != *id {
				return items, 0, nil
			}
			opts.UID = *id
		}
		rows, count, e := user_model.SearchUsers(ui.ctx, opts)
		total, err = count, e
		for _, r := range rows {
			items = append(items, UISelectorItem{ID: r.ID, Label: r.Name})
		}
	case "repo":
		if id != nil {
			row, exists, e := db.GetByID[repo_model.Repository](ui.ctx, *id)
			if e != nil {
				return nil, 0, ErrPolicyStorage
			}
			if !exists {
				return items, 0, nil
			}
			if e := row.LoadOwner(ui.ctx); e != nil {
				return nil, 0, ErrPolicyStorage
			}
			return []UISelectorItem{{ID: row.ID, Label: row.FullName()}}, 1, nil
		}
		rows, count, e := repo_model.SearchRepository(ui.ctx, repo_model.SearchRepoOptions{ListOptions: list, Actor: resolved.actor, Keyword: keyword, Private: true, OrderBy: db.SearchOrderByID})
		total, err = count, e
		if err == nil {
			err = rows.LoadOwners(ui.ctx)
		}
		for _, r := range rows {
			items = append(items, UISelectorItem{ID: r.ID, Label: r.FullName()})
		}
	case "team":
		cond := builder.NewCond()
		if id != nil {
			cond = cond.And(builder.Eq{"id": *id})
		}
		if keyword != "" {
			cond = cond.And(builder.Like{"lower_name", strings.ToLower(keyword)})
		}
		if ui.scope.Type != authz_model.ScopeSystem {
			cond = cond.And(builder.Eq{"org_id": resolved.ownerID})
		}
		if resolved.repo != nil {
			cond = cond.And(builder.Or(builder.Eq{"includes_all_repositories": true}, builder.In("id", builder.Select("team_id").From("team_repo").Where(builder.Eq{"repo_id": resolved.repo.ID, "org_id": resolved.ownerID}))))
		}
		var rows []organization.Team
		total, err = db.GetEngine(ui.ctx).Where(cond).OrderBy("id").Limit(limit, offset).FindAndCount(&rows)
		for _, r := range rows {
			org, exists, e := db.GetByID[user_model.User](ui.ctx, r.OrgID)
			if e != nil {
				return nil, 0, ErrPolicyStorage
			}
			label := r.Name
			if exists {
				label = org.Name + " / " + label
			}
			items = append(items, UISelectorItem{ID: r.ID, Label: label})
		}
	case "role":
		cond := roleVisibility(resolved)
		if id != nil {
			cond = cond.And(builder.Eq{"id": *id})
		}
		if keyword != "" {
			cond = cond.And(builder.Like{"lower_name", strings.ToLower(keyword)})
		}
		if ui.scope.Type != authz_model.ScopeSystem {
			cond = cond.And(builder.Or(builder.IsNull{"builtin_key"}, builder.Neq{"builtin_key": "platform-admin"}))
		}
		var rows []authz_model.RoleDefinition
		total, err = db.GetEngine(ui.ctx).Where(cond).OrderBy("id").Limit(limit, offset).FindAndCount(&rows)
		for _, r := range rows {
			scope := r.Scope()
			items = append(items, UISelectorItem{ID: r.ID, Label: r.Name, Scope: &scope})
		}
	case "history_repo", "history_actor":
		return ui.selectHistory(resolved, kind, keyword, options, id)
	default:
		return nil, 0, ErrInvalidPolicy
	}
	if err != nil {
		return nil, 0, ErrPolicyStorage
	}
	return items, total, nil
}

func (ui *ManagementUI) selectHistory(resolved *managementScope, kind, keyword string, options PolicyListOptions, id *int64) ([]UISelectorItem, int64, error) {
	limit, offset, err := options.pagination()
	if err != nil {
		return nil, 0, err
	}
	cond, err := decisionScope(ui.ctx, resolved, 0)
	if err != nil {
		return nil, 0, safePolicyError(err)
	}
	column := "repo_id"
	if kind == "history_actor" {
		column = "actor_id"
	}
	if id != nil {
		cond = cond.And(builder.Eq{column: *id})
	}
	if keyword != "" {
		text := strings.ToLower(keyword)
		var candidates *builder.Builder
		if kind == "history_repo" {
			names := builder.Like{"lower_name", text}
			nameCond := builder.Cond(names)
			if owner, repo, ok := strings.Cut(text, "/"); ok {
				nameCond = builder.And(builder.Like{"lower_name", repo}, builder.In("owner_id", builder.Select("id").From("`user`").Where(builder.Like{"lower_name", owner})))
			}
			candidates = builder.Select("id").From("repository").Where(nameCond)
		} else {
			candidates = builder.Select("id").From("`user`").Where(builder.Or(builder.Like{"lower_name", text}, builder.Like{"full_name", keyword}))
		}
		search := builder.In(column, candidates)
		if kind == "history_actor" {
			if slices.ContainsFunc([]string{"anonymous", "machine", "runner"}, func(alias string) bool { return strings.Contains(alias, text) }) {
				search = search.Or(builder.Eq{column: 0})
			}

			for _, actor := range []*user_model.User{user_model.NewGhostUser(), user_model.NewActionsUser(), user_model.NewDeployKeyUser(), user_model.NewCliUser(), user_model.NewAuthSourceUser()} {
				if strings.Contains(actor.LowerName, text) || strings.Contains(strings.ToLower(actor.FullName), text) {
					search = search.Or(builder.Eq{column: actor.ID})
				}
			}
		}
		if number, e := strconv.ParseInt(keyword, 10, 64); e == nil {
			search = search.Or(builder.Eq{column: number})
		}
		cond = cond.And(search)
	}
	ids := builder.Select("DISTINCT " + column).From("enterprise_authz_decision").Where(cond)
	countSQL, args, err := builder.Select("COUNT(*) AS total").From(ids, "history_objects").ToSQL()
	if err != nil {
		return nil, 0, ErrPolicyStorage
	}
	var count struct{ Total int64 }
	if _, err = db.GetEngine(ui.ctx).SQL(countSQL, args...).Get(&count); err != nil {
		return nil, 0, ErrPolicyStorage
	}
	rows := make([]UISelectorItem, 0)
	err = db.GetEngine(ui.ctx).Table("enterprise_authz_decision").Where(cond).Select(column+" AS id").GroupBy(column).OrderBy(column).Limit(limit, offset).Find(&rows)
	if err != nil {
		return nil, 0, ErrPolicyStorage
	}
	for i := range rows {
		if kind == "history_repo" {
			row, exists, e := db.GetByID[repo_model.Repository](ui.ctx, rows[i].ID)
			if e != nil {
				return nil, 0, ErrPolicyStorage
			}
			rows[i].Missing = !exists
			if exists {
				if e = row.LoadOwner(ui.ctx); e != nil {
					return nil, 0, ErrPolicyStorage
				}
				rows[i].Label = row.FullName()
			}
		} else {
			row, exists, e := db.GetByID[user_model.User](ui.ctx, rows[i].ID)
			if e != nil {
				return nil, 0, ErrPolicyStorage
			}
			if rows[i].ID < 0 {
				_, row, e = user_model.GetPossibleUserByID(ui.ctx, rows[i].ID)
				if e != nil {
					return nil, 0, ErrPolicyStorage
				}
				exists = true
			}
			rows[i].Missing = !exists
			if exists {
				rows[i].Label = row.Name
			}
		}
	}
	return rows, count.Total, nil
}
