// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package admin

import (
	"net/http"
	"net/url"
	"strconv"

	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	api "gitea.dev/modules/structs"
	"gitea.dev/modules/timeutil"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"
)

type authzDecisionView struct {
	*api.EnterpriseAuthzDecision
	ActorName     string
	RepoName      string
	Mismatch      string
	DeletedRepo   bool
	ArchivedKnown bool
	Archived      bool
}

func authzDecisionViewModel(ctx *context.Context, record *api.EnterpriseAuthzDecision) (*authzDecisionView, error) {
	view := &authzDecisionView{EnterpriseAuthzDecision: record, Mismatch: "unknown"}
	if record.Snapshot != nil && record.Snapshot.Archived != nil {
		view.ArchivedKnown = true
		view.Archived = *record.Snapshot.Archived
	}
	if mismatch, known := authz_service.NativeMismatch(record.CandidateDecision, authz_service.NativeOutcome(record.NativeOutcome)); known {
		view.Mismatch = strconv.FormatBool(mismatch)
	}
	row, err := repo_model.GetRepositoryByID(ctx, record.RepoID)
	if repo_model.IsErrRepoNotExist(err) {
		view.DeletedRepo = true
		view.RepoName = ctx.Locale.TrString("admin.enterprise_authz.deleted_repo")
	} else if err != nil {
		return nil, authz_service.ErrPolicyStorage
	}
	if !view.DeletedRepo {
		if err := row.LoadOwner(ctx); err != nil {
			return nil, authz_service.ErrPolicyStorage
		}
		view.RepoName = row.FullName()
	}
	actor, err := user_model.GetUserByID(ctx, record.ActorID)
	if user_model.IsErrUserNotExist(err) {
		view.ActorName = ctx.Locale.TrString("admin.enterprise_authz.deleted_user")
		if record.ActorID <= 0 {
			_, actor, err = user_model.GetPossibleUserByID(ctx, record.ActorID)
			if err != nil {
				return nil, authz_service.ErrPolicyStorage
			}
			view.ActorName = actor.Name
		}
	} else if err != nil {
		return nil, authz_service.ErrPolicyStorage
	} else {
		view.ActorName = actor.Name
	}
	return view, nil
}

func authzHistoryInt(query url.Values, key string) (int64, error) {
	values := query[key]
	if len(values) == 0 || len(values) == 1 && values[0] == "" {
		return 0, nil
	}
	if len(values) != 1 {
		return 0, authz_service.ErrInvalidPolicy
	}
	value, err := strconv.ParseInt(values[0], 10, 64)
	if err != nil {
		return 0, authz_service.ErrInvalidPolicy
	}
	return value, nil
}

func authzHistoryTime(query url.Values, key string) (int64, error) {
	values := query[key]
	if len(values) == 0 || len(values) == 1 && values[0] == "" {
		return 0, nil
	}
	if len(values) != 1 {
		return 0, authz_service.ErrInvalidPolicy
	}
	value := values[0]
	number, err := strconv.ParseInt(value, 10, 64)
	if err == nil {
		if number < 0 || number > 253402300799 {
			return 0, authz_service.ErrInvalidPolicy
		}
		return number, nil
	}
	return 0, authz_service.ErrInvalidPolicy
}

func authzHistoryTimeText(value int64) string {
	if value == 0 {
		return ""
	}
	return strconv.FormatInt(value, 10)
}

func EnterpriseAuthzDecisions(ctx *context.Context) {
	ui := authzUI(ctx)
	if ui == nil {
		return
	}
	ctx.Data["AuthzTab"] = "decisions"
	ctx.Data["AuthzCandidates"] = []string{"allow", "deny", "error"}
	query := ctx.Req.URL.Query()
	nums := make(map[string]int64, 6)
	for _, key := range []string{"page", "limit", "actor_id", "repo_id"} {
		value, err := authzHistoryInt(query, key)
		if err != nil {
			authzError(ctx, err)
			return
		}
		nums[key] = value
	}
	for _, key := range []string{"since", "until"} {
		value, err := authzHistoryTime(query, key)
		if err != nil {
			authzError(ctx, err)
			return
		}
		nums[key] = value
	}
	if nums["page"] < 0 || nums["limit"] < 0 || nums["limit"] > 100 {
		authzError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	page, limit := max(int64(1), nums["page"]), nums["limit"]
	if limit == 0 {
		limit = 20
	}
	// 服务端分页不接受会溢出的 offset。
	if page-1 > int64(^uint(0)>>1)/limit {
		authzError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	options := authz_service.DecisionListOptions{PolicyListOptions: authz_service.PolicyListOptions{Page: int(page), Limit: int(limit)}, RepoID: nums["repo_id"], Action: authz.Action(query.Get("action")), CandidateDecision: query.Get("decision"), Since: timeutil.TimeStamp(nums["since"]), Until: timeutil.TimeStamp(nums["until"])}
	if query.Get("actor_id") != "" {
		actorID := nums["actor_id"]
		options.ActorID = &actorID
	}
	for _, key := range []string{"action", "decision"} {
		if len(query[key]) > 1 {
			authzError(ctx, authz_service.ErrInvalidPolicy)
			return
		}
	}
	records, total, err := ui.Decisions(options)
	if err != nil {
		authzError(ctx, err)
		return
	}
	views := make([]*authzDecisionView, 0, len(records))
	for i := range records {
		dto, err := authz_service.DecisionDTO(&records[i])
		if err != nil {
			authzError(ctx, err)
			return
		}
		view, err := authzDecisionViewModel(ctx, dto)
		if err != nil {
			authzError(ctx, err)
			return
		}
		views = append(views, view)
	}
	if !authzPicker(ctx, ui, "AuthzHistoryActorPicker", "authz-history-actor", "actor_id", "history_actor", "history_actor", query.Get("actor_id"), false) || !authzPicker(ctx, ui, "AuthzHistoryRepoPicker", "authz-history-repo", "repo_id", "history_repo", "history_repo", query.Get("repo_id"), false) {
		return
	}
	ctx.Data["AuthzHistorySince"], ctx.Data["AuthzHistoryUntil"] = authzHistoryTimeText(nums["since"]), authzHistoryTimeText(nums["until"])
	ctx.Data["AuthzDecisions"], ctx.Data["AuthzTotal"], ctx.Data["AuthzHistoryQuery"], ctx.Data["AuthzHistoryLimit"] = views, total, query, limit
	if page > 1 {
		query.Set("page", strconv.FormatInt(page-1, 10))
		ctx.Data["AuthzHistoryPrevious"] = "?" + query.Encode()
	}
	if page <= total/limit && (page-1)*limit+int64(len(records)) < total {
		query.Set("page", strconv.FormatInt(page+1, 10))
		ctx.Data["AuthzHistoryNext"] = "?" + query.Encode()
	}
	authzRender(ctx, http.StatusOK, "admin/enterpriseauthz/decisions")
}

func EnterpriseAuthzDecision(ctx *context.Context) {
	ui := authzUI(ctx)
	if ui == nil {
		return
	}
	ctx.Data["AuthzTab"] = "decisions"
	id, err := strconv.ParseInt(ctx.PathParam("id"), 10, 64)
	if err != nil || id <= 0 {
		authzError(ctx, authz_service.ErrInvalidPolicy)
		return
	}
	record, err := ui.Decision(id)
	if err != nil {
		authzError(ctx, err)
		return
	}
	dto, err := authz_service.DecisionDTO(record)
	if err != nil {
		authzError(ctx, err)
		return
	}
	view, err := authzDecisionViewModel(ctx, dto)
	if err != nil {
		authzError(ctx, err)
		return
	}
	ctx.Data["AuthzDecision"] = view
	authzRender(ctx, http.StatusOK, "admin/enterpriseauthz/decision")
}
