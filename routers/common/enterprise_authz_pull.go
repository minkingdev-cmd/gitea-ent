// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package common

import (
	stdcontext "context"
	"errors"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"time"

	auth_model "gitea.dev/models/auth"
	"gitea.dev/models/db"
	issues_model "gitea.dev/models/issues"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/reqctx"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/web/types"
	"gitea.dev/services/context"
	authz_service "gitea.dev/services/enterpriseauthz"

	"xorm.io/builder"
)

type PullMutationTarget int

const (
	PullTargetRepository PullMutationTarget = iota
	PullTargetIndex
	PullTargetReview
	PullTargetComment
	PullTargetReply
	PullTargetWebReview
	PullTargetWebComment
	PullTargetReviewContent
)

type (
	pullMutationKey   struct{}
	pullMutationRoute struct {
		action authz.Action
		target PullMutationTarget
	}
)

func PullMutationRoute(action authz.Action, target PullMutationTarget) types.PreMiddlewareProvider {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			if setting.EnterpriseAuthz.Enabled {
				reqctx.GetRequestDataStore(req.Context()).SetContextValue(pullMutationKey{}, pullMutationRoute{action: action, target: target})
			}
			next.ServeHTTP(w, req)
		})
	}
}

func ObserveMarkedPullDenial(base *context.Base, actor *user_model.User, repo *context.Repository, source string) {
	if !setting.EnterpriseAuthz.Enabled {
		return
	}
	if route, ok := base.Value(pullMutationKey{}).(pullMutationRoute); ok {
		ObservePullDenial(base, actor, repo, route.action, route.target, source)
	}
}

func ObserveMarkedPullValidationFailure(base *context.Base, actor *user_model.User, repo *context.Repository) {
	if !setting.EnterpriseAuthz.Enabled {
		return
	}
	if route, ok := base.Value(pullMutationKey{}).(pullMutationRoute); ok {
		observePullRejection(base, actor, repo, route.action, route.target, "api", true)
	}
}

func ObservePullDenial(base *context.Base, actor *user_model.User, repo *context.Repository, action authz.Action, target PullMutationTarget, source string) {
	observePullRejection(base, actor, repo, action, target, source, false)
}

func observePullRejection(base *context.Base, actor *user_model.User, repo *context.Repository, action authz.Action, target PullMutationTarget, source string, validationFailed bool) {
	if !setting.EnterpriseAuthz.Enabled || actor == nil || !repo.Permission.CanRead(unit.TypePullRequests) || (source == "api" && target != PullTargetReviewContent || action == authz.CreatePullRequest) && !repo.Permission.CanRead(unit.TypeCode) {
		return
	}
	id := base.PathParamInt64("id")
	ceiling := RepoCredentialCeiling(base, actor)
	if source == "api" && target == PullTargetReviewContent {
		ceiling = PullReviewCommentCredentialCeiling(base, actor)
	}
	observe := authz_service.ObserveGuardDenial
	if validationFailed {
		observe = authz_service.ObserveValidationFailure
	}
	observe(base, authz_service.EvaluateInput{
		Actor: actor, Repo: repo.Repository, Permission: &repo.Permission,
		Credential: ceiling, Action: action, ConditionContext: authz.ConditionContext{Source: source},
	}, func(ctx stdcontext.Context) (bool, error) {
		if target == PullTargetWebReview || target == PullTargetWebComment {
			key := "review_id"
			if target == PullTargetWebComment {
				key = "comment_id"
			}
			var err error
			id, err = pullGuardFormID(ctx, base, key)
			if err != nil {
				return false, err
			}
		}
		scope := builder.Eq{"issue.repo_id": repo.Repository.ID, "issue.is_pull": true}
		switch target {
		case PullTargetRepository:
			return true, nil
		case PullTargetIndex:
			return db.GetEngine(ctx).Table("issue").Where(scope).And(builder.Eq{"issue.`index`": base.PathParamInt64("index")}).Exist()
		case PullTargetReview, PullTargetWebReview:
			if id <= 0 {
				return false, nil
			}
			query := db.GetEngine(ctx).Table("review").Join("INNER", "issue", "issue.id = review.issue_id").Where(scope).And(builder.Eq{"review.id": id})
			if target == PullTargetReview {
				query.And(builder.Eq{"issue.`index`": base.PathParamInt64("index")})
			}
			return query.Exist()
		case PullTargetComment, PullTargetReply, PullTargetWebComment, PullTargetReviewContent:
			if id <= 0 {
				return false, nil
			}
			query := db.GetEngine(ctx).Table("comment").Join("INNER", "issue", "issue.id = comment.issue_id").Where(scope).And(builder.Eq{"comment.id": id})
			if target == PullTargetReviewContent {
				query.In("comment.type", issues_model.CommentTypeCode, issues_model.CommentTypeReview, issues_model.CommentTypeDismissReview)
			} else {
				query.And(builder.Eq{"comment.type": issues_model.CommentTypeCode})
			}
			if target == PullTargetReply {
				query.And(builder.Eq{"issue.`index`": base.PathParamInt64("index")}).And("comment.review_id <> 0")
			}
			return query.Exist()
		default:
			return false, nil
		}
	})
}

func PullReviewCommentCredentialCeiling(base *context.Base, actor *user_model.User) authz_service.CredentialCeiling {
	ceiling := RepoCredentialCeiling(base, actor)
	if scope, exists := base.Data["ApiTokenScope"].(auth_model.AccessTokenScope); exists {
		ceiling.Actions = []authz.Action{authz.ReviewPullRequest}
		var err error
		ceiling.Read, err = scope.HasScope(auth_model.AccessTokenScopeReadIssue)
		if err != nil {
			ceiling.Read = false
		}
		ceiling.Write, err = scope.HasScope(auth_model.AccessTokenScopeWriteIssue)
		if err != nil {
			ceiling.Write = false
		}
	}
	return ceiling
}

func ObservePullReviewComment(base *context.Base, actor *user_model.User, repo *context.Repository, comment *issues_model.Comment, source string) func(authz_service.NativeOutcome) {
	if !setting.EnterpriseAuthz.Enabled || comment.Issue == nil || !comment.Issue.IsPull || comment.Issue.RepoID != repo.Repository.ID || !slices.Contains([]issues_model.CommentType{issues_model.CommentTypeCode, issues_model.CommentTypeReview, issues_model.CommentTypeDismissReview}, comment.Type) {
		return func(authz_service.NativeOutcome) {}
	}
	ceiling := RepoCredentialCeiling(base, actor)
	if source == "api" {
		ceiling = PullReviewCommentCredentialCeiling(base, actor)
	}
	return observeRepoMutation(base, actor, repo.Repository, &repo.Permission, authz.ReviewPullRequest, source, ceiling)
}

func pullGuardFormID(ctx stdcontext.Context, base *context.Base, key string) (int64, error) {
	value, err := nativeGuardFormValue(ctx, base, key)
	if err != nil {
		return 0, err
	}
	id, _ := strconv.ParseInt(value, 10, 64)
	return id, nil
}

func nativeGuardFormValue(ctx stdcontext.Context, base *context.Base, key string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if base.Req.Form != nil {
		return base.Req.Form.Get(key), nil
	}
	mediaType, _, err := mime.ParseMediaType(base.Req.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		return "", errors.New("target_form_unresolved")
	}
	reset, err := nativeGuardBodyDeadline(ctx, base)
	if err != nil {
		return "", err
	}
	defer reset()
	req := base.Req.Clone(ctx)
	req.Body = http.MaxBytesReader(nil, req.Body, 64<<10)
	if err := req.ParseForm(); err != nil {
		return "", errors.New("target_form_unresolved")
	}
	return req.Form.Get(key), nil
}

func nativeGuardBodyDeadline(ctx stdcontext.Context, base *context.Base) (func(), error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil, errors.New("target_form_unresolved")
	}
	controller := http.NewResponseController(base.Resp)
	if err := controller.SetReadDeadline(deadline); err != nil {
		return nil, errors.New("target_form_unresolved")
	}
	return func() { _ = controller.SetReadDeadline(time.Time{}) }, nil
}
