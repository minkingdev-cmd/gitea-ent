// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package activities

import (
	"context"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"

	"xorm.io/builder"
)

func activityFeatureCond(ctx context.Context) (builder.Cond, error) {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return builder.NewCond(), nil
	}
	issues := []ActionType{ActionCreateIssue, ActionCommentIssue, ActionCloseIssue, ActionReopenIssue}
	pulls := []ActionType{ActionCreatePullRequest, ActionMergePullRequest, ActionClosePullRequest, ActionReopenPullRequest, ActionApprovePullRequest, ActionRejectPullRequest, ActionCommentPull, ActionPullReviewDismissed, ActionPullRequestReadyForReview, ActionAutoMergePullRequest}
	issueCond, err := authz_model.FeatureQueryCond(ctx, authz.FeatureIssues, "action.repo_id")
	if err != nil {
		return nil, err
	}
	pullCond, err := authz_model.FeatureQueryCond(ctx, authz.FeaturePullRequests, "action.repo_id")
	if err != nil {
		return nil, err
	}
	return builder.And(
		builder.Or(builder.NotIn("action.op_type", issues), issueCond),
		builder.Or(builder.NotIn("action.op_type", pulls), pullCond),
	), nil
}

func notificationFeatureCond() builder.Cond {
	if !setting.EnterpriseAuthz.Enabled || !setting.EnterpriseAuthz.Enforce {
		return builder.NewCond()
	}
	return builder.Or(builder.Eq{"notification.issue_id": 0}, builder.In("notification.issue_id", builder.Select("issue.id").From("issue").Where(builder.Or(
		builder.And(builder.Eq{"issue.is_pull": false}, authz_model.RepoFeatureEnabledCond(context.TODO(), authz.FeatureIssues, "issue.repo_id")),
		builder.And(builder.Eq{"issue.is_pull": true}, authz_model.RepoFeatureEnabledCond(context.TODO(), authz.FeaturePullRequests, "issue.repo_id")),
	))))
}

func notificationFeatureQueryCond(ctx context.Context) (builder.Cond, error) {
	issueCond, err := authz_model.FeatureQueryCond(ctx, authz.FeatureIssues, "issue.repo_id")
	if err != nil {
		return nil, err
	}
	pullCond, err := authz_model.FeatureQueryCond(ctx, authz.FeaturePullRequests, "issue.repo_id")
	if err != nil {
		return nil, err
	}
	if !issueCond.IsValid() && !pullCond.IsValid() {
		return builder.NewCond(), nil
	}
	return builder.Or(builder.Eq{"notification.issue_id": 0}, builder.In("notification.issue_id", builder.Select("issue.id").From("issue").Where(builder.Or(
		builder.And(builder.Eq{"issue.is_pull": false}, issueCond), builder.And(builder.Eq{"issue.is_pull": true}, pullCond),
	)))), nil
}

func observeNotificationQuery(ctx context.Context, native builder.Cond) {
	for _, key := range []authz.FeatureKey{authz.FeatureIssues, authz.FeaturePullRequests} {
		candidate := authz_model.RepoFeatureCandidateCond(ctx, key, "issue.repo_id")
		authz_model.ObserveFeatureQuery(ctx, key, candidate, func(tx context.Context, denied builder.Cond) (bool, error) {
			return db.GetEngine(tx).Table("notification").Where(native).And(builder.In("notification.issue_id", builder.Select("issue.id").From("issue").Where(builder.Eq{"issue.is_pull": key == authz.FeaturePullRequests}.And(denied)))).Exist(new(Notification))
		})
	}
}

func observeActivityQuery(ctx context.Context, native builder.Cond) {
	for _, item := range []struct {
		key   authz.FeatureKey
		types []ActionType
	}{
		{authz.FeatureIssues, []ActionType{ActionCreateIssue, ActionCommentIssue, ActionCloseIssue, ActionReopenIssue}},
		{authz.FeaturePullRequests, []ActionType{ActionCreatePullRequest, ActionMergePullRequest, ActionClosePullRequest, ActionReopenPullRequest, ActionApprovePullRequest, ActionRejectPullRequest, ActionCommentPull, ActionPullReviewDismissed, ActionPullRequestReadyForReview, ActionAutoMergePullRequest}},
	} {
		authz_model.ObserveFeatureQuery(ctx, item.key, authz_model.RepoFeatureCandidateCond(ctx, item.key, "action.repo_id"), func(tx context.Context, denied builder.Cond) (bool, error) {
			return db.GetEngine(tx).Where(native).And(builder.In("action.op_type", item.types), denied).Exist(new(Action))
		})
	}
}
