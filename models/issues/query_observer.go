// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package issues

import (
	"context"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	authz "gitea.dev/modules/enterpriseauthz"

	"xorm.io/builder"
)

func observeIssueSession(ctx context.Context, session func(context.Context) db.Session) {
	for _, key := range []authz.FeatureKey{authz.FeatureIssues, authz.FeaturePullRequests} {
		authz_model.ObserveFeatureQuery(ctx, key, authz_model.RepoFeatureCandidateCond(ctx, key, "issue.repo_id"), func(tx context.Context, denied builder.Cond) (bool, error) {
			return session(tx).And(builder.Eq{"issue.is_pull": key == authz.FeaturePullRequests}, denied).Exist(new(Issue))
		})
	}
}

func observeIssueOptions(ctx context.Context, opts *IssuesOptions, otherConds ...builder.Cond) {
	observeIssueSession(ctx, func(tx context.Context) db.Session {
		sess := db.GetEngine(tx).Table("issue").Join("INNER", "repository", "`issue`.repo_id = `repository`.id")
		applyConditions(sess, opts)
		for _, cond := range otherConds {
			sess.And(cond)
		}
		return sess
	})
}

func observeIssueReferenceQuery(ctx context.Context, issueIDSQL string, session func(context.Context) db.Session) {
	for _, key := range []authz.FeatureKey{authz.FeatureIssues, authz.FeaturePullRequests} {
		authz_model.ObserveFeatureQuery(ctx, key, authz_model.RepoFeatureCandidateCond(ctx, key, "issue.repo_id"), func(tx context.Context, denied builder.Cond) (bool, error) {
			return session(tx).And(builder.In(issueIDSQL, builder.Select("issue.id").From("issue").Where(builder.Eq{"issue.is_pull": key == authz.FeaturePullRequests}.And(denied)))).Exist()
		})
	}
}

func observeTrackedTimeQuery(ctx context.Context, opts *FindTrackedTimesOptions) {
	observeIssueReferenceQuery(ctx, "tracked_time.issue_id", func(tx context.Context) db.Session {
		sess := db.GetEngine(tx).Table("tracked_time").Where(opts.ToConds())
		if opts.RepositoryID > 0 || opts.MilestoneID > 0 {
			sess.Join("INNER", "issue", "issue.id=tracked_time.issue_id")
		}
		return sess
	})
}
