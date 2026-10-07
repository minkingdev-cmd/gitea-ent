// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package issues

import (
	"context"

	"gitea.dev/models/db"
)

func HasUnresolvedReviewConversation(ctx context.Context, issueID int64) (bool, error) {
	return db.GetEngine(ctx).Table("comment").
		Join("LEFT", "review", "review.id=comment.review_id AND review.issue_id=comment.issue_id").
		Where("comment.issue_id=? AND comment.type=? AND comment.review_id>0 AND comment.resolve_doer_id=0", issueID, CommentTypeCode).
		And("review.id IS NULL OR review.type<>?", ReviewTypePending).
		And(`NOT EXISTS (
			SELECT 1 FROM comment earlier
			LEFT JOIN review earlier_review ON earlier_review.id=earlier.review_id AND earlier_review.issue_id=earlier.issue_id
			WHERE earlier.issue_id=comment.issue_id AND earlier.type=comment.type AND earlier.review_id=comment.review_id
			AND earlier.tree_path=comment.tree_path AND earlier.line=comment.line
			AND (earlier_review.id IS NULL OR earlier_review.type<>?)
			AND (earlier.created_unix<comment.created_unix OR (earlier.created_unix=comment.created_unix AND earlier.id<comment.id))
		)`, ReviewTypePending).
		Exist(new(Comment))
}
