// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package issue

import (
	"context"

	issues_model "gitea.dev/models/issues"
	user_model "gitea.dev/models/user"
)

func CreateIssueStopwatch(ctx context.Context, user *user_model.User, issue *issues_model.Issue) (bool, error) {
	if err := RequireFeature(ctx, issue); err != nil {
		return false, err
	}
	exists, _, other, err := issues_model.HasUserStopwatch(ctx, user.ID)
	if err != nil {
		return false, err
	}
	if exists {
		if err := RequireFeature(ctx, other); err != nil {
			return false, err
		}
	}
	return issues_model.CreateIssueStopwatch(ctx, user, issue)
}

func FinishIssueStopwatch(ctx context.Context, user *user_model.User, issue *issues_model.Issue) (bool, error) {
	if err := RequireFeature(ctx, issue); err != nil {
		return false, err
	}
	return issues_model.FinishIssueStopwatch(ctx, user, issue)
}

func CancelStopwatch(ctx context.Context, user *user_model.User, issue *issues_model.Issue) (bool, error) {
	if err := RequireFeature(ctx, issue); err != nil {
		return false, err
	}
	return issues_model.CancelStopwatch(ctx, user, issue)
}
