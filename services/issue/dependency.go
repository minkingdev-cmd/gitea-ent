// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package issue

import (
	"context"

	issues_model "gitea.dev/models/issues"
	user_model "gitea.dev/models/user"
)

func CreateIssueDependency(ctx context.Context, user *user_model.User, issue, dep *issues_model.Issue) error {
	if err := RequireFeature(ctx, issue); err != nil {
		return err
	}
	if err := RequireFeature(ctx, dep); err != nil {
		return err
	}

	return issues_model.CreateIssueDependency(ctx, user, issue, dep)
}

func RemoveIssueDependency(ctx context.Context, user *user_model.User, issue, dep *issues_model.Issue, depType issues_model.DependencyType) error {
	if err := RequireFeature(ctx, issue); err != nil {
		return err
	}
	if err := RequireFeature(ctx, dep); err != nil {
		return err
	}

	return issues_model.RemoveIssueDependency(ctx, user, issue, dep, depType)
}
