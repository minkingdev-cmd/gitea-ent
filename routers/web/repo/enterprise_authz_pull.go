// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repo

import (
	"gitea.dev/routers/common"
	"gitea.dev/services/context"
)

func ObservePullMutationGuard(guard func(*context.Context)) func(*context.Context) {
	return func(ctx *context.Context) {
		guard(ctx)
		if ctx.Written() {
			common.ObserveMarkedPullDenial(ctx.Base, ctx.Doer, ctx.Repo, "web")
		}
	}
}

func ObserveRepoMutationGuard(guard func(*context.Context)) func(*context.Context) {
	return func(ctx *context.Context) {
		guard(ctx)
		if ctx.Written() {
			common.ObserveMarkedRepoDenial(ctx.Base, ctx.Doer, ctx.Repo, "web")
		}
	}
}
