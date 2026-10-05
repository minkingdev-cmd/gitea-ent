// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package cmd

import (
	"context"
	"errors"
	"fmt"

	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/services/audit"
	authz_service "gitea.dev/services/enterpriseauthz"

	"github.com/urfave/cli/v3"
)

func newEnterpriseFeaturesCommand() *cli.Command {
	return &cli.Command{Name: "enterprise-features", Usage: "管理企业功能授权的受控迁移", Commands: []*cli.Command{{
		Name: "adopt-cargo-index", Usage: "经操作者核实后，将明确仓库 ID 认领为 Cargo registry Git 索引；不会按名称推断", Flags: []cli.Flag{
			&cli.Int64Flag{Name: "repo-id", Required: true, Usage: "已核实的 Cargo 索引仓库 ID"},
			&cli.Int64Flag{Name: "actor-id", Required: true, Usage: "具有真实系统管理 authority 的用户 ID"},
			&cli.BoolFlag{Name: "confirm-index-purpose", Required: true, Usage: "确认已离线核实仓库仅用于 Cargo registry 索引，来源清单涵盖全部 Git 历史"},
			&cli.Int64SliceFlag{Name: "source-repo-id", Usage: "索引全部历史曾关联的仓库 ID，可重复；不能只检查当前仍存在的包"},
			&cli.BoolFlag{Name: "confirm-no-linked-history", Usage: "确认全部Git历史均没有关联仓库包；与source-repo-id互斥"},
		}, Action: func(ctx context.Context, c *cli.Command) error {
			setting.LoadSettings()
			if err := initDB(ctx); err != nil {
				return err
			}
			actor, err := user_model.GetUserByID(ctx, c.Int64("actor-id"))
			if err != nil {
				return err
			}
			ctx = audit.WithOrigin(ctx, "cli")
			sources := c.Int64Slice("source-repo-id")
			if (len(sources) == 0) != c.Bool("confirm-no-linked-history") {
				return errors.New("provide complete source-repo-id history or confirm-no-linked-history, exclusively")
			}
			if err := authz_service.AdoptCargoIndex(ctx, actor, c.Int64("repo-id"), c.Bool("confirm-index-purpose"), sources...); err != nil {
				return err
			}
			_, err = fmt.Fprintln(c.Writer, "Cargo 索引用途已确认；可以重新运行 enabled preflight。")
			return err
		},
	}}}
}
