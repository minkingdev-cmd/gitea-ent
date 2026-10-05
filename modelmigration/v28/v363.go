// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"context"
	"errors"

	"gitea.dev/modelmigration/base"
	"gitea.dev/modules/timeutil"

	"xorm.io/xorm"
)

type FeatureDefinitionV363 struct {
	ID                  int64              `xorm:"pk autoincr"`
	Key                 string             `xorm:"VARCHAR(64) NOT NULL UNIQUE"`
	Description         string             `xorm:"TEXT NOT NULL"`
	SupportedScopesJSON string             `xorm:"TEXT NOT NULL"`
	DefaultState        string             `xorm:"VARCHAR(16) NOT NULL"`
	CapabilityKind      string             `xorm:"VARCHAR(16) NOT NULL"`
	ConfigSchemaVersion int                `xorm:"NOT NULL"`
	CatalogVersion      int                `xorm:"NOT NULL"`
	PolicyRevision      int64              `xorm:"NOT NULL DEFAULT 1"`
	CreatedUnix         timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix         timeutil.TimeStamp `xorm:"updated"`
}

func (*FeatureDefinitionV363) TableName() string { return "enterprise_feature_definition" }

type FeatureGrantV363 struct {
	ID          int64              `xorm:"pk autoincr"`
	FeatureKey  string             `xorm:"VARCHAR(64) NOT NULL UNIQUE(feature_scope)"`
	ScopeType   string             `xorm:"VARCHAR(16) NOT NULL UNIQUE(feature_scope) INDEX"`
	ScopeID     int64              `xorm:"NOT NULL UNIQUE(feature_scope)"`
	State       string             `xorm:"VARCHAR(16) NOT NULL"`
	ConfigJSON  string             `xorm:"TEXT NOT NULL"`
	Revision    int64              `xorm:"NOT NULL"`
	CreatedBy   int64              `xorm:"NOT NULL"`
	UpdatedBy   int64              `xorm:"NOT NULL"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

func (*FeatureGrantV363) TableName() string { return "enterprise_feature_grant" }

func SeedEnterpriseFeaturesV363(sess base.Session) error {
	for _, entry := range []struct {
		key, description string
		external         bool
	}{
		{"feature.issues", "Issue 功能", false},
		{"feature.pull_requests", "Pull Request 功能", false},
		{"feature.packages", "Package registry", false},
		{"feature.wiki", "Wiki 功能", false},
		{"feature.webhooks", "Webhook 功能", false},
		{"feature.ci_secret_management", "CI secret 管理", false},
		{"feature.required_status_checks", "Required status checks 管理", false},
		{"feature.woodpecker_ci", "Woodpecker CI 策略", true},
		{"feature.sonarqube_quality_gate", "SonarQube 质量策略", true},
		{"feature.semgrep_scan", "Semgrep 安全扫描策略", true},
		{"feature.gitleaks_scan", "Gitleaks 密钥扫描策略", true},
		{"feature.trivy_scan", "Trivy 扫描策略", true},
		{"feature.ai_review", "AI review 策略", true},
	} {
		definition := &FeatureDefinitionV363{Key: entry.key, Description: entry.description, SupportedScopesJSON: `["global","org","repo"]`, DefaultState: "enabled", CapabilityKind: "native_gate", ConfigSchemaVersion: 1, CatalogVersion: 1, PolicyRevision: 1}
		if entry.external {
			definition.DefaultState, definition.CapabilityKind = "disabled", "policy_only"
		}
		stored := new(FeatureDefinitionV363)
		found, err := sess.Where("`key` = ?", entry.key).Get(stored)
		if err != nil {
			return err
		}
		if found {
			if stored.Description != definition.Description || stored.SupportedScopesJSON != definition.SupportedScopesJSON || stored.DefaultState != definition.DefaultState || stored.CapabilityKind != definition.CapabilityKind || stored.ConfigSchemaVersion != 1 || stored.CatalogVersion != 1 || stored.PolicyRevision < 1 {
				return errors.New("feature_seed_conflict")
			}
			continue
		}
		if _, err := sess.Insert(definition); err != nil {
			return err
		}
	}
	return nil
}

func AddEnterpriseFeatureGrants(ctx context.Context, x base.EngineMigration) error {
	if _, err := x.SyncWithOptions(xorm.SyncOptions{IgnoreDropIndices: true}, new(FeatureDefinitionV363), new(FeatureGrantV363), new(FeatureHookTaskV363), new(FeatureRepositoryV363), new(FeatureCargoSourceV363)); err != nil {
		return err
	}
	sess := x.NewSession().Context(ctx)
	defer sess.Close()
	if err := sess.Begin(); err != nil {
		return err
	}
	if err := SeedEnterpriseFeaturesV363(sess); err != nil {
		return err
	}
	return sess.Commit()
}

type FeatureHookTaskV363 struct {
	ID             int64 `xorm:"pk autoincr"`
	SourceRepoID   int64 `xorm:"NOT NULL DEFAULT 0"`
	SourceOwnerID  int64 `xorm:"NOT NULL DEFAULT 0"`
	SourceResolved bool  `xorm:"NOT NULL DEFAULT false"`
}

func (*FeatureHookTaskV363) TableName() string { return "hook_task" }

type FeatureRepositoryV363 struct {
	OwnerID       int64
	LowerName     string `xorm:"NOT NULL DEFAULT ''"`
	ID            int64  `xorm:"pk autoincr"`
	InternalUsage string `xorm:"VARCHAR(32) NOT NULL DEFAULT ''"`
}

func (*FeatureRepositoryV363) TableName() string { return "repository" }

type FeatureCargoSourceV363 struct {
	ID           int64 `xorm:"pk autoincr"`
	IndexRepoID  int64 `xorm:"NOT NULL UNIQUE(index_source)"`
	SourceRepoID int64 `xorm:"NOT NULL UNIQUE(index_source)"`
}

func (*FeatureCargoSourceV363) TableName() string { return "enterprise_cargo_index_source" }
