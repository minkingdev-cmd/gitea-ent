// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"
	"slices"

	"gitea.dev/models/db"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/timeutil"
)

type FeatureDefinition struct {
	ID                  int64              `xorm:"pk autoincr"`
	Key                 authz.FeatureKey   `xorm:"VARCHAR(64) NOT NULL UNIQUE"`
	Description         string             `xorm:"TEXT NOT NULL"`
	SupportedScopesJSON string             `xorm:"TEXT NOT NULL"`
	DefaultState        authz.FeatureState `xorm:"VARCHAR(16) NOT NULL"`
	CapabilityKind      string             `xorm:"VARCHAR(16) NOT NULL"`
	ConfigSchemaVersion int                `xorm:"NOT NULL"`
	CatalogVersion      int                `xorm:"NOT NULL"`
	PolicyRevision      int64              `xorm:"NOT NULL DEFAULT 1"`
	CreatedUnix         timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix         timeutil.TimeStamp `xorm:"updated"`
}

func (*FeatureDefinition) TableName() string { return "enterprise_feature_definition" }

func (d *FeatureDefinition) Validate() error {
	metadata, ok := authz.LookupFeature(d.Key)
	var scopes []string
	if !ok || json.Unmarshal([]byte(d.SupportedScopesJSON), &scopes) != nil || !slices.Equal(scopes, metadata.SupportedScopes) || d.Description != metadata.Description || d.DefaultState != metadata.DefaultState || d.CapabilityKind != metadata.CapabilityKind || d.ConfigSchemaVersion != metadata.ConfigSchemaVersion || d.CatalogVersion != authz.FeatureCatalogVersion || d.PolicyRevision < 1 {
		return errors.New("invalid_feature_definition")
	}
	return nil
}

type FeatureGrant struct {
	ID          int64              `xorm:"pk autoincr"`
	FeatureKey  authz.FeatureKey   `xorm:"VARCHAR(64) NOT NULL UNIQUE(feature_scope)"`
	ScopeType   ScopeType          `xorm:"VARCHAR(16) NOT NULL UNIQUE(feature_scope) INDEX"`
	ScopeID     int64              `xorm:"NOT NULL UNIQUE(feature_scope)"`
	State       authz.FeatureState `xorm:"VARCHAR(16) NOT NULL"`
	ConfigJSON  string             `xorm:"TEXT NOT NULL"`
	Revision    int64              `xorm:"NOT NULL"`
	CreatedBy   int64              `xorm:"NOT NULL"`
	UpdatedBy   int64              `xorm:"NOT NULL"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

func (*FeatureGrant) TableName() string { return "enterprise_feature_grant" }
func (g *FeatureGrant) Scope() Scope    { return Scope{g.ScopeType, g.ScopeID} }

func (g *FeatureGrant) Validate() error {
	_, canonical, err := authz.ParseFeatureConfig(g.FeatureKey, g.State, []byte(g.ConfigJSON))
	if err != nil || !g.Scope().Valid() || g.Revision < 1 || canonical != g.ConfigJSON {
		return errors.New("invalid_feature_grant")
	}
	return nil
}

func FeatureScopeName(typ ScopeType) string {
	if typ == ScopeSystem {
		return "global"
	}
	return string(typ)
}

func LockFeatures(ctx context.Context, keys []authz.FeatureKey) error {
	if !db.InTransaction(ctx) {
		return errors.New("policy_lock_requires_transaction")
	}
	keys = slices.Clone(keys)
	slices.Sort(keys)
	for _, key := range slices.Compact(keys) {
		if _, known := authz.LookupFeature(key); !known {
			return errors.New("invalid_feature_policy")
		}
		result, err := db.Exec(ctx, "UPDATE `enterprise_feature_definition` SET policy_revision=policy_revision WHERE `key`=?", key)
		if err != nil {
			return err
		}
		count, err := result.RowsAffected()
		if err != nil || count != 1 {
			return errors.New("feature_seed_missing")
		}
	}
	return nil
}

func CheckFeatureReady(ctx context.Context) error {
	var definitions []FeatureDefinition
	if err := db.GetEngine(ctx).Find(&definitions); err != nil {
		return errors.New("authz_schema_missing")
	}
	if len(definitions) != len(authz.FeatureCatalog()) {
		return errSeedIncomplete
	}
	for _, definition := range definitions {
		if definition.Validate() != nil {
			return errSeedIncomplete
		}
	}
	return nil
}

func init() {
	db.RegisterModel(new(FeatureDefinition))
	db.RegisterModel(new(FeatureGrant))
}

type CargoIndexSource struct {
	ID           int64 `xorm:"pk autoincr"`
	IndexRepoID  int64 `xorm:"NOT NULL UNIQUE(index_source)"`
	SourceRepoID int64 `xorm:"NOT NULL UNIQUE(index_source)"`
}

func (*CargoIndexSource) TableName() string { return "enterprise_cargo_index_source" }

func init() { db.RegisterModel(new(CargoIndexSource)) }
