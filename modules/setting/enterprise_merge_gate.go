// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"errors"
	"strings"

	"gitea.dev/modules/log"
)

type EnterpriseMergeGateConfig struct {
	Enabled bool
	Enforce bool
}

var EnterpriseMergeGate EnterpriseMergeGateConfig

func loadEnterpriseMergeGateFrom(root ConfigProvider) {
	cfg, err := readEnterpriseMergeGateConfig(root)
	if err != nil {
		log.Fatal("Invalid [enterprise.merge_gate] configuration: %v", err)
	}
	EnterpriseMergeGate = cfg
}

func readEnterpriseMergeGateConfig(root ConfigProvider) (EnterpriseMergeGateConfig, error) {
	var cfg EnterpriseMergeGateConfig
	sec := root.Section("enterprise.merge_gate")
	for _, field := range []struct {
		key   string
		value *bool
	}{{"ENABLED", &cfg.Enabled}, {"ENFORCE", &cfg.Enforce}} {
		if !sec.HasKey(field.key) {
			continue
		}
		value, err := sec.Key(field.key).Bool()
		if err != nil {
			return cfg, errors.New("invalid_" + strings.ToLower(field.key))
		}
		*field.value = value
	}
	if cfg.Enforce && !cfg.Enabled {
		return cfg, errors.New("enforce_requires_enabled")
	}
	if cfg.Enabled && !EnterpriseAuthz.Enabled {
		return cfg, errors.New("authz_enabled_required")
	}
	if cfg.Enabled && Audit.RecordOutput != AuditRecordOutputDatabase {
		return cfg, errors.New("database_audit_required")
	}
	if cfg.Enforce && !EnterpriseAuthz.Enforce {
		return cfg, errors.New("authz_enforce_required")
	}
	return cfg, nil
}
