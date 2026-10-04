// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"errors"
	"strings"

	"gitea.dev/modules/log"
)

type EnterpriseAuthzConfig struct {
	Enabled           bool
	Enforce           bool
	FailClosedOnError bool
}

var EnterpriseAuthz = EnterpriseAuthzConfig{FailClosedOnError: true}

func loadEnterpriseAuthzFrom(root ConfigProvider) {
	cfg, err := readEnterpriseAuthzConfig(root)
	if err != nil {
		log.Fatal("Invalid [enterprise.authz] configuration: %v", err)
	}
	EnterpriseAuthz = cfg
}

func readEnterpriseAuthzConfig(root ConfigProvider) (EnterpriseAuthzConfig, error) {
	cfg := EnterpriseAuthzConfig{FailClosedOnError: true}
	sec := root.Section("enterprise.authz")
	for _, field := range []struct {
		key   string
		value *bool
	}{
		{"ENABLED", &cfg.Enabled}, {"ENFORCE", &cfg.Enforce}, {"FAIL_CLOSED_ON_ERROR", &cfg.FailClosedOnError},
	} {
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
	if cfg.Enabled && Audit.RecordOutput != AuditRecordOutputDatabase {
		return cfg, errors.New("database_audit_required")
	}
	return cfg, nil
}
