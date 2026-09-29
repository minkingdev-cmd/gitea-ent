// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"errors"
	"strings"
	"time"

	"gitea.dev/modules/log"
)

// EnterpriseWeComConfig contains the Enterprise WeCom web-login settings.
type EnterpriseWeComConfig struct {
	Enabled                  bool
	LoginOnly                bool
	LoginSourceName          string
	CorpID                   string
	AgentID                  string
	CorpSecretURI            string
	CorpSecret               string
	UsernameTemplate         string
	AutoCreateUser           bool
	SyncDepartments          bool
	SyncTags                 bool
	ApplyAuthzMappingsOnSync bool
	SuperAdminTagName        string
	HTTPTimeout              time.Duration
	APIBaseURL               string
	OAuthBaseURL             string
}

// EnterpriseWeCom is disabled by default and only affects web sign-in when enabled.
var EnterpriseWeCom = EnterpriseWeComConfig{
	LoginOnly:         true,
	LoginSourceName:   "enterprise-wecom",
	UsernameTemplate:  "{userid}",
	AutoCreateUser:    true,
	SyncDepartments:   true,
	SyncTags:          true,
	SuperAdminTagName: "超管",
	HTTPTimeout:       15 * time.Second,
	APIBaseURL:        "https://qyapi.weixin.qq.com",
	OAuthBaseURL:      "https://login.work.weixin.qq.com",
}

func loadEnterpriseWeComFrom(rootCfg ConfigProvider) {
	sec := rootCfg.Section("enterprise.wecom")
	cfg := EnterpriseWeComConfig{
		Enabled:                  sec.Key("ENABLED").MustBool(false),
		LoginOnly:                sec.Key("LOGIN_ONLY").MustBool(true),
		LoginSourceName:          strings.TrimSpace(sec.Key("LOGIN_SOURCE_NAME").MustString("enterprise-wecom")),
		CorpID:                   strings.TrimSpace(sec.Key("CORP_ID").String()),
		AgentID:                  strings.TrimSpace(sec.Key("AGENT_ID").String()),
		CorpSecretURI:            strings.TrimSpace(sec.Key("CORP_SECRET_URI").String()),
		UsernameTemplate:         sec.Key("USERNAME_TEMPLATE").MustString("{userid}"),
		AutoCreateUser:           sec.Key("AUTO_CREATE_USER").MustBool(true),
		SyncDepartments:          sec.Key("SYNC_DEPARTMENTS").MustBool(true),
		SyncTags:                 sec.Key("SYNC_TAGS").MustBool(true),
		ApplyAuthzMappingsOnSync: sec.Key("APPLY_AUTHZ_MAPPINGS_ON_SYNC").MustBool(false),
		SuperAdminTagName:        strings.TrimSpace(sec.Key("SUPER_ADMIN_TAG_NAME").MustString("超管")),
		HTTPTimeout:              sec.Key("HTTP_TIMEOUT").MustDuration(15 * time.Second),
		APIBaseURL:               strings.TrimRight(sec.Key("API_BASE_URL").MustString("https://qyapi.weixin.qq.com"), "/"),
		OAuthBaseURL:             strings.TrimRight(sec.Key("OAUTH_BASE_URL").MustString("https://login.work.weixin.qq.com"), "/"),
	}
	cfg.CorpSecret = loadSecret(sec, "CORP_SECRET_URI", "CORP_SECRET")

	if err := validateEnterpriseWeComConfig(cfg); err != nil {
		log.Fatal("Invalid [enterprise.wecom] configuration: %v", err)
	}
	EnterpriseWeCom = cfg
}

func validateEnterpriseWeComConfig(cfg EnterpriseWeComConfig) error {
	if !cfg.Enabled {
		return nil
	}

	var missing []string
	if cfg.LoginSourceName == "" {
		missing = append(missing, "LOGIN_SOURCE_NAME")
	}
	if cfg.CorpID == "" {
		missing = append(missing, "CORP_ID")
	}
	if cfg.AgentID == "" {
		missing = append(missing, "AGENT_ID")
	}
	if cfg.CorpSecret == "" {
		missing = append(missing, "CORP_SECRET or CORP_SECRET_URI")
	}
	if len(missing) > 0 {
		return errors.New("missing required setting(s): " + strings.Join(missing, ", "))
	}
	if cfg.HTTPTimeout <= 0 {
		return errors.New("HTTP_TIMEOUT must be greater than zero")
	}
	return nil
}

func EnterpriseWeComEnabled() bool {
	return EnterpriseWeCom.Enabled
}

// EnterpriseWeComLoginOnly reports whether Enterprise WeCom owns the web login surface.
func EnterpriseWeComLoginOnly() bool {
	return EnterpriseWeCom.Enabled && EnterpriseWeCom.LoginOnly
}
