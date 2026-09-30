// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"encoding/base64"
	"errors"
	"strconv"
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
	ManagedOrgID             int64
	PersonalRepoQuota        int
	AdminCallbackEnabled     bool
	AdminCallbackToken       string
	AdminCallbackAESKey      string
	AdminCallbackReceiverID  string
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
	PersonalRepoQuota: 10,
	HTTPTimeout:       15 * time.Second,
	APIBaseURL:        "https://qyapi.weixin.qq.com",
	OAuthBaseURL:      "https://login.work.weixin.qq.com",
}

func loadEnterpriseWeComFrom(rootCfg ConfigProvider) {
	cfg, err := readEnterpriseWeComConfig(rootCfg)
	if err != nil {
		log.Fatal("Invalid [enterprise.wecom] configuration: %v", err)
	}
	EnterpriseWeCom = cfg
}

func readEnterpriseWeComConfig(rootCfg ConfigProvider) (EnterpriseWeComConfig, error) {
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
		AdminCallbackEnabled:     sec.Key("ADMIN_CALLBACK_ENABLED").MustBool(false),
		AdminCallbackReceiverID:  strings.TrimSpace(sec.Key("ADMIN_CALLBACK_RECEIVER_ID").String()),
		HTTPTimeout:              sec.Key("HTTP_TIMEOUT").MustDuration(15 * time.Second),
		APIBaseURL:               strings.TrimRight(sec.Key("API_BASE_URL").MustString("https://qyapi.weixin.qq.com"), "/"),
		OAuthBaseURL:             strings.TrimRight(sec.Key("OAUTH_BASE_URL").MustString("https://login.work.weixin.qq.com"), "/"),
	}
	var err error
	cfg.ManagedOrgID, err = strconv.ParseInt(sec.Key("MANAGED_ORG_ID").MustString("0"), 10, 64)
	if err != nil || cfg.ManagedOrgID < 0 {
		return cfg, errors.New("MANAGED_ORG_ID must be a non-negative integer")
	}
	cfg.PersonalRepoQuota, err = strconv.Atoi(sec.Key("PERSONAL_REPO_QUOTA").MustString("10"))
	if err != nil || cfg.PersonalRepoQuota < 0 {
		return cfg, errors.New("PERSONAL_REPO_QUOTA must be a non-negative integer")
	}
	if sec.HasKey("APPLY_AUTHZ_MAPPINGS_ON_SYNC") {
		log.Warn("APPLY_AUTHZ_MAPPINGS_ON_SYNC is deprecated and ignored; WeCom governance publishes complete authorization snapshots")
	}
	cfg.CorpSecret = loadSecret(sec, "CORP_SECRET_URI", "CORP_SECRET")
	cfg.AdminCallbackToken = loadSecret(sec, "ADMIN_CALLBACK_TOKEN_URI", "ADMIN_CALLBACK_TOKEN")
	cfg.AdminCallbackAESKey = loadSecret(sec, "ADMIN_CALLBACK_AES_KEY_URI", "ADMIN_CALLBACK_AES_KEY")

	if err := validateEnterpriseWeComConfig(cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func validateEnterpriseWeComConfig(cfg EnterpriseWeComConfig) error {
	if cfg.ManagedOrgID < 0 {
		return errors.New("MANAGED_ORG_ID must be a non-negative integer")
	}
	if cfg.PersonalRepoQuota < 0 {
		return errors.New("PERSONAL_REPO_QUOTA must be a non-negative integer")
	}
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
	if cfg.AdminCallbackEnabled {
		if cfg.AdminCallbackToken == "" {
			return errors.New("ADMIN_CALLBACK_TOKEN or ADMIN_CALLBACK_TOKEN_URI is required")
		}
		if cfg.AdminCallbackReceiverID == "" {
			return errors.New("ADMIN_CALLBACK_RECEIVER_ID is required")
		}
		key, err := base64.StdEncoding.DecodeString(cfg.AdminCallbackAESKey + "=")
		if len(cfg.AdminCallbackAESKey) != 43 || err != nil || len(key) != 32 {
			return errors.New("ADMIN_CALLBACK_AES_KEY must be a 43-character base64 encoding of 32 bytes")
		}
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
