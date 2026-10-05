// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"bytes"
	"encoding/json" //nolint:depguard // 拒绝重复字段，不能先解码到 map。
	"errors"
	"io"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

type (
	FeatureKey   string
	FeatureState string
)

const (
	FeatureIssues               FeatureKey   = "feature.issues"
	FeaturePullRequests         FeatureKey   = "feature.pull_requests"
	FeaturePackages             FeatureKey   = "feature.packages"
	FeatureWiki                 FeatureKey   = "feature.wiki"
	FeatureWebhooks             FeatureKey   = "feature.webhooks"
	FeatureWoodpeckerCI         FeatureKey   = "feature.woodpecker_ci"
	FeatureSonarqubeQualityGate FeatureKey   = "feature.sonarqube_quality_gate"
	FeatureSemgrepScan          FeatureKey   = "feature.semgrep_scan"
	FeatureGitleaksScan         FeatureKey   = "feature.gitleaks_scan"
	FeatureTrivyScan            FeatureKey   = "feature.trivy_scan"
	FeatureAIReview             FeatureKey   = "feature.ai_review"
	FeatureCISecretManagement   FeatureKey   = "feature.ci_secret_management"
	FeatureRequiredStatusChecks FeatureKey   = "feature.required_status_checks"
	FeatureDisabled             FeatureState = "disabled"
	FeatureEnabled              FeatureState = "enabled"
	FeatureRequired             FeatureState = "required"
	FeatureInherited            FeatureState = "inherited"
	FeatureCatalogVersion                    = 1
)

type FeatureMetadata struct {
	Key                 FeatureKey   `json:"key"`
	Description         string       `json:"description"`
	SupportedScopes     []string     `json:"supported_scopes"`
	DefaultState        FeatureState `json:"default_state"`
	CapabilityKind      string       `json:"capability_kind"`
	ConfigSchemaVersion int          `json:"config_schema_version"`
}

func FeatureCatalog() []FeatureMetadata {
	var result []FeatureMetadata
	for _, entry := range []struct {
		key         FeatureKey
		description string
		external    bool
	}{
		{FeatureIssues, "Issue 功能", false},
		{FeaturePullRequests, "Pull Request 功能", false},
		{FeaturePackages, "Package registry", false},
		{FeatureWiki, "Wiki 功能", false},
		{FeatureWebhooks, "Webhook 功能", false},
		{FeatureCISecretManagement, "CI secret 管理", false},
		{FeatureRequiredStatusChecks, "Required status checks 管理", false},
		{FeatureWoodpeckerCI, "Woodpecker CI 策略", true},
		{FeatureSonarqubeQualityGate, "SonarQube 质量策略", true},
		{FeatureSemgrepScan, "Semgrep 安全扫描策略", true},
		{FeatureGitleaksScan, "Gitleaks 密钥扫描策略", true},
		{FeatureTrivyScan, "Trivy 扫描策略", true},
		{FeatureAIReview, "AI review 策略", true},
	} {
		state, kind := FeatureEnabled, "native_gate"
		if entry.external {
			state, kind = FeatureDisabled, "policy_only"
		}
		result = append(result, FeatureMetadata{entry.key, entry.description, []string{"global", "org", "repo"}, state, kind, 1})
	}
	return result
}

func LookupFeature(key FeatureKey) (FeatureMetadata, bool) {
	for _, entry := range FeatureCatalog() {
		if entry.Key == key {
			return entry, true
		}
	}
	return FeatureMetadata{}, false
}

func (s FeatureState) Valid() bool {
	return slices.Contains([]FeatureState{FeatureDisabled, FeatureEnabled, FeatureRequired, FeatureInherited}, s)
}

type FeatureConfig struct {
	CheckContexts []string `json:"check_contexts,omitempty"`
}

func ParseFeatureConfig(key FeatureKey, state FeatureState, raw []byte) (FeatureConfig, string, error) {
	invalid := errors.New("invalid_feature_config")
	fail := func() (FeatureConfig, string, error) { return FeatureConfig{}, "", invalid }
	_, known := LookupFeature(key)
	if !known || !state.Valid() || len(raw) == 0 || len(raw) > 16*1024 || !utf8.Valid(raw) {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return fail()
	}
	config := FeatureConfig{}
	seen := false
	contextsAllowed := state != FeatureInherited && (key == FeatureRequiredStatusChecks || slices.Contains([]FeatureKey{FeatureWoodpeckerCI, FeatureSonarqubeQualityGate, FeatureSemgrepScan, FeatureGitleaksScan, FeatureTrivyScan, FeatureAIReview}, key))
	for d.More() {
		token, err = d.Token()
		if err != nil || token != "check_contexts" || seen || !contextsAllowed {
			return fail()
		}
		seen = true
		var list json.RawMessage
		if d.Decode(&list) != nil || bytes.Equal(bytes.TrimSpace(list), []byte("null")) || json.Unmarshal(list, &config.CheckContexts) != nil || len(config.CheckContexts) > 64 {
			return fail()
		}
		for _, value := range config.CheckContexts {
			if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsFunc(value, unicode.IsControl) {
				return fail()
			}
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return fail()
	}
	if _, err = d.Token(); !errors.Is(err, io.EOF) {
		return fail()
	}
	slices.Sort(config.CheckContexts)
	config.CheckContexts = slices.Compact(config.CheckContexts)
	canonical, err := json.Marshal(config)
	if err != nil {
		return fail()
	}
	return config, string(canonical), nil
}

type FeatureScope struct {
	Scope string `json:"scope"`
	ID    int64  `json:"id"`
}

type FeatureLayer struct {
	Scope    string        `json:"scope"`
	ID       int64         `json:"id"`
	State    FeatureState  `json:"state"`
	Config   FeatureConfig `json:"config"`
	Revision int64         `json:"revision"`
}

type ResolvedFeature struct {
	Key            FeatureKey     `json:"key"`
	State          FeatureState   `json:"state"`
	Source         FeatureScope   `json:"source"`
	LockedBy       *FeatureScope  `json:"locked_by,omitempty"`
	Conflicts      []FeatureScope `json:"conflicts"`
	Config         FeatureConfig  `json:"config"`
	CapabilityKind string         `json:"capability_kind"`
}

func ResolveFeature(definition FeatureMetadata, layers []FeatureLayer) (ResolvedFeature, error) {
	result := ResolvedFeature{Key: definition.Key, State: definition.DefaultState, Source: FeatureScope{Scope: "default"}, CapabilityKind: definition.CapabilityKind}
	if _, ok := LookupFeature(definition.Key); !ok {
		return result, errors.New("invalid_feature_policy")
	}
	lastScope := -1
	var required []string
	for _, layer := range layers {
		rank := slices.Index([]string{"global", "org", "repo"}, layer.Scope)
		if rank < 0 || rank <= lastScope || layer.Scope == "global" && layer.ID != 0 || layer.Scope != "global" && layer.ID <= 0 || !layer.State.Valid() {
			return result, errors.New("invalid_feature_policy")
		}
		lastScope = rank
		if layer.State == FeatureInherited {
			continue
		}
		current := FeatureScope{Scope: layer.Scope, ID: layer.ID}
		if result.LockedBy != nil {
			if result.State == FeatureDisabled && layer.State != FeatureDisabled || result.State == FeatureRequired && layer.State == FeatureDisabled {
				result.Conflicts = append(result.Conflicts, current)
				continue
			}
		} else {
			result.State, result.Source = layer.State, current
			if layer.State == FeatureDisabled || layer.State == FeatureRequired {
				result.LockedBy = &current
			}
		}
		if result.State == FeatureDisabled {
			continue
		}
		result.Config.CheckContexts = slices.Clone(layer.Config.CheckContexts)
		if layer.State == FeatureRequired {
			required = append(required, layer.Config.CheckContexts...)
		}
	}
	if result.State == FeatureDisabled {
		result.Config = FeatureConfig{}
	} else {
		result.Config.CheckContexts = append(result.Config.CheckContexts, required...)
		slices.Sort(result.Config.CheckContexts)
		result.Config.CheckContexts = slices.Compact(result.Config.CheckContexts)
	}
	return result, nil
}
