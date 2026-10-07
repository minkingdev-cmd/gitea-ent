// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"bytes"
	"encoding/json" //nolint:depguard // Token 解码用于拒绝重复字段。
	"errors"
	"io"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"gitea.dev/modules/glob"
)

type ProtectedPathConfig struct {
	PathPattern    string   `json:"path_pattern"`
	BranchPattern  string   `json:"branch_pattern,omitempty"`
	RequiredRoleID int64    `json:"required_role_id"`
	CheckContexts  []string `json:"check_contexts,omitempty"`
	Enabled        bool     `json:"enabled"`
}

func ParseProtectedPathConfig(raw []byte) (ProtectedPathConfig, string, error) {
	invalid := errors.New("invalid_protected_path_config")
	fail := func() (ProtectedPathConfig, string, error) { return ProtectedPathConfig{}, "", invalid }
	if len(raw) == 0 || len(raw) > 16*1024 || !utf8.Valid(raw) {
		return fail()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return fail()
	}
	config := ProtectedPathConfig{Enabled: true}
	seen := map[string]bool{}
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return fail()
		}
		seen[key] = true
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fail()
		}
		switch key {
		case "path_pattern":
			err = json.Unmarshal(value, &config.PathPattern)
		case "branch_pattern":
			err = json.Unmarshal(value, &config.BranchPattern)
		case "required_role_id":
			err = json.Unmarshal(value, &config.RequiredRoleID)
		case "check_contexts":
			err = json.Unmarshal(value, &config.CheckContexts)
		case "enabled":
			err = json.Unmarshal(value, &config.Enabled)
		default:
			return fail()
		}
		if err != nil {
			return fail()
		}
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return fail()
	}
	if _, err = d.Token(); !errors.Is(err, io.EOF) {
		return fail()
	}
	if config.RequiredRoleID <= 0 || !validRepoPath(config.PathPattern) || len(config.CheckContexts) > 64 {
		return fail()
	}
	for _, pattern := range []string{config.PathPattern, config.BranchPattern} {
		if pattern == "" {
			continue
		}
		if len(pattern) > 256 || !utf8.ValidString(pattern) || strings.TrimSpace(pattern) != pattern || strings.ContainsFunc(pattern, unicode.IsControl) {
			return fail()
		}
		if _, err := glob.Compile(pattern, '/'); err != nil {
			return fail()
		}
	}
	if seen["branch_pattern"] && config.BranchPattern == "" {
		return fail()
	}
	for _, value := range config.CheckContexts {
		if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsFunc(value, unicode.IsControl) {
			return fail()
		}
	}
	slices.Sort(config.CheckContexts)
	config.CheckContexts = slices.Compact(config.CheckContexts)
	canonical, err := json.Marshal(config)
	if err != nil {
		return fail()
	}
	return config, string(canonical), nil
}

func ValidMergeGatePath(path string) bool {
	return validRepoPath(path) && !strings.ContainsFunc(path, unicode.IsControl)
}

func (c ProtectedPathConfig) Match(branch string, paths []string, complete bool) (MatchResult, []string) {
	raw, err := json.Marshal(c)
	if err != nil {
		return Unresolved, nil
	}
	if _, _, err := ParseProtectedPathConfig(raw); err != nil {
		return Unresolved, nil
	}
	if !c.Enabled {
		return NotMatched, nil
	}
	if branch == "" || !complete || len(paths) > MaxContextPaths {
		return Unresolved, nil
	}
	for _, path := range paths {
		if !ValidMergeGatePath(path) {
			return Unresolved, nil
		}
	}
	if c.BranchPattern != "" && !matchesAny([]string{c.BranchPattern}, branch) {
		return NotMatched, nil
	}
	var matched []string
	for _, path := range paths {
		if matchesAny([]string{c.PathPattern}, path) {
			matched = append(matched, path)
		}
	}
	slices.Sort(matched)
	matched = slices.Compact(matched)
	if len(matched) == 0 {
		return NotMatched, nil
	}
	return Matched, matched
}
