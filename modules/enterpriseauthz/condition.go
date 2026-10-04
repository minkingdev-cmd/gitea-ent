// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json" //nolint:depguard // Token-level decoding is required to reject duplicate condition fields.
	"errors"
	"io"
	"slices"
	"strings"
	"unicode/utf8"

	"gitea.dev/modules/glob"
)

const (
	MaxConditionBytes  = 8 * 1024
	MaxContextPaths    = 1024
	MaxRolePermissions = 128
	MaxBodyBytes       = 1024 * 1024
	MaxSnapshotBytes   = 64 * 1024
)

type Condition struct {
	BranchPattern  []string `json:"branch_pattern,omitempty"`
	PathPattern    []string `json:"path_pattern,omitempty"`
	RequestSources []string `json:"request_sources,omitempty"`
}

type ConditionContext struct {
	Branch        string
	BranchKnown   bool
	Paths         []string
	PathsComplete bool
	Source        string
}

type MatchResult string

const (
	Matched    MatchResult = "matched"
	NotMatched MatchResult = "not_matched"
	Unresolved MatchResult = "unresolved"
)

var requestSources = []string{"web", "api", "git_http", "ssh", "file_editor", "receive_hook", "auto_merge", "system", "diagnostic"}

func RequestSources() []string { return slices.Clone(requestSources) }

func ValidSource(source string) bool { return slices.Contains(requestSources, source) }

func ParseCondition(data []byte) (*Condition, string, string, error) {
	invalid := errors.New("invalid_condition")
	if len(data) > MaxConditionBytes || !utf8.Valid(data) {
		return nil, "", "", invalid
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	first, err := dec.Token()
	if err != nil || first != json.Delim('{') {
		return nil, "", "", invalid
	}
	fields := map[string][]string{}
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return nil, "", "", invalid
		}
		key, ok := token.(string)
		if !ok || !slices.Contains([]string{"branch_pattern", "path_pattern", "request_sources"}, key) {
			return nil, "", "", invalid
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, "", "", invalid
		}
		var values []string
		if err := dec.Decode(&values); err != nil || len(values) == 0 || len(values) > 16 {
			return nil, "", "", invalid
		}
		for _, value := range values {
			if value == "" || len(value) > 256 || strings.ContainsRune(value, 0) {
				return nil, "", "", invalid
			}
			if key == "request_sources" {
				if !ValidSource(value) {
					return nil, "", "", invalid
				}
			} else if _, err := glob.Compile(value, '/'); err != nil {
				return nil, "", "", invalid
			}
		}
		slices.Sort(values)
		fields[key] = slices.Compact(values)
	}
	if _, err := dec.Token(); err != nil {
		return nil, "", "", invalid
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, "", "", invalid
	}
	c := &Condition{fields["branch_pattern"], fields["path_pattern"], fields["request_sources"]}
	normalized, err := json.Marshal(c)
	if err != nil {
		return nil, "", "", invalid
	}
	hash := sha256.Sum256(normalized)
	return c, string(normalized), hex.EncodeToString(hash[:]), nil
}

func validRepoPath(path string) bool {
	if path == "" || strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\\x00") || !utf8.ValidString(path) {
		return false
	}
	for part := range strings.SplitSeq(path, "/") {
		if part == ".." || part == "." || part == "" {
			return false
		}
	}
	return true
}

func matchesAny(patterns []string, value string) bool {
	for _, pattern := range patterns {
		g, err := glob.Compile(pattern, '/')
		if err == nil && g.Match(value) {
			return true
		}
	}
	return false
}

func (c *Condition) Match(ctx ConditionContext) MatchResult {
	if len(c.BranchPattern) != 0 && (!ctx.BranchKnown || ctx.Branch == "") {
		return Unresolved
	}
	if len(c.PathPattern) != 0 {
		if !ctx.PathsComplete || len(ctx.Paths) == 0 || len(ctx.Paths) > MaxContextPaths {
			return Unresolved
		}
		for _, path := range ctx.Paths {
			if !validRepoPath(path) {
				return Unresolved
			}
		}
	}
	if len(c.RequestSources) != 0 && !ValidSource(ctx.Source) {
		return Unresolved
	}
	if len(c.BranchPattern) != 0 && !matchesAny(c.BranchPattern, ctx.Branch) {
		return NotMatched
	}
	if len(c.RequestSources) != 0 && !slices.Contains(c.RequestSources, ctx.Source) {
		return NotMatched
	}
	if len(c.PathPattern) != 0 {
		for _, path := range ctx.Paths {
			if !matchesAny(c.PathPattern, path) {
				return NotMatched
			}
		}
	}
	return Matched
}
