// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"slices"
	"strings"

	authz_model "gitea.dev/models/enterpriseauthz"
	git_model "gitea.dev/models/git"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func statusCheckContextsEqual(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

func hasStatusChecks(rule *git_model.ProtectedBranch) bool {
	return rule != nil && (rule.EnableStatusCheck || len(rule.StatusCheckContexts) > 0)
}

func requireStatusChecksIntent(ctx context.Context, repoID int64, old, next *git_model.ProtectedBranch) error {
	if !setting.EnterpriseAuthz.Enabled {
		return nil
	}
	changed := old == nil && hasStatusChecks(next) || next == nil && hasStatusChecks(old)
	if old != nil && next != nil {
		changed = old.EnableStatusCheck != next.EnableStatusCheck || !statusCheckContextsEqual(old.StatusCheckContexts, next.StatusCheckContexts) || (hasStatusChecks(old) || hasStatusChecks(next)) && (old.RuleName != next.RuleName || old.Priority != next.Priority)
	}
	if !changed {
		return nil
	}
	if err := authz_service.RequireRepoFeature(ctx, repoID, authz.FeatureRequiredStatusChecks); err != nil {
		return err
	}
	policy, err := authz_service.GetFeaturePolicy(ctx, authz.FeatureRequiredStatusChecks, authz_model.Scope{Type: authz_model.ScopeRepo, ID: repoID})
	if err != nil {
		return authz_service.FeatureGuardError(err)
	}
	denied := policy.Effective.State == authz.FeatureDisabled
	if policy.Effective.State == authz.FeatureRequired {
		if hasStatusChecks(old) && (next == nil || !next.EnableStatusCheck || len(old.StatusCheckContexts) > 0 && len(next.StatusCheckContexts) == 0 || old.RuleName != next.RuleName) {
			denied = true
		}
		if hasStatusChecks(next) {
			for _, mandatory := range policy.Effective.Config.CheckContexts {
				if !next.EnableStatusCheck || !slices.Contains(next.StatusCheckContexts, mandatory) {
					denied = true
				}
			}
		}
	}
	if denied {
		return authz_service.FeatureIntentDenied(ctx, repoID, authz.FeatureRequiredStatusChecks, policy, "feature_status_checks_locked")
	}
	return nil
}

func protectionPriorityChecksChanged(old, next []*git_model.ProtectedBranch) bool {
	for _, a := range old {
		if !hasStatusChecks(a) {
			continue
		}
		for _, b := range next {
			if b.ID == a.ID || b.Priority > priorityOf(next, a.ID) || !protectionRulesOverlap(a, b) {
				continue
			}
			before := protectionRuleByID(old, b.ID)
			if before == nil || before.Priority > a.Priority || before.RuleName != b.RuleName {
				return true
			}
		}
		for _, b := range old {
			if b.ID != a.ID && protectionRulesOverlap(a, b) && (a.Priority < b.Priority) != (priorityOf(next, a.ID) < priorityOf(next, b.ID)) {
				return true
			}
		}
	}
	return false
}

func protectionRuleByID(rules []*git_model.ProtectedBranch, id int64) *git_model.ProtectedBranch {
	for _, rule := range rules {
		if rule.ID == id {
			return rule
		}
	}
	return nil
}

func priorityOf(rules []*git_model.ProtectedBranch, id int64) int64 {
	for _, rule := range rules {
		if rule.ID == id {
			return rule.Priority
		}
	}
	return 0
}

func requireStatusChecksPriority(ctx context.Context, repoID int64, old, next []*git_model.ProtectedBranch) error {
	if !setting.EnterpriseAuthz.Enabled || !protectionPriorityChecksChanged(old, next) {
		return nil
	}
	if err := authz_service.RequireRepoFeature(ctx, repoID, authz.FeatureRequiredStatusChecks); err != nil {
		return err
	}
	policy, err := authz_service.GetFeaturePolicy(ctx, authz.FeatureRequiredStatusChecks, authz_model.Scope{Type: authz_model.ScopeRepo, ID: repoID})
	if err != nil {
		return authz_service.FeatureGuardError(err)
	}
	denied := policy.Effective.State == authz.FeatureDisabled
	if policy.Effective.State == authz.FeatureRequired {
		for _, a := range old {
			if !hasStatusChecks(a) {
				continue
			}
			for _, b := range next {
				if b.ID == a.ID || b.Priority > priorityOf(next, a.ID) || !protectionRulesOverlap(a, b) {
					continue
				}
				before := protectionRuleByID(old, b.ID)
				if before != nil && before.Priority < a.Priority && before.RuleName == b.RuleName {
					continue
				}
				if !b.EnableStatusCheck {
					denied = true
				}
				for _, mandatory := range append(slices.Clone(a.StatusCheckContexts), policy.Effective.Config.CheckContexts...) {
					if !slices.Contains(b.StatusCheckContexts, mandatory) {
						denied = true
					}
				}
			}
		}
	}
	if denied {
		return authz_service.FeatureIntentDenied(ctx, repoID, authz.FeatureRequiredStatusChecks, policy, "feature_status_checks_locked")
	}
	return nil
}

func protectionPriorities(ctx context.Context, repoID int64, ids []int64) ([]*git_model.ProtectedBranch, []*git_model.ProtectedBranch, error) {
	old, err := git_model.FindRepoProtectedBranchRules(ctx, repoID)
	if err != nil {
		return nil, nil, err
	}
	next := make([]*git_model.ProtectedBranch, len(old))
	for i, rule := range old {
		intendedRule := *rule
		next[i] = &intendedRule
	}
	for i, id := range ids {
		for _, rule := range next {
			if rule.ID == id {
				rule.Priority = int64(i + 1)
			}
		}
	}
	return old, next, nil
}

func RequiredChecksPriorityChanged(ctx context.Context, repoID int64, ids []int64) (bool, error) {
	old, next, err := protectionPriorities(ctx, repoID, ids)
	if err != nil {
		return false, err
	}
	return protectionPriorityChecksChanged(old, next), nil
}

func protectionMutationRules(ctx context.Context, repoID int64, next *git_model.ProtectedBranch) ([]*git_model.ProtectedBranch, []*git_model.ProtectedBranch, error) {
	old, err := git_model.FindRepoProtectedBranchRules(ctx, repoID)
	if err != nil {
		return nil, nil, err
	}
	intended := slices.Clone(old)
	for i, rule := range intended {
		if rule.ID == next.ID && next.ID > 0 {
			intended[i] = next
			return old, intended, nil
		}
	}
	if next.Priority == 0 {
		intendedRule := *next
		for _, rule := range old {
			if rule.Priority >= intendedRule.Priority {
				intendedRule.Priority = rule.Priority + 1
			}
		}
		next = &intendedRule
	}
	return old, append(intended, next), nil
}

func protectionRulesOverlap(a, b *git_model.ProtectedBranch) bool {
	if !git_model.IsRuleNameSpecial(a.RuleName) {
		return b.Match(a.RuleName)
	}
	if !git_model.IsRuleNameSpecial(b.RuleName) {
		return a.Match(b.RuleName)
	}
	prefix := func(pattern string) string {
		if i := strings.IndexAny(pattern, "*?[{\\"); i >= 0 {
			return pattern[:i]
		}
		return pattern
	}
	ap, bp := prefix(a.RuleName), prefix(b.RuleName)
	return strings.HasPrefix(ap, bp) || strings.HasPrefix(bp, ap)
}
