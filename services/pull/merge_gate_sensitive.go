// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"time"
	"unicode/utf8"

	"gitea.dev/models/db"
	issues_model "gitea.dev/models/issues"
	organization_model "gitea.dev/models/organization"
	access_model "gitea.dev/models/perm/access"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	authz_service "gitea.dev/services/enterpriseauthz"
)

type mergeGateRuleEvidence struct {
	ID           int64  `json:"id"`
	Revision     int64  `json:"revision"`
	RoleID       int64  `json:"role_id"`
	RoleRevision int64  `json:"role_revision"`
	PathsHash    string `json:"paths_hash"`
	PathCount    int    `json:"path_count"`
	Unresolved   bool   `json:"unresolved"`
}

type mergeGateReviewEvidence struct {
	ID         int64                   `json:"id"`
	ReviewerID int64                   `json:"reviewer_id"`
	CommitID   string                  `json:"commit_id"`
	Type       issues_model.ReviewType `json:"type"`
	Stale      bool                    `json:"stale"`
	Dismissed  bool                    `json:"dismissed"`
	Eligible   bool                    `json:"eligible"`
	Roles      []int64                 `json:"roles"`
}

type mergeGateSensitiveFacts struct {
	Facts     []authz.MergeGateFact     `json:"facts"`
	Contexts  []authz.MergeGateContext  `json:"contexts"`
	Rules     []mergeGateRuleEvidence   `json:"rules"`
	Reviews   []mergeGateReviewEvidence `json:"reviews"`
	PathsHash string                    `json:"paths_hash"`
	PathCount int                       `json:"path_count"`
}

func mergeGatePathsHash(paths []string) string {
	raw, _ := json.Marshal(paths)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}

func readMergeGateBaseCodeowners(ctx context.Context, repo *git.Repository, baseSHA string) ([]*issues_model.CodeOwnerRule, error) {
	commit, err := repo.GetCommit(ctx, baseSHA)
	if err != nil {
		return nil, err
	}
	for _, path := range []string{"CODEOWNERS", "docs/CODEOWNERS", ".gitea/CODEOWNERS"} {
		blob, err := commit.GetBlobByPath(ctx, repo, path)
		if git.IsErrNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		limit := setting.UI.MaxDisplayFileSize
		if limit <= 0 || blob.Size(ctx) > limit {
			return nil, errors.New("merge_gate_codeowners_incomplete")
		}
		data, err := blob.GetBlobContent(ctx, limit)
		if err != nil {
			return nil, err
		}
		if !utf8.ValidString(data) {
			return nil, errors.New("merge_gate_codeowners_invalid")
		}
		return issues_model.GetCodeOwnersForSensitivePaths(ctx, data)
	}
	return nil, nil
}

func collectMergeGateSensitivePaths(ctx context.Context, pr *issues_model.PullRequest, repo *git.Repository, baseSHA, headSHA, mergeBaseSHA string) (mergeGateSensitiveFacts, error) {
	var result mergeGateSensitiveFacts
	if !setting.EnterpriseMergeGate.Enabled {
		return result, nil
	}
	if pr == nil || repo == nil {
		return result, errMergeGatePathsIncomplete
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	paths, err := collectMergeGatePaths(ctx, repo, mergeBaseSHA, headSHA)
	if err != nil {
		return result, err
	}
	result.PathsHash, result.PathCount = mergeGatePathsHash(paths), len(paths)
	collect := func(tx context.Context) error {
		current := *pr
		current.BaseRepo = nil
		if err := current.LoadBaseRepo(tx); err != nil {
			return err
		}
		current.Issue = nil
		if err := current.LoadIssue(tx); err != nil {
			return err
		}
		policies, err := authz_service.EffectiveProtectedPathRules(tx, current.BaseRepoID)
		if err != nil {
			return err
		}
		type matchedPolicy struct {
			policy authz_service.ProtectedPathPolicy
			paths  []string
		}
		var matched []matchedPolicy
		for _, policy := range policies {
			match, paths := policy.Config.Match(current.BaseBranch, paths, true)
			if match == authz.Unresolved {
				return errMergeGatePathsIncomplete
			}
			if match != authz.Matched {
				continue
			}
			result.Rules = append(result.Rules, mergeGateRuleEvidence{ID: policy.Rule.ID, Revision: policy.Rule.Revision, RoleID: policy.Rule.RequiredRoleID, RoleRevision: policy.RoleRevision, PathsHash: mergeGatePathsHash(paths), PathCount: len(paths), Unresolved: policy.Unresolved})
			for _, context := range policy.Config.CheckContexts {
				result.Contexts = append(result.Contexts, authz.MergeGateContext{Context: context, Source: "path", ReferenceID: policy.Rule.ID})
			}
			if policy.Unresolved {
				result.Facts = append(result.Facts, authz.MergeGateFact{Code: "policy_unresolved", Source: "path", ReferenceID: policy.Rule.ID, State: "failed"})
				continue
			}
			matched = append(matched, matchedPolicy{policy: policy, paths: paths})
		}
		if len(matched) == 0 {
			return nil
		}
		owners, err := readMergeGateBaseCodeowners(tx, repo, baseSHA)
		if err != nil {
			return err
		}
		reviews, err := issues_model.FindLatestReviews(tx, issues_model.FindReviewOptions{IssueID: current.IssueID, Types: []issues_model.ReviewType{issues_model.ReviewTypeApprove, issues_model.ReviewTypeReject, issues_model.ReviewTypeRequest}})
		if err != nil {
			return err
		}
		if len(reviews) > authz.MaxMergeGateFacts {
			return errors.New("merge_gate_reviews_limit_exceeded")
		}
		approved := map[int64]bool{}
		reviewRoles := map[int64][]int64{}
		for _, review := range reviews {
			evidence := mergeGateReviewEvidence{ID: review.ID, ReviewerID: review.ReviewerID, CommitID: review.CommitID, Type: review.Type, Stale: review.Stale, Dismissed: review.Dismissed}
			if review.Type == issues_model.ReviewTypeApprove && !review.Stale && !review.Dismissed && review.CommitID == headSHA && review.ReviewerID > 0 && review.ReviewerID != current.Issue.PosterID {
				reviewer, err := user_model.GetUserByID(tx, review.ReviewerID)
				if err != nil && !user_model.IsErrUserNotExist(err) {
					return err
				}
				if err == nil && reviewer.IsIndividual() && reviewer.IsActive && !reviewer.ProhibitLogin {
					if reviewer.IsAdmin {
						reviewer.IsAdmin, err = access_model.HasSystemManagementAuthority(tx, reviewer)
						if err != nil {
							return err
						}
					}
					permission, err := access_model.GetDoerRepoPermission(tx, current.BaseRepo, reviewer)
					if err != nil {
						return err
					}
					if permission.CanRead(unit.TypeCode) && permission.CanRead(unit.TypePullRequests) {
						evidence.Eligible = true
						evidence.Roles, err = authz_service.MergeGateReviewerRoles(tx, reviewer.ID, current.BaseRepo)
						if err != nil {
							return err
						}
						approved[reviewer.ID] = true
						reviewRoles[reviewer.ID] = evidence.Roles
					}
				}
			}
			result.Reviews = append(result.Reviews, evidence)
		}
		var matchedPaths []string
		for _, entry := range matched {
			matchedPaths = append(matchedPaths, entry.paths...)
		}
		slices.Sort(matchedPaths)
		coverage, err := mergeGateCodeownerCoverage(tx, slices.Compact(matchedPaths), owners, approved)
		if err != nil {
			return err
		}
		for _, entry := range matched {
			if err := tx.Err(); err != nil {
				return err
			}
			roleApproved := false
			for _, roles := range reviewRoles {
				roleApproved = roleApproved || slices.Contains(roles, entry.policy.Rule.RequiredRoleID)
			}
			ownersApproved := true
			for _, path := range entry.paths {
				ownersApproved = ownersApproved && coverage[path]
			}

			state := "failed"
			if roleApproved || ownersApproved {
				state = "passed"
			}
			result.Facts = append(result.Facts, authz.MergeGateFact{Code: "sensitive_path_approval", Source: "path", ReferenceID: entry.policy.Rule.ID, State: state})
		}
		return nil
	}
	if db.InTransaction(ctx) {
		err = collect(ctx)
	} else {
		err = db.WithIndependentReadTx(ctx, collect)
	}
	if err != nil {
		return mergeGateSensitiveFacts{}, err
	}
	return result, nil
}

func mergeGateCodeownerCoverage(ctx context.Context, paths []string, owners []*issues_model.CodeOwnerRule, approved map[int64]bool) (map[string]bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(paths) > authz.MaxMergeGateFacts || len(owners) > authz.MaxMergeGateFacts {
		return nil, errors.New("merge_gate_codeowners_limit_exceeded")
	}
	coverage := make(map[string]bool, len(paths))
	teams := map[int64][]*user_model.User{}
	for _, path := range paths {
		if _, seen := coverage[path]; seen {
			continue
		}
		covered, allApproved := false, true
		for _, owner := range owners {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if owner == nil || owner.Rule == nil {
				return nil, errors.New("merge_gate_codeowners_invalid")
			}
			match, err := owner.Rule.MatchString(path)
			if err != nil {
				return nil, err
			}
			if match == owner.Negative {
				continue
			}
			covered = true
			ruleApproved := slices.ContainsFunc(owner.Users, func(user *user_model.User) bool { return approved[user.ID] })
			for _, team := range owner.Teams {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				members, ok := teams[team.ID]
				if !ok {
					fresh, err := organization_model.GetTeamByID(ctx, team.ID)
					if err != nil {
						return nil, err
					}
					if err := fresh.LoadMembers(ctx); err != nil {
						return nil, err
					}
					members = fresh.Members
					teams[team.ID] = members
				}
				ruleApproved = ruleApproved || slices.ContainsFunc(members, func(user *user_model.User) bool { return approved[user.ID] })
			}
			allApproved = allApproved && ruleApproved
		}
		coverage[path] = covered && allApproved
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return coverage, nil
}
