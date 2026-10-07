// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package pull

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"gitea.dev/models/db"
	git_model "gitea.dev/models/git"
	issues_model "gitea.dev/models/issues"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/git"
	"gitea.dev/modules/git/gitrepo"
	"gitea.dev/modules/glob"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	asymkey_service "gitea.dev/services/asymkey"
	authz_service "gitea.dev/services/enterpriseauthz"
	issue_service "gitea.dev/services/issue"
)

type mergeGateGitContext struct {
	Repo                  gitrepo.RepositoryFacade
	HeadSHA, BaseSHA      string
	Paths                 []string
	PushProof             bool
	Manual                bool
	ManualAutomatic       bool
	TargetSHA             string
	PusherID              int64
	CredentialAttribution *authz_service.MergeGateQueueAttribution
}

type mergeGateNativeReviewEvidence struct {
	ID         int64                   `json:"id"`
	ReviewerID int64                   `json:"reviewer_id"`
	TeamID     int64                   `json:"team_id,omitempty"`
	CommitID   string                  `json:"commit_id"`
	Type       issues_model.ReviewType `json:"type"`
	Official   bool                    `json:"official"`
	Stale      bool                    `json:"stale"`
	Dismissed  bool                    `json:"dismissed"`
}

type mergeGateNativeEvidence struct {
	ProtectionID      int64                           `json:"protection_id,omitempty"`
	ProtectionUpdated int64                           `json:"protection_updated,omitempty"`
	PolicyHash        string                          `json:"policy_hash,omitempty"`
	Reviews           []mergeGateNativeReviewEvidence `json:"reviews,omitempty"`
}

func collectMergeGateNativeFacts(ctx context.Context, pr *issues_model.PullRequest, actor *user_model.User, style repo_model.MergeStyle, phase string, gitContext *mergeGateGitContext) ([]authz.MergeGateFact, error) {
	facts, _, err := collectMergeGateNativeState(ctx, pr, actor, style, phase, gitContext)
	return facts, err
}

func collectMergeGateNativeState(ctx context.Context, pr *issues_model.PullRequest, actor *user_model.User, style repo_model.MergeStyle, phase string, gitContext *mergeGateGitContext) ([]authz.MergeGateFact, mergeGateNativeEvidence, error) {
	if !setting.EnterpriseMergeGate.Enabled {
		return nil, mergeGateNativeEvidence{}, nil
	}
	if pr == nil || actor == nil || pr.ID <= 0 || actor.ID <= 0 {
		return nil, mergeGateNativeEvidence{}, errors.New("merge_gate_native_context_invalid")
	}
	var facts []authz.MergeGateFact
	var evidence mergeGateNativeEvidence
	collect := func(tx context.Context) error {
		current, err := issues_model.GetPullRequestByID(tx, pr.ID)
		if err != nil {
			return err
		}
		if current.BaseRepoID != pr.BaseRepoID {
			return errors.New("merge_gate_native_context_changed")
		}
		if err := current.LoadBaseRepo(tx); err != nil {
			return err
		}
		if err := current.LoadIssue(tx); err != nil {
			return err
		}
		reviewer, err := user_model.GetUserByID(tx, actor.ID)
		if err != nil {
			return err
		}
		reviewer.ExtDoerData = actor.ExtDoerData
		if reviewer.IsAdmin {
			reviewer.IsAdmin, err = access_model.HasSystemManagementAuthority(tx, reviewer)
			if err != nil {
				return err
			}
		}
		add := func(code string, passed bool, err error) {
			state := "failed"
			if err != nil {
				state = "error"
			} else if passed {
				state = "passed"
			}
			facts = append(facts, authz.MergeGateFact{Code: code, Source: "native", State: state})
		}
		add("actor_invalid", reviewer.IsIndividual() && reviewer.IsActive && !reviewer.ProhibitLogin && reviewer.ExtDoerData == nil, nil)
		permission, err := access_model.GetDoerRepoPermission(tx, current.BaseRepo, reviewer)
		if err != nil {
			return err
		}
		pb, err := git_model.GetFirstMatchProtectedBranchRule(tx, current.BaseRepoID, current.BaseBranch)
		if err != nil {
			return err
		}
		if pb != nil {
			policy := *pb
			policy.Repo = nil
			raw, err := json.Marshal(policy)
			if err != nil {
				return err
			}
			evidence.ProtectionID, evidence.ProtectionUpdated = pb.ID, int64(pb.UpdatedUnix)
			evidence.PolicyHash = fmt.Sprintf("%x", sha256.Sum256(raw))
			var reviews []*issues_model.Review
			err = db.GetEngine(tx).Where("issue_id = ?", current.IssueID).Asc("id").Limit(authz.MaxMergeGateFacts + 1).Find(&reviews)
			if err != nil {
				return err
			}
			if len(reviews) > authz.MaxMergeGateFacts {
				return errors.New("merge_gate_native_reviews_limit_exceeded")
			}
			for _, review := range reviews {
				evidence.Reviews = append(evidence.Reviews, mergeGateNativeReviewEvidence{ID: review.ID, ReviewerID: review.ReviewerID, TeamID: review.ReviewerTeamID, CommitID: review.CommitID, Type: review.Type, Official: review.Official, Stale: review.Stale, Dismissed: review.Dismissed})
			}
		}
		allowed := permission.CanWrite(unit.TypeCode)
		if pb != nil {
			allowed, err = git_model.IsUserMergeWhitelistedWithError(tx, pb, reviewer.ID, permission)
		}
		add("native_permission_denied", allowed && permission.CanRead(unit.TypeCode) && permission.CanRead(unit.TypePullRequests) && !current.BaseRepo.IsArchived && !current.BaseRepo.IsMirror, err)
		add("closed", !current.Issue.IsClosed, nil)
		add("merged", !current.HasMerged, nil)
		add("draft", !issues_model.HasWorkInProgressPrefix(current.Issue.Title), nil)
		if phase != "manual_recognition" {
			add("checking", !current.IsChecking(), nil)
			add("conflict", current.IsChecking() || current.IsStatusMergeable() || current.IsEmpty(), nil)
		}
		prUnit, err := current.BaseRepo.GetUnit(tx, unit.TypePullRequests)
		styleAllowed := err == nil && prUnit.PullRequestsConfig().IsMergeStyleAllowed(style)
		if phase == "manual_recognition" && gitContext != nil && gitContext.ManualAutomatic && err == nil {
			styleAllowed = prUnit.PullRequestsConfig().AutodetectManualMerge
		}
		add("merge_style_denied", styleAllowed, err)
		noDependencies, err := issues_model.IssueNoDependenciesLeft(tx, current.Issue)
		add("dependency", noDependencies, err)
		unresolved, err := issues_model.HasUnresolvedReviewConversation(tx, current.IssueID)
		add("unresolved_conversation", !unresolved, err)
		if pb != nil {
			enough, err := issues_model.HasEnoughApprovalsWithError(tx, pb, current)
			add("required_approvals", enough, err)
			rejected, err := issues_model.MergeBlockedByRejectedReviewWithError(tx, pb, current)
			add("rejected_review", !rejected, err)
			requested, err := issues_model.MergeBlockedByOfficialReviewRequestsWithError(tx, pb, current)
			add("official_review_request", !requested, err)
			outdated, protected, gitErr := mergeGateCurrentGitGuards(tx, pb, gitContext)
			add("outdated_branch", !outdated, gitErr)
			add("protected_files", !protected, gitErr)
			owners, err := mergeGateNativeCodeownerReviews(tx, pb, current, gitContext)
			add("codeowners_review", owners, err)
			if phase != "manual_recognition" {
				err := checkMergeGateSigningRequirements(tx, pb, current, reviewer, style, gitContext)
				if err != nil && !errors.Is(err, ErrHeadCommitsNotAllVerified) && !asymkey_service.IsErrWontSign(err) {
					add("signing_required", false, err)
				} else {
					add("signing_required", err == nil, nil)
				}
			}
		}
		return nil
	}
	var err error
	if db.InTransaction(ctx) {
		err = collect(ctx)
	} else {
		err = db.WithIndependentReadTx(ctx, collect)
	}
	if err != nil {
		return nil, evidence, err
	}
	return facts, evidence, nil
}

func mergeGateCurrentGitGuards(ctx context.Context, pb *git_model.ProtectedBranch, current *mergeGateGitContext) (outdated, protected bool, err error) {
	var patterns []glob.Glob
	for expression := range strings.SplitSeq(strings.ToLower(pb.ProtectedFilePatterns), ";") {
		expression = strings.TrimSpace(expression)
		if expression == "" {
			continue
		}
		pattern, err := glob.Compile(expression, '.', '/')
		if err != nil {
			return false, false, err
		}
		patterns = append(patterns, pattern)
	}
	if !pb.BlockOnOutdatedBranch && len(patterns) == 0 {
		return false, false, nil
	}
	if current == nil || current.Repo == nil || current.Paths == nil || !git.IsStringValidObjectID(nil, current.BaseSHA) || !git.IsStringValidObjectID(nil, current.HeadSHA) {
		return false, false, errMergeGatePathsIncomplete
	}
	for _, path := range current.Paths {
		if err := ctx.Err(); err != nil {
			return false, false, err
		}
		for _, pattern := range patterns {
			protected = protected || pattern.Match(strings.ToLower(path))
		}
	}
	if pb.BlockOnOutdatedBranch {
		diverging, err := git.GetDivergingCommits(ctx, current.Repo, current.BaseSHA, current.HeadSHA)
		if err != nil {
			return false, false, err
		}
		outdated = diverging.Behind > 0
	}
	return outdated, protected, nil
}

func mergeGateNativeCodeownerReviews(ctx context.Context, pb *git_model.ProtectedBranch, pr *issues_model.PullRequest, current *mergeGateGitContext) (bool, error) {
	if !pb.BlockOnCodeownerReviews {
		return true, nil
	}
	if current == nil || current.Repo == nil {
		return false, errMergeGatePathsIncomplete
	}
	repo, err := git.OpenRepository(ctx, current.Repo)
	if err != nil {
		return false, err
	}
	defer repo.Close()
	return issue_service.HasAllRequiredCodeownerReviewsAt(ctx, pb, pr, repo, current.BaseSHA, current.Paths)
}

func checkMergeGateSigningRequirements(ctx context.Context, pb *git_model.ProtectedBranch, pr *issues_model.PullRequest, actor *user_model.User, style repo_model.MergeStyle, current *mergeGateGitContext) error {
	if !pb.RequireSignedCommits {
		return nil
	}
	if current == nil || current.Repo == nil || !git.IsStringValidObjectID(nil, current.BaseSHA) || !git.IsStringValidObjectID(nil, current.HeadSHA) || git.IsEmptyCommitID(current.BaseSHA) || git.IsEmptyCommitID(current.HeadSHA) {
		return errMergeGatePathsIncomplete
	}
	repo, err := git.OpenRepository(ctx, current.Repo)
	if err != nil {
		return err
	}
	defer repo.Close()
	if style == repo_model.MergeStyleFastForwardOnly || style == repo_model.MergeStyleMerge {
		verified, err := asymkey_service.AllCommitsVerifiedAt(ctx, repo, current.BaseSHA, current.HeadSHA)
		if err != nil {
			return err
		}
		if !verified {
			return ErrHeadCommitsNotAllVerified
		}
	}
	if style != repo_model.MergeStyleFastForwardOnly {
		_, _, _, err = asymkey_service.SignMerge(ctx, pr, actor, repo, current.BaseSHA, current.HeadSHA)
	}
	return err
}
