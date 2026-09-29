// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package repository

import (
	"context"
	"errors"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	"gitea.dev/models/perm"
	repo_model "gitea.dev/models/repo"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/timeutil"
	"gitea.dev/modules/util"
	"gitea.dev/services/audit"
)

const enterprisePersonalRepoQuota = 10

var (
	ErrEnterpriseOrgRepoRequiresApproval           = util.NewPermissionDeniedErrorf("organization repositories require Enterprise WeCom super-admin approval")
	ErrEnterpriseOrgRepoApprovalRequiresSuperAdmin = util.NewPermissionDeniedErrorf("organization repository approval requires Enterprise WeCom super administrator")
	ErrEnterpriseOrgRepoRequestNotPending          = util.NewInvalidArgumentErrorf("organization repository request is not pending")
	ErrEnterpriseRepoAuthorizationDenied           = util.NewPermissionDeniedErrorf("repository authorization changes require repository creator, owner-level permission, or Enterprise WeCom super administrator")
	ErrEnterprisePersonalRepoQuotaExceeded         = util.NewPermissionDeniedErrorf("personal repository quota exceeded")
	ErrEnterpriseRepoOwnerDenied                   = util.NewPermissionDeniedErrorf("personal repositories must be created in the actor's own namespace")
)

type OrganizationRepositoryRequestOptions struct {
	Name        string
	Description string
	Reason      string
}

func enforceEnterpriseRepoCreationGovernance(ctx context.Context, doer, owner *user_model.User, opts *CreateRepoOptions) error {
	if !setting.EnterpriseWeCom.Enabled || opts == nil {
		return nil
	}
	if doer == nil || owner == nil {
		return util.ErrPermissionDenied
	}
	requestedPrivate := opts.IsPrivate
	opts.IsPrivate = true
	if !requestedPrivate {
		recordEnterpriseRepoVisibilityEnforced(ctx, doer, owner)
	}
	if owner.IsOrganization() {
		superAdmin, err := wecom_model.IsActiveManagementAuthorityBoundUser(ctx, setting.EnterpriseWeCom.CorpID, setting.EnterpriseWeCom.AgentID, doer.ID)
		if err != nil {
			return err
		}
		if !superAdmin {
			return ErrEnterpriseOrgRepoRequiresApproval
		}
		return nil
	}
	if doer.ID != owner.ID {
		return ErrEnterpriseRepoOwnerDenied
	}
	count, err := repo_model.CountRepositories(ctx, repo_model.CountRepositoryOptions{OwnerID: owner.ID})
	if err != nil {
		return err
	}
	if count >= enterprisePersonalRepoQuota {
		audit.RecordAs(ctx, doer, audit_model.EnterpriseWeComPersonalRepoQuotaDeny, owner,
			"namespace_id", owner.ID,
			"quota", enterprisePersonalRepoQuota,
			"current_count", count,
			"outcome", "denied",
		)
		return ErrEnterprisePersonalRepoQuotaExceeded
	}
	return nil
}

func isEnterpriseWeComSuperAdmin(ctx context.Context, user *user_model.User) (bool, error) {
	if !setting.EnterpriseWeCom.Enabled || user == nil {
		return false, nil
	}
	return wecom_model.IsActiveManagementAuthorityBoundUser(ctx, setting.EnterpriseWeCom.CorpID, setting.EnterpriseWeCom.AgentID, user.ID)
}

func SubmitOrganizationRepositoryRequest(ctx context.Context, requester, org *user_model.User, opts OrganizationRepositoryRequestOptions) (*wecom_model.OrgRepoRequest, error) {
	if !setting.EnterpriseWeCom.Enabled {
		return nil, util.ErrPermissionDenied
	}
	if requester == nil || org == nil || !org.IsOrganization() {
		return nil, util.ErrInvalidArgument
	}
	if err := repo_model.IsUsableRepoName(opts.Name); err != nil {
		return nil, err
	}
	has, err := repo_model.IsRepositoryModelExist(ctx, org, opts.Name)
	if err != nil {
		return nil, err
	}
	if has {
		return nil, repo_model.ErrRepoAlreadyExist{Uname: org.Name, Name: opts.Name}
	}
	request := &wecom_model.OrgRepoRequest{
		OrgID:       org.ID,
		RequesterID: requester.ID,
		Name:        opts.Name,
		Description: opts.Description,
		Reason:      opts.Reason,
		Status:      wecom_model.OrgRepoRequestStatusPending,
	}
	if err := db.Insert(ctx, request); err != nil {
		return nil, err
	}
	audit.RecordAs(ctx, requester, audit_model.EnterpriseWeComOrgRepoRequest, org,
		"request_id", request.ID,
		"outcome", "submitted",
		"repository", request.Name,
		"org_id", org.ID,
	)
	return request, nil
}

func ApproveOrganizationRepositoryRequest(ctx context.Context, reviewer *user_model.User, requestID int64, reason string) (*repo_model.Repository, error) {
	superAdmin, err := isEnterpriseWeComSuperAdmin(ctx, reviewer)
	if err != nil {
		return nil, err
	}
	if !superAdmin {
		return nil, ErrEnterpriseOrgRepoApprovalRequiresSuperAdmin
	}
	request := &wecom_model.OrgRepoRequest{ID: requestID}
	has, err := db.GetEngine(ctx).Get(request)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, util.ErrNotExist
	}
	if request.Status != wecom_model.OrgRepoRequestStatusPending {
		return nil, ErrEnterpriseOrgRepoRequestNotPending
	}
	org, err := user_model.GetUserByID(ctx, request.OrgID)
	if err != nil {
		return nil, err
	}
	requester, err := user_model.GetUserByID(ctx, request.RequesterID)
	if err != nil {
		return nil, err
	}
	repo, err := CreateRepository(ctx, reviewer, org, CreateRepoOptions{
		Name:        request.Name,
		Description: request.Description,
		IsPrivate:   true,
	})
	if err != nil {
		return nil, err
	}
	if err := AddOrUpdateCollaborator(ctx, repo, requester, perm.AccessModeAdmin); err != nil {
		return nil, err
	}
	if err := upsertRepositoryGovernance(ctx, repo.ID, request.RequesterID, request.ID, wecom_model.RepositoryGovernanceSourceOrgRequest); err != nil {
		return nil, err
	}
	request.Status = wecom_model.OrgRepoRequestStatusApproved
	request.RepoID = repo.ID
	request.ReviewerID = reviewer.ID
	request.DecisionReason = reason
	request.ReviewedUnix = timeutil.TimeStampNow()
	if _, err = db.GetEngine(ctx).ID(request.ID).Cols("status", "repo_id", "reviewer_id", "decision_reason", "reviewed_unix").Update(request); err != nil {
		return nil, err
	}
	audit.RecordAs(ctx, reviewer, audit_model.EnterpriseWeComOrgRepoRequest, repo,
		"request_id", request.ID,
		"requester_id", request.RequesterID,
		"reviewer_id", reviewer.ID,
		"outcome", "approved",
		"repo_id", repo.ID,
	)
	return repo, nil
}

func RejectOrganizationRepositoryRequest(ctx context.Context, reviewer *user_model.User, requestID int64, reason string) error {
	superAdmin, err := isEnterpriseWeComSuperAdmin(ctx, reviewer)
	if err != nil {
		return err
	}
	if !superAdmin {
		return ErrEnterpriseOrgRepoApprovalRequiresSuperAdmin
	}
	request := &wecom_model.OrgRepoRequest{ID: requestID}
	has, err := db.GetEngine(ctx).Get(request)
	if err != nil {
		return err
	}
	if !has {
		return util.ErrNotExist
	}
	if request.Status != wecom_model.OrgRepoRequestStatusPending {
		return ErrEnterpriseOrgRepoRequestNotPending
	}
	request.Status = wecom_model.OrgRepoRequestStatusRejected
	request.ReviewerID = reviewer.ID
	request.DecisionReason = reason
	request.ReviewedUnix = timeutil.TimeStampNow()
	if _, err = db.GetEngine(ctx).ID(request.ID).Cols("status", "reviewer_id", "decision_reason", "reviewed_unix").Update(request); err != nil {
		return err
	}
	audit.RecordAs(ctx, reviewer, audit_model.EnterpriseWeComOrgRepoRequest, nil,
		"request_id", request.ID,
		"requester_id", request.RequesterID,
		"reviewer_id", reviewer.ID,
		"outcome", "rejected",
	)
	return nil
}

func recordEnterpriseRepositoryGovernance(ctx context.Context, doer, owner *user_model.User, repo *repo_model.Repository) error {
	if !setting.EnterpriseWeCom.Enabled || repo == nil || doer == nil || owner == nil {
		return nil
	}
	source := wecom_model.RepositoryGovernanceSourcePersonal
	if owner.IsOrganization() {
		source = wecom_model.RepositoryGovernanceSourceSuperAdminDirect
	}
	return upsertRepositoryGovernance(ctx, repo.ID, doer.ID, 0, source)
}

func upsertRepositoryGovernance(ctx context.Context, repoID, creatorID, requestID int64, source wecom_model.RepositoryGovernanceSource) error {
	row := &wecom_model.RepositoryGovernance{RepoID: repoID}
	has, err := db.GetEngine(ctx).Get(row)
	if err != nil {
		return err
	}
	row.CreatorID = creatorID
	row.RequestID = requestID
	row.Source = source
	if has {
		_, err = db.GetEngine(ctx).ID(row.ID).Cols("creator_id", "request_id", "source").Update(row)
		return err
	}
	if err := db.Insert(ctx, row); err != nil {
		if errors.Is(err, util.ErrAlreadyExist) {
			return nil
		}
		return err
	}
	return nil
}

func CheckEnterpriseRepoAuthorizationChange(ctx context.Context, actor *user_model.User, repo *repo_model.Repository) error {
	if !setting.EnterpriseWeCom.Enabled {
		return nil
	}
	if actor == nil || repo == nil {
		return ErrEnterpriseRepoAuthorizationDenied
	}
	superAdmin, err := isEnterpriseWeComSuperAdmin(ctx, actor)
	if err != nil {
		return err
	}
	if superAdmin {
		return nil
	}
	governance := &wecom_model.RepositoryGovernance{RepoID: repo.ID}
	has, err := db.GetEngine(ctx).Get(governance)
	if err != nil {
		return err
	}
	if has && governance.CreatorID == actor.ID {
		return nil
	}
	ownerLevel, err := hasRepositoryOwnerLevelPermission(ctx, actor, repo)
	if err != nil {
		return err
	}
	if ownerLevel {
		return nil
	}
	audit.RecordAs(ctx, actor, audit_model.EnterpriseWeComRepoAuthorizationDeny, repo,
		"reason", "actor_not_creator_owner_or_super_admin",
		"outcome", "denied",
	)
	return ErrEnterpriseRepoAuthorizationDenied
}

func hasRepositoryOwnerLevelPermission(ctx context.Context, actor *user_model.User, repo *repo_model.Repository) (bool, error) {
	if err := repo.LoadOwner(ctx); err != nil {
		return false, err
	}
	if !repo.Owner.IsOrganization() {
		return actor.ID == repo.OwnerID, nil
	}
	teams, err := organization.GetUserRepoTeams(ctx, repo.OwnerID, actor.ID, repo.ID)
	if err != nil {
		return false, err
	}
	for _, team := range teams {
		if team.IsOwnerTeam() || team.AccessMode == perm.AccessModeOwner {
			return true, nil
		}
	}
	return false, nil
}

func recordEnterpriseRepoVisibilityEnforced(ctx context.Context, doer, owner *user_model.User) {
	audit.RecordAs(ctx, doer, audit_model.EnterpriseWeComRepoVisibilityEnforce, owner,
		"owner_id", owner.ID,
		"owner_type", util.Iif(owner.IsOrganization(), "organization", "user"),
		"outcome", "private_enforced",
	)
}
