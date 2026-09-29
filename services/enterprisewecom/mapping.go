// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/services/audit"
)

var ErrInvalidAuthzMapping = errors.New("invalid enterprise wecom authorization mapping")

type AuthzMappingOptions struct {
	CorpID     string
	SourceType wecom_model.AuthzSourceType
	SourceID   string
	TargetType wecom_model.AuthzTargetType
	OrgID      int64
	TeamID     int64
	ActorID    int64
}

type AuthzMappingListOptions struct {
	CorpID          string
	IncludeInactive bool
}

func CreateAuthzMapping(ctx context.Context, opts AuthzMappingOptions) (*wecom_model.AuthzMapping, error) {
	mapping, err := normalizeAndValidateAuthzMapping(ctx, opts)
	if err != nil {
		recordMappingUpdateAudit(ctx, opts.ActorID, nil, "error", "validation_failed")
		return nil, err
	}
	mapping.CreatedBy = opts.ActorID
	if err := db.Insert(ctx, mapping); err != nil {
		return nil, err
	}
	recordMappingUpdateAudit(ctx, opts.ActorID, mapping, "created", "")
	return mapping, nil
}

func UpdateAuthzMapping(ctx context.Context, id int64, opts AuthzMappingOptions) (*wecom_model.AuthzMapping, error) {
	mapping, err := normalizeAndValidateAuthzMapping(ctx, opts)
	if err != nil {
		recordMappingUpdateAudit(ctx, opts.ActorID, &wecom_model.AuthzMapping{ID: id}, "error", "validation_failed")
		return nil, err
	}
	mapping.ID = id
	_, err = db.GetEngine(ctx).ID(id).Cols("corp_id", "source_type", "source_id", "target_type", "org_id", "team_id", "is_active").Update(mapping)
	if err != nil {
		return nil, err
	}
	recordMappingUpdateAudit(ctx, opts.ActorID, mapping, "updated", "")
	return GetAuthzMapping(ctx, id)
}

func DisableAuthzMapping(ctx context.Context, id, actorID int64) error {
	mapping, err := GetAuthzMapping(ctx, id)
	if err != nil {
		return err
	}
	mapping.IsActive = false
	_, err = db.GetEngine(ctx).ID(id).Cols("is_active").Update(mapping)
	if err != nil {
		return err
	}
	recordMappingUpdateAudit(ctx, actorID, mapping, "disabled", "")
	return nil
}

func GetAuthzMapping(ctx context.Context, id int64) (*wecom_model.AuthzMapping, error) {
	mapping := &wecom_model.AuthzMapping{ID: id}
	has, err := db.GetEngine(ctx).Get(mapping)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, fmt.Errorf("%w: mapping %d does not exist", ErrInvalidAuthzMapping, id)
	}
	return mapping, nil
}

func ListAuthzMappings(ctx context.Context, opts AuthzMappingListOptions) ([]*wecom_model.AuthzMapping, error) {
	corpID := strings.TrimSpace(opts.CorpID)
	if corpID == "" {
		corpID = setting.EnterpriseWeCom.CorpID
	}
	var mappings []*wecom_model.AuthzMapping
	sess := db.GetEngine(ctx).Where("corp_id = ?", corpID).OrderBy("id ASC")
	if !opts.IncludeInactive {
		sess = sess.And("is_active = ?", true)
	}
	return mappings, sess.Find(&mappings)
}

func normalizeAndValidateAuthzMapping(ctx context.Context, opts AuthzMappingOptions) (*wecom_model.AuthzMapping, error) {
	corpID := strings.TrimSpace(opts.CorpID)
	if corpID == "" {
		corpID = setting.EnterpriseWeCom.CorpID
	}
	sourceID := strings.TrimSpace(opts.SourceID)
	if corpID == "" || sourceID == "" {
		return nil, fmt.Errorf("%w: missing corp id or source id", ErrInvalidAuthzMapping)
	}
	if err := validateMappingSource(ctx, corpID, opts.SourceType, sourceID); err != nil {
		return nil, err
	}
	orgID, teamID, err := validateMappingTarget(ctx, opts.TargetType, opts.OrgID, opts.TeamID)
	if err != nil {
		return nil, err
	}
	return &wecom_model.AuthzMapping{
		CorpID:     corpID,
		SourceType: opts.SourceType,
		SourceID:   sourceID,
		TargetType: opts.TargetType,
		OrgID:      orgID,
		TeamID:     teamID,
		IsActive:   true,
	}, nil
}

func validateMappingSource(ctx context.Context, corpID string, sourceType wecom_model.AuthzSourceType, sourceID string) error {
	switch sourceType {
	case wecom_model.AuthzSourceUser:
		_, has, err := wecom_model.GetIdentityByCorpAndUserID(ctx, corpID, sourceID)
		if err != nil {
			return err
		}
		if !has {
			return fmt.Errorf("%w: wecom user source does not exist", ErrInvalidAuthzMapping)
		}
		return nil
	case wecom_model.AuthzSourceDepartment:
		id, err := strconv.ParseInt(sourceID, 10, 64)
		if err != nil {
			return fmt.Errorf("%w: department source id must be numeric", ErrInvalidAuthzMapping)
		}
		has, err := db.GetEngine(ctx).Where("corp_id = ? AND department_id = ?", corpID, id).Exist(new(wecom_model.Department))
		if err != nil {
			return err
		}
		if !has {
			return fmt.Errorf("%w: wecom department source does not exist", ErrInvalidAuthzMapping)
		}
		return nil
	case wecom_model.AuthzSourceTag:
		id, err := strconv.ParseInt(sourceID, 10, 64)
		if err != nil {
			return fmt.Errorf("%w: tag source id must be numeric", ErrInvalidAuthzMapping)
		}
		has, err := db.GetEngine(ctx).Where("corp_id = ? AND tag_id = ?", corpID, id).Exist(new(wecom_model.Tag))
		if err != nil {
			return err
		}
		if !has {
			return fmt.Errorf("%w: wecom tag source does not exist", ErrInvalidAuthzMapping)
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported source type", ErrInvalidAuthzMapping)
	}
}

func validateMappingTarget(ctx context.Context, targetType wecom_model.AuthzTargetType, orgID, teamID int64) (int64, int64, error) {
	switch targetType {
	case wecom_model.AuthzTargetOrg:
		if orgID == 0 {
			return 0, 0, fmt.Errorf("%w: org target requires org id", ErrInvalidAuthzMapping)
		}
		if _, err := organization.GetOrgByID(ctx, orgID); err != nil {
			return 0, 0, fmt.Errorf("%w: org target does not exist", ErrInvalidAuthzMapping)
		}
		return orgID, 0, nil
	case wecom_model.AuthzTargetTeam:
		if teamID == 0 {
			return 0, 0, fmt.Errorf("%w: team target requires team id", ErrInvalidAuthzMapping)
		}
		team, err := organization.GetTeamByID(ctx, teamID)
		if err != nil {
			return 0, 0, fmt.Errorf("%w: team target does not exist", ErrInvalidAuthzMapping)
		}
		if orgID != 0 && team.OrgID != orgID {
			return 0, 0, fmt.Errorf("%w: team is outside target org", ErrInvalidAuthzMapping)
		}
		return team.OrgID, team.ID, nil
	default:
		return 0, 0, fmt.Errorf("%w: unsupported target type", ErrInvalidAuthzMapping)
	}
}

func recordMappingUpdateAudit(ctx context.Context, actorID int64, mapping *wecom_model.AuthzMapping, outcome, reason string) {
	metadata := []any{"outcome", outcome}
	if reason != "" {
		metadata = append(metadata, "reason", reason)
	}
	if mapping != nil {
		metadata = append(metadata,
			"mapping_id", mapping.ID,
			"source_type", string(mapping.SourceType),
			"target_type", string(mapping.TargetType),
		)
	}
	audit.RecordAs(ctx, mappingAuditActor(ctx, actorID), audit_model.EnterpriseWeComMappingUpdate, nil, metadata...)
}

func mappingAuditActor(ctx context.Context, actorID int64) *user_model.User {
	if actorID == 0 {
		return user_model.NewAuthSourceUser()
	}
	u, err := user_model.GetUserByID(ctx, actorID)
	if err != nil {
		return user_model.NewAuthSourceUser()
	}
	return u
}
