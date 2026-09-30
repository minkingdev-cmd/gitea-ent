// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
)

func ListGeneratedAuthzMappings(ctx context.Context, opts AuthzMappingListOptions) ([]*wecom_model.AuthzMapping, error) {
	mappings := make([]*wecom_model.AuthzMapping, 0)
	valid, err := generatedMappingReadTarget(ctx)
	if err != nil || !valid {
		return mappings, err
	}
	sess := db.GetEngine(ctx).Where("corp_id = ? AND agent_id = ? AND org_id = ? AND origin = ?", setting.EnterpriseWeCom.CorpID, setting.EnterpriseWeCom.AgentID, setting.EnterpriseWeCom.ManagedOrgID, wecom_model.AuthzMappingOriginGenerated).OrderBy("id ASC")
	if !opts.IncludeInactive {
		sess = sess.And("is_active = ?", true)
	}
	return mappings, sess.Find(&mappings)
}

func GetGeneratedAuthzMapping(ctx context.Context, id int64) (*wecom_model.AuthzMapping, error) {
	valid, err := generatedMappingReadTarget(ctx)
	if err != nil {
		return nil, err
	}
	if !valid || id <= 0 {
		return nil, ErrInvalidAuthzMapping
	}
	mapping := new(wecom_model.AuthzMapping)
	has, err := db.GetEngine(ctx).Where("id = ? AND corp_id = ? AND agent_id = ? AND org_id = ? AND origin = ?", id, setting.EnterpriseWeCom.CorpID, setting.EnterpriseWeCom.AgentID, setting.EnterpriseWeCom.ManagedOrgID, wecom_model.AuthzMappingOriginGenerated).Get(mapping)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, ErrInvalidAuthzMapping
	}
	return mapping, nil
}

func generatedMappingReadTarget(ctx context.Context) (bool, error) {
	if !setting.EnterpriseWeCom.Enabled || setting.EnterpriseWeCom.ManagedOrgID <= 0 || setting.EnterpriseWeCom.CorpID == "" || setting.EnterpriseWeCom.AgentID == "" {
		return false, nil
	}
	org, err := organization.GetOrgByID(ctx, setting.EnterpriseWeCom.ManagedOrgID)
	if organization.IsErrOrgNotExist(err) || user_model.IsErrUserNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return org.Type == user_model.UserTypeOrganization, nil
}
