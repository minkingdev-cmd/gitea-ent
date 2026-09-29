// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"errors"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/auth"
	"gitea.dev/models/db"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/services/audit"
)

var ErrConfiguredWeComSourceProtected = errors.New("configured Enterprise WeCom login source is protected while login-only mode is enabled")

type oauth2ProviderConfig interface {
	OAuth2ProviderName() string
}

func isConfiguredWeComSource(source *auth.Source) bool {
	if source == nil || source.Type != auth.OAuth2 || source.Name != setting.EnterpriseWeCom.LoginSourceName {
		return false
	}
	cfg, ok := source.Cfg.(oauth2ProviderConfig)
	return ok && cfg.OAuth2ProviderName() == "wecom"
}

func validateConfiguredWeComSourceMutation(original, updated *auth.Source) error {
	if setting.EnterpriseWeComLoginOnly() && isConfiguredWeComSource(original) && (updated == nil || !updated.IsActive || !isConfiguredWeComSource(updated)) {
		return ErrConfiguredWeComSourceProtected
	}
	return nil
}

// CreateSource creates a AuthSource record in DB.
func CreateSource(ctx context.Context, source *auth.Source) error {
	if err := auth.CreateSource(ctx, source); err != nil {
		return err
	}

	audit.Record(ctx, audit_model.SystemAuthenticationSourceAdd, nil,
		"auth_source", source.Name, "auth_source_type", source.Type.String(), "is_active", source.IsActive)

	return nil
}

// UpdateSource updates a AuthSource record in DB.
func UpdateSource(ctx context.Context, source *auth.Source) error {
	if setting.EnterpriseWeComLoginOnly() {
		original, err := auth.GetSourceByID(ctx, source.ID)
		if err != nil {
			return err
		}
		if err := validateConfiguredWeComSourceMutation(original, source); err != nil {
			return err
		}
	}
	if err := auth.UpdateSource(ctx, source); err != nil {
		return err
	}

	audit.Record(ctx, audit_model.SystemAuthenticationSourceUpdate, nil,
		"auth_source", source.Name, "auth_source_type", source.Type.String(), "is_active", source.IsActive)

	return nil
}

// DeleteSource deletes a AuthSource record in DB.
func DeleteSource(ctx context.Context, source *auth.Source) error {
	if err := validateConfiguredWeComSourceMutation(source, nil); err != nil {
		return err
	}
	count, err := db.GetEngine(ctx).Count(&user_model.User{LoginSource: source.ID})
	if err != nil {
		return err
	} else if count > 0 {
		return auth.ErrSourceInUse{
			ID: source.ID,
		}
	}

	count, err = db.GetEngine(ctx).Count(&user_model.ExternalLoginUser{LoginSourceID: source.ID})
	if err != nil {
		return err
	} else if count > 0 {
		return auth.ErrSourceInUse{
			ID: source.ID,
		}
	}

	if registerableSource, ok := source.Cfg.(auth.RegisterableSource); ok {
		if err := registerableSource.UnregisterSource(); err != nil {
			return err
		}
	}

	if _, err = db.GetEngine(ctx).ID(source.ID).Delete(new(auth.Source)); err != nil {
		return err
	}

	audit.Record(ctx, audit_model.SystemAuthenticationSourceRemove, nil, "auth_source", source.Name)

	return nil
}
