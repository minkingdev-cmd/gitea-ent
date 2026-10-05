// Copyright 2023 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package secrets

import (
	"context"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	secret_model "gitea.dev/models/secret"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func CreateOrUpdateSecret(ctx context.Context, ownerID, repoID int64, name, data, description string) (*secret_model.Secret, bool, error) {
	if err := ValidateName(name); err != nil {
		return nil, false, err
	}

	if repoID > 0 {
		if err := authz_service.RequireSettingsExecution(ctx, repoID, authz.ManageSecret, authz_service.SettingsIntent(authz.ManageSecret, name)); err != nil {
			return nil, false, err
		}
	}

	if err := RequireManagementFeature(ctx, ownerID, repoID); err != nil {
		return nil, false, err
	}

	var result *secret_model.Secret
	var created bool
	err := db.WithTx(ctx, func(ctx context.Context) error {
		if setting.EnterpriseAuthz.Enabled && setting.EnterpriseAuthz.Enforce {
			scope := authz_model.Scope{Type: authz_model.ScopeOrg, ID: ownerID}
			if repoID > 0 {
				scope = authz_model.Scope{Type: authz_model.ScopeRepo, ID: repoID}
			}
			if err := authz_model.LockScope(ctx, scope); err != nil {
				if rejection := authz_service.FeatureGuardError(err); rejection != nil {
					return rejection
				}
			}
			if err := authz_model.LockFeatures(ctx, []authz.FeatureKey{authz.FeatureCISecretManagement}); err != nil {
				if rejection := authz_service.FeatureGuardError(err); rejection != nil {
					return rejection
				}
			}
			if err := RequireManagementFeature(ctx, ownerID, repoID); err != nil {
				return err
			}
			if repoID > 0 {
				if err := authz_service.RequireSettingsExecution(ctx, repoID, authz.ManageSecret, authz_service.SettingsIntent(authz.ManageSecret, name)); err != nil {
					return err
				}
			}
		}
		s, err := db.Find[secret_model.Secret](ctx, secret_model.FindSecretsOptions{
			OwnerID: ownerID,
			RepoID:  repoID,
			Name:    name,
		})
		if err != nil {
			return err
		}

		if len(s) == 0 {
			s, err := secret_model.InsertEncryptedSecret(ctx, ownerID, repoID, name, data, description)
			if err != nil {
				return err
			}
			result, created = s, true
			return nil
		}

		if err := secret_model.UpdateSecret(ctx, s[0].ID, data, description); err != nil {
			return err
		}

		result = s[0]
		return nil
	})
	return result, created, err
}

func RequireManagementFeature(ctx context.Context, ownerID, repoID int64) error {
	if repoID > 0 {
		return authz_service.RequireRepoFeature(ctx, repoID, authz.FeatureCISecretManagement)
	}
	return authz_service.RequireOwnerFeature(ctx, ownerID, authz.FeatureCISecretManagement)
}

func ListManagementSecrets(ctx context.Context, opts *secret_model.FindSecretsOptions) ([]*secret_model.Secret, int64, error) {
	if err := RequireManagementFeature(ctx, opts.OwnerID, opts.RepoID); err != nil {
		return nil, 0, err
	}
	return db.FindAndCount[secret_model.Secret](ctx, opts)
}

func DeleteSecretByID(ctx context.Context, ownerID, repoID, secretID int64) (*secret_model.Secret, error) {
	s, err := db.Find[secret_model.Secret](ctx, secret_model.FindSecretsOptions{
		OwnerID:  ownerID,
		RepoID:   repoID,
		SecretID: secretID,
	})
	if err != nil {
		return nil, err
	}
	if len(s) != 1 {
		return nil, secret_model.ErrSecretNotFound{}
	}

	return s[0], deleteSecret(ctx, s[0])
}

func DeleteSecretByName(ctx context.Context, ownerID, repoID int64, name string) (*secret_model.Secret, error) {
	s, err := db.Find[secret_model.Secret](ctx, secret_model.FindSecretsOptions{
		OwnerID: ownerID,
		RepoID:  repoID,
		Name:    name,
	})
	if err != nil {
		return nil, err
	}
	if len(s) != 1 {
		return nil, secret_model.ErrSecretNotFound{}
	}

	return s[0], deleteSecret(ctx, s[0])
}

func deleteSecret(ctx context.Context, s *secret_model.Secret) error {
	if s.RepoID > 0 {
		if err := authz_service.RequireSettingsExecution(ctx, s.RepoID, authz.ManageSecret, authz_service.SettingsIntent(authz.ManageSecret, s.Name)); err != nil {
			return err
		}
	}
	if _, err := db.DeleteByID[secret_model.Secret](ctx, s.ID); err != nil {
		return err
	}
	return nil
}
