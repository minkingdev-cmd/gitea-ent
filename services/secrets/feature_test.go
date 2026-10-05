// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package secrets

import (
	"testing"

	actions_model "gitea.dev/models/actions"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	repo_model "gitea.dev/models/repo"
	secret_model "gitea.dev/models/secret"
	"gitea.dev/models/unittest"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"

	"github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) { unittest.MainTest(m) }

func TestSecretFeatureDisabledPreservesCleanupAndRunner(t *testing.T) {
	for _, ownerID := range []int64{2, 3} {
		t.Run(string(rune('0'+ownerID)), func(t *testing.T) {
			require.NoError(t, unittest.PrepareTestDatabase())
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
			t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
			setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
			require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureCISecretManagement, ScopeType: authz_model.ScopeSystem, State: authz.FeatureDisabled, ConfigJSON: `{}`, Revision: 1}))
			secret, err := secret_model.InsertEncryptedSecret(t.Context(), ownerID, 0, "EXISTING", "runner-value", "")
			require.NoError(t, err)
			_, _, err = CreateOrUpdateSecret(t.Context(), ownerID, 0, "NEW", "never-stored", "")
			require.Error(t, err)
			_, _, err = CreateOrUpdateSecret(t.Context(), ownerID, 0, "EXISTING", "never-updated", "")
			require.Error(t, err)
			repo := &repo_model.Repository{ID: 1, OwnerID: ownerID}
			values, err := secret_model.GetSecretsOfTask(t.Context(), &actions_model.ActionTask{Token: "runner-token", Job: &actions_model.ActionRunJob{Run: &actions_model.ActionRun{RepoID: repo.ID, Repo: repo}}})
			require.NoError(t, err)
			require.Equal(t, "runner-value", values["EXISTING"])
			deleted, err := DeleteSecretByID(t.Context(), ownerID, 0, secret.ID)
			require.NoError(t, err)
			require.Equal(t, secret.ID, deleted.ID)
			unittest.AssertNotExistsBean(t, &secret_model.Secret{OwnerID: ownerID, Name: "NEW"})
		})
	}
}

func TestSecretFeatureModesAndRequiredPending(t *testing.T) {
	for _, tc := range []struct {
		name             string
		enabled, enforce bool
		state            authz.FeatureState
	}{
		{"disabled", false, true, authz.FeatureDisabled},
		{"shadow", true, false, authz.FeatureDisabled},
		{"required", true, true, authz.FeatureRequired},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, unittest.PrepareTestDatabase())
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
			t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
			setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = tc.enabled, tc.enforce, true
			require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureCISecretManagement, ScopeType: authz_model.ScopeSystem, State: tc.state, ConfigJSON: `{}`, Revision: 1}))
			secrets, count, err := ListManagementSecrets(t.Context(), &secret_model.FindSecretsOptions{OwnerID: 3})
			require.NoError(t, err)
			require.Zero(t, count)
			require.Empty(t, secrets)
			secret, created, err := CreateOrUpdateSecret(t.Context(), 3, 0, "MODE_TEST", "encrypted-value", "")
			require.NoError(t, err)
			require.True(t, created)
			require.NotEqual(t, "encrypted-value", secret.Data)
		})
	}
}
