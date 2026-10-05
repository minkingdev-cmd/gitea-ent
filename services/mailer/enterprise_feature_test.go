// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package mailer

import (
	"testing"

	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	sender_service "gitea.dev/services/mailer/sender"

	"github.com/stretchr/testify/require"
)

func TestFeatureBlocksIssueMailComposition(t *testing.T) {
	t.Cleanup(test.MockVariableValue(&setting.MailService))
	t.Cleanup(test.MockVariableValue(&setting.AppURL))
	doer, _, issue, comment := prepareMailerTest(t)
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureIssues, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	_, err := composeIssueCommentMessages(t.Context(), &mailComment{Issue: issue, Doer: doer, Comment: comment}, "en-US", []*user_model.User{issue.Poster}, false, "test")
	require.ErrorContains(t, err, "feature_disabled")
}

func TestFeatureQueuedIssueMailRechecksPolicy(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	t.Cleanup(test.MockVariableValue(&setting.EnterpriseAuthz))
	t.Cleanup(test.MockVariableValue(&setting.Audit.RecordOutput, setting.AuditRecordOutputDatabase))
	setting.EnterpriseAuthz.Enabled, setting.EnterpriseAuthz.Enforce, setting.EnterpriseAuthz.FailClosedOnError = true, true, true
	message := &sender_service.Message{IssueID: 1}
	require.NoError(t, requireMailFeature(t.Context(), message))
	require.NoError(t, db.Insert(t.Context(), &authz_model.FeatureGrant{FeatureKey: authz.FeatureIssues, ScopeType: authz_model.ScopeRepo, ScopeID: 1, State: authz.FeatureDisabled, ConfigJSON: "{}", Revision: 1}))
	require.ErrorContains(t, requireMailFeature(t.Context(), message), "feature_disabled")
	require.NoError(t, requireMailFeature(t.Context(), &sender_service.Message{IssueID: 2}))
	setting.EnterpriseAuthz.Enforce = false
	require.NoError(t, requireMailFeature(t.Context(), message))
}
