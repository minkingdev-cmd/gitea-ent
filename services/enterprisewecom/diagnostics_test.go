// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"testing"
	"time"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/timeutil"

	"github.com/stretchr/testify/require"
)

func TestAdminAuthorityDiagnosticsDisabledAndUnsupported(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{})()

	diag, err := BuildAdminAuthorityDiagnostics(t.Context(), AdminAuthorityDiagnosticsOptions{})
	require.NoError(t, err)
	require.Equal(t, AdminAuthorityDiagnosticStatusDisabled, diag.Status)
	require.Empty(t, diag.ProtectedUserIDs)

	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-diag", AgentID: "1000002"})()
	require.NoError(t, db.Insert(t.Context(), &wecom_model.ReconcileRun{RunID: "diag-unsupported", CorpID: "corp-diag", AgentID: "1000002", Trigger: "cron", Status: wecom_model.ReconcileRunStatusSuccess, AuthorityRefreshStatus: "unsupported"}))
	diag, err = BuildAdminAuthorityDiagnostics(t.Context(), AdminAuthorityDiagnosticsOptions{})
	require.NoError(t, err)
	require.Equal(t, AdminAuthorityDiagnosticStatusUnsupported, diag.Status)
	require.True(t, diag.HasWarning(AdminAuthorityWarningUnsupported))
}

func TestAdminAuthorityDiagnosticsWarnsForUnboundInactiveMultipleStaleAndGeneratedFailures(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-diag", AgentID: "1000002"})()

	activeUser := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	require.NoError(t, insertDiagnosticAuthority(t, "bound.admin", timeutil.TimeStampNow()-100, true))
	require.NoError(t, insertDiagnosticAuthority(t, "unbound.admin", timeutil.TimeStampNow()-100, true))
	require.NoError(t, insertDiagnosticAuthority(t, "inactive.admin", timeutil.TimeStampNow()-100, true))
	require.NoError(t, insertDiagnosticAuthority(t, "stale.admin", timeutil.TimeStampNow()-10_000, true))
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: activeUser.ID, CorpID: "corp-diag", WeComUserID: "bound.admin", LoginSourceID: 1, Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	_, _, err = wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: 3, CorpID: "corp-diag", WeComUserID: "inactive.admin", LoginSourceID: 1, Status: wecom_model.IdentityStatusOutOfScope})
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &wecom_model.GeneratedMapping{CorpID: "corp-diag", AgentID: "1000002", RunID: "diag-generated", SourceType: wecom_model.AuthzSourceDepartment, SourceID: "1", TargetType: wecom_model.AuthzTargetTeam, Status: wecom_model.GeneratedStateError, ErrorMessage: "team missing"}))

	diag, err := BuildAdminAuthorityDiagnostics(t.Context(), AdminAuthorityDiagnosticsOptions{Now: timeutil.TimeStampNow(), StaleAfter: time.Hour})
	require.NoError(t, err)
	require.Equal(t, AdminAuthorityDiagnosticStatusWarning, diag.Status)
	require.ElementsMatch(t, []int64{activeUser.ID}, diag.ProtectedUserIDs)
	for _, code := range []AdminAuthorityWarningCode{
		AdminAuthorityWarningUnboundIdentity,
		AdminAuthorityWarningInactiveIdentity,
		AdminAuthorityWarningMultipleManagementAdmins,
		AdminAuthorityWarningStaleRefresh,
		AdminAuthorityWarningGeneratedMappingFailure,
	} {
		require.True(t, diag.HasWarning(code), "missing warning %s", code)
	}
	require.NotContains(t, diag.Warnings[0].Message, "corp-secret")
}

func TestAdminAuthorityDiagnosticsReflectsAuthorityRemoval(t *testing.T) {
	require.NoError(t, unittest.PrepareTestDatabase())
	defer test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{Enabled: true, CorpID: "corp-diag", AgentID: "1000002"})()

	user := unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
	_, _, err := wecom_model.BindIdentityToUser(t.Context(), wecom_model.BindIdentityOptions{UserID: user.ID, CorpID: "corp-diag", WeComUserID: "removed.admin", LoginSourceID: 1, Status: wecom_model.IdentityStatusActive})
	require.NoError(t, err)
	require.NoError(t, insertDiagnosticAuthority(t, "removed.admin", timeutil.TimeStampNow(), false))

	diag, err := BuildAdminAuthorityDiagnostics(t.Context(), AdminAuthorityDiagnosticsOptions{})
	require.NoError(t, err)
	require.Equal(t, AdminAuthorityDiagnosticStatusOK, diag.Status)
	require.Empty(t, diag.ProtectedUserIDs)
}

func insertDiagnosticAuthority(t *testing.T, wecomUserID string, lastRefresh timeutil.TimeStamp, active bool) error {
	t.Helper()
	return db.Insert(t.Context(), &wecom_model.AdminAuthority{
		CorpID:          "corp-diag",
		AgentID:         "1000002",
		WeComUserID:     wecomUserID,
		AuthType:        wecom_model.AdminAuthorityAuthTypeManagement,
		IsManagement:    true,
		IsActive:        active,
		LastRefreshUnix: lastRefresh,
	})
}
