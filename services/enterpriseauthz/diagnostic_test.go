// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	audit_model "gitea.dev/models/audit"
	"gitea.dev/models/db"
	authz_model "gitea.dev/models/enterpriseauthz"
	"gitea.dev/models/perm"
	access_model "gitea.dev/models/perm/access"
	repo_model "gitea.dev/models/repo"
	"gitea.dev/models/unit"
	"gitea.dev/models/unittest"
	user_model "gitea.dev/models/user"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/json"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/test"
	"gitea.dev/modules/util"

	"github.com/stretchr/testify/require"
	xormlog "xorm.io/xorm/log"
)

func diagnosticReader(t *testing.T) DiagnosticInput {
	t.Helper()
	permission := &access_model.Permission{AccessMode: perm.AccessModeRead}
	permission.SetUnitsWithDefaultAccessMode([]*repo_model.RepoUnit{{Type: unit.TypeCode}}, perm.AccessModeRead)
	return DiagnosticInput{
		Caller: unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 4}),
		Repo:   unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 1}), Permission: permission,
		Credential: CredentialCeiling{Read: true, Write: true, Reference: "access-token:42"}, Action: authz.CreateBranch,
	}
}

func diagnosticRole(t *testing.T, input DiagnosticInput, subjectID int64, action authz.Action, condition string) (*authz_model.RoleDefinition, *authz_model.SubjectRoleBinding) {
	t.Helper()
	role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: input.Repo.ID, Name: "private policy", LowerName: "private policy", Description: "secret=TOPSECRET", Revision: 3}
	require.NoError(t, db.Insert(t.Context(), role))
	_, normalized, hash, err := authz.ParseCondition([]byte(condition))
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: action, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}))
	binding := &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: subjectID, ScopeType: authz_model.ScopeRepo, ScopeID: input.Repo.ID, ScopeOwnerID: input.Repo.OwnerID, RoleID: role.ID}
	require.NoError(t, db.Insert(t.Context(), binding))
	return role, binding
}

func TestDiagnosticReaderSelfIsRedactedAndSeparatelyAudited(t *testing.T) {
	enableObservation(t)
	input := diagnosticReader(t)
	role, binding := diagnosticRole(t, input, input.Caller.ID, authz.CreateBranch, `{"branch_pattern":["private-release/*"],"path_pattern":["private-docs/**"],"request_sources":["diagnostic"]}`)
	other := &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: 5, ScopeType: authz_model.ScopeRepo, ScopeID: input.Repo.ID, ScopeOwnerID: input.Repo.OwnerID, RoleID: role.ID}
	require.NoError(t, db.Insert(t.Context(), other))
	input.ConditionContext = authz.ConditionContext{Branch: "private-release/topic", BranchKnown: true, Paths: []string{"private-docs/secret.md"}, PathsComplete: true, Source: "api"}
	result, err := Diagnose(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, "allow", result.CandidateDecision)
	require.Equal(t, "role_action", result.Reason)
	require.Equal(t, []authz.Action{authz.Clone, authz.ReadCode, authz.ViewMetadata}, result.NativeActions)
	require.Equal(t, []authz.Action{authz.CreateBranch}, result.RoleActions)
	require.Equal(t, []int64{role.ID}, result.MatchedRoleIDs)
	require.Equal(t, []int64{binding.ID}, result.MatchedBindingIDs)
	require.Equal(t, []DiagnosticRole{{ID: role.ID, Revision: 3}}, result.Roles)
	require.Equal(t, []DiagnosticBinding{{ID: binding.ID}}, result.Bindings)
	require.Len(t, result.Conditions, 1)
	require.Equal(t, "matched", result.Conditions[0].Result)
	require.Len(t, result.Conditions[0].ConditionHash, 64)
	require.True(t, result.CandidateOnly)
	require.False(t, result.SafetyGuardsEvaluated)
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	for _, sensitive := range []string{"snapshot", "subject_id", "credential", "private-", "private policy", "TOPSECRET"} {
		require.NotContains(t, string(encoded), sensitive)
	}
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 0)
	event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.Action("enterprise:authz:diagnostic")})
	require.Equal(t, input.Caller.ID, event.ActorID)
	require.Equal(t, "access-token:42", event.ActorCredential)
	require.Contains(t, event.Metadata, `"query_kind":"action"`)
	require.Contains(t, event.Metadata, `"target_user_id":4`)
	require.NotContains(t, event.Metadata, "private-")
}

func TestDiagnosticOtherUserNeedsManagementAndTargetVisibility(t *testing.T) {
	for _, name := range []string{"reader denied", "manager sees reader", "private target denied", "PAT retains read ceiling", "synthetic cannot impersonate"} {
		t.Run(name, func(t *testing.T) {
			enableObservation(t)
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
			input := diagnosticReader(t)
			input.TargetUserID = 5
			if name != "reader denied" {
				input.Caller = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
				input.Permission.AccessMode = perm.AccessModeOwner
				input.Permission.SetUnitsWithDefaultAccessMode([]*repo_model.RepoUnit{{Type: unit.TypeCode}}, perm.AccessModeOwner)
			}
			var want error = util.ErrPermissionDenied
			switch name {
			case "manager sees reader":
				input.Action = authz.ReadCode
				want = nil
			case "private target denied":
				input.Repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: 2})
				input.TargetUserID = 4
			case "PAT retains read ceiling":
				diagnosticRole(t, input, input.TargetUserID, authz.CreateBranch, `{}`)
				input.Credential.Write = false
				want = nil
			case "synthetic cannot impersonate":
				input.Caller.ExtDoerData = user_model.NewActionsUserWithTaskID(1).ExtDoerData
			}
			result, err := Diagnose(t.Context(), input)
			if want != nil {
				require.ErrorIs(t, err, want)
				unittest.AssertCount(t, &audit_model.Event{}, 0)
				return
			}
			require.NoError(t, err)
			if name == "PAT retains read ceiling" {
				require.Equal(t, "deny", result.CandidateDecision)
				require.Equal(t, "native_visibility_denied", result.Reason)
				require.Empty(t, result.RoleActions)
			} else {
				require.Equal(t, "allow", result.CandidateDecision)
				require.NotContains(t, result.NativeActions, authz.CreateBranch)
			}
		})
	}
}

func TestDiagnosticSyntheticSelfRetainsNativeCredential(t *testing.T) {
	for _, synthetic := range []*user_model.User{user_model.NewActionsUserWithTaskID(1), user_model.NewDeployKeyUserWithKeyID(1)} {
		for _, signedUser := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/user=%v", synthetic.Name, signedUser), func(t *testing.T) {
				enableObservation(t)
				input := diagnosticReader(t)
				diagnosticRole(t, input, input.Caller.ID, authz.CreateBranch, `{}`)
				if signedUser {
					input.Caller.ExtDoerData = synthetic.ExtDoerData
				} else {
					input.Caller = synthetic
				}
				result, err := Diagnose(t.Context(), input)
				require.NoError(t, err)
				require.Equal(t, "deny", result.CandidateDecision)
				require.Equal(t, "missing_action", result.Reason)
				require.Empty(t, result.RoleActions)
				require.Empty(t, result.Roles)
			})
		}
	}
}

func TestEffectivePermissionsSummarizesUnknownConditionsAndHiddenUnits(t *testing.T) {
	enableObservation(t)
	input := diagnosticReader(t)
	role, binding := diagnosticRole(t, input, input.Caller.ID, authz.CreateBranch, `{"path_pattern":["private-docs/**"],"request_sources":["diagnostic"]}`)
	_, normalized, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.ManageSecret, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}))
	require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.PushBranch, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}))
	var queries bytes.Buffer
	engine := db.GetXORMEngineForTesting()
	previous := engine.Logger()
	logger := xormlog.NewSimpleLogger(&queries)
	logger.ShowSQL(true)
	engine.SetLogger(logger)
	t.Cleanup(func() { engine.SetLogger(previous) })
	result, err := EffectivePermissions(t.Context(), input)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(queries.String(), "FROM `enterprise_subject_role_binding`"))
	require.Equal(t, []authz.Action{authz.Clone, authz.ReadCode, authz.ViewMetadata}, result.NativeActions)
	require.Equal(t, []authz.Action{authz.PushBranch}, result.RoleActions)
	require.Equal(t, []authz.Action{authz.CreateBranch}, result.UnresolvedActions)
	require.Equal(t, []DiagnosticRole{{ID: role.ID, Revision: 3}}, result.Roles)
	require.Equal(t, []DiagnosticBinding{{ID: binding.ID}}, result.Bindings)
	require.Len(t, result.Conditions, 2)
	encoded, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(encoded), string(authz.ManageSecret))
	require.NotContains(t, string(encoded), "private-")
	require.NotContains(t, string(encoded), "snapshot")
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 0)
	event := unittest.AssertExistsAndLoadBean(t, &audit_model.Event{Action: audit_model.Action("enterprise:authz:diagnostic")})
	require.Contains(t, event.Metadata, `"query_kind":"effective"`)
}

func TestDiagnosticAuthorizationPrecedesDisabledAndValidation(t *testing.T) {
	for _, name := range []string{"anonymous", "invisible", "reader queries other", "authorized disabled"} {
		t.Run(name, func(t *testing.T) {
			enableObservation(t)
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
			setting.EnterpriseAuthz.Enabled = false
			input := diagnosticReader(t)
			input.Action = "secret=TOPSECRET"
			want := util.ErrPermissionDenied
			switch name {
			case "anonymous":
				input.Caller = nil
			case "invisible":
				input.Permission = &access_model.Permission{}
			case "reader queries other":
				input.TargetUserID = 2
			case "authorized disabled":
				want = util.ErrNotExist
			}
			_, err := Diagnose(t.Context(), input)
			require.ErrorIs(t, err, want)
			_, err = EffectivePermissions(t.Context(), input)
			require.ErrorIs(t, err, want)
			unittest.AssertCount(t, &audit_model.Event{}, 0)
		})
	}
}

func TestDiagnosticRejectsInvalidOrOversizedContextWithoutRawInput(t *testing.T) {
	for _, name := range []string{"unknown action", "absolute path", "traversal", "bad UTF8", "too many paths", "too large branch", "invalid branch", "negative target"} {
		t.Run(name, func(t *testing.T) {
			enableObservation(t)
			t.Cleanup(test.MockVariableValue(&setting.EnterpriseWeCom, setting.EnterpriseWeComConfig{}))
			input := diagnosticReader(t)
			switch name {
			case "unknown action":
				input.Action = "secret=TOPSECRET"
			case "absolute path":
				input.ConditionContext.Paths = []string{"/private/secret"}
			case "traversal":
				input.ConditionContext.Paths = []string{"private/../secret"}
			case "bad UTF8":
				input.ConditionContext.Paths = []string{string([]byte{0xff})}
			case "too many paths":
				input.ConditionContext.Paths = make([]string, authz.MaxContextPaths+1)
			case "too large branch":
				input.ConditionContext.Branch = strings.Repeat("private-", authz.MaxBodyBytes)
			case "invalid branch":
				input.ConditionContext.Branch = "private-\nsecret"
			case "negative target":
				input.TargetUserID = -1
				input.Caller = unittest.AssertExistsAndLoadBean(t, &user_model.User{ID: 2})
			}
			_, err := Diagnose(t.Context(), input)
			require.ErrorIs(t, err, ErrInvalidPolicy)
			require.NotContains(t, err.Error(), "private")
			require.NotContains(t, err.Error(), "TOPSECRET")
			unittest.AssertCount(t, &audit_model.Event{}, 0)
		})
	}
}

func TestDiagnosticAuditFailureReturnsSafeStorageError(t *testing.T) {
	enableObservation(t)
	input := diagnosticReader(t)
	_, err := db.GetEngine(t.Context()).Exec(`CREATE TRIGGER authz_diagnostic_audit_failure BEFORE INSERT ON audit_event BEGIN SELECT RAISE(ABORT, 'secret=TOPSECRET token=TOPTOKEN code=OAUTH private/path'); END`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, err := db.GetEngine(context.WithoutCancel(t.Context())).Exec("DROP TRIGGER authz_diagnostic_audit_failure")
		require.NoError(t, err)
	})
	_, err = Diagnose(t.Context(), input)
	require.ErrorIs(t, err, ErrPolicyStorage)
	require.NotContains(t, err.Error(), "TOPSECRET")
	_, err = EffectivePermissions(t.Context(), input)
	require.ErrorIs(t, err, ErrPolicyStorage)
	unittest.AssertCount(t, &audit_model.Event{}, 0)
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 0)
}

func TestDiagnosticPolicyReadFailureReturnsSafeStorageError(t *testing.T) {
	enableObservation(t)
	input := diagnosticReader(t)
	diagnosticRole(t, input, input.Caller.ID, authz.CreateBranch, `{}`)
	_, err := db.GetEngine(t.Context()).Where("action = ?", authz.CreateBranch).Cols("condition_json").Update(&authz_model.RolePermission{ConditionJSON: `{"secret":"TOPSECRET"}`})
	require.NoError(t, err)
	_, err = Diagnose(t.Context(), input)
	require.ErrorIs(t, err, ErrPolicyStorage)
	_, err = EffectivePermissions(t.Context(), input)
	require.ErrorIs(t, err, ErrPolicyStorage)
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 0)
}

func TestDiagnosticSnapshotLimitReturnsSafeStorageError(t *testing.T) {
	enableObservation(t)
	input := diagnosticReader(t)
	_, normalized, hash, err := authz.ParseCondition([]byte(`{}`))
	require.NoError(t, err)
	for i := range 200 {
		name := fmt.Sprintf("bounded-%d", i)
		role := &authz_model.RoleDefinition{ScopeType: authz_model.ScopeRepo, ScopeID: input.Repo.ID, Name: name, LowerName: name, Revision: 1}
		require.NoError(t, db.Insert(t.Context(), role))
		require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.CreateBranch, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}))
		require.NoError(t, db.Insert(t.Context(), &authz_model.SubjectRoleBinding{SubjectType: authz_model.SubjectUser, SubjectID: input.Caller.ID, ScopeType: authz_model.ScopeRepo, ScopeID: input.Repo.ID, ScopeOwnerID: input.Repo.OwnerID, RoleID: role.ID}))
	}
	_, err = Diagnose(t.Context(), input)
	require.ErrorIs(t, err, ErrPolicyStorage)
	_, err = EffectivePermissions(t.Context(), input)
	require.ErrorIs(t, err, ErrPolicyStorage)
	unittest.AssertCount(t, &authz_model.DecisionRecord{}, 0)
	unittest.AssertCount(t, &audit_model.Event{Action: audit_model.EnterpriseAuthzDiagnostic}, 2)
	var events []audit_model.Event
	require.NoError(t, db.GetEngine(t.Context()).Find(&events))
	for _, event := range events {
		require.Contains(t, event.Metadata, `"reason":"snapshot_limit_exceeded"`)
	}
}

func TestEffectivePermissionsUsesCurrentArchiveSnapshot(t *testing.T) {
	for _, currentArchived := range []bool{true, false} {
		t.Run(fmt.Sprintf("archived=%v", currentArchived), func(t *testing.T) {
			enableObservation(t)
			input := diagnosticReader(t)
			previousArchived := !currentArchived
			_, err := db.GetEngine(t.Context()).ID(input.Repo.ID).Cols("is_archived").Update(&repo_model.Repository{IsArchived: previousArchived})
			require.NoError(t, err)
			input.Repo = unittest.AssertExistsAndLoadBean(t, &repo_model.Repository{ID: input.Repo.ID})
			role, binding := diagnosticRole(t, input, input.Caller.ID, authz.PushBranch, `{}`)
			_, normalized, hash, err := authz.ParseCondition([]byte(`{"path_pattern":["private-docs/**"]}`))
			require.NoError(t, err)
			require.NoError(t, db.Insert(t.Context(), &authz_model.RolePermission{RoleID: role.ID, Action: authz.CreateBranch, Effect: "allow", ConditionJSON: normalized, ConditionHash: hash}))
			_, err = db.GetEngine(t.Context()).ID(input.Repo.ID).Cols("is_archived").Update(&repo_model.Repository{IsArchived: currentArchived})
			require.NoError(t, err)
			require.Equal(t, previousArchived, input.Repo.IsArchived)

			result, err := EffectivePermissions(t.Context(), input)
			require.NoError(t, err)
			require.Equal(t, []authz.Action{authz.Clone, authz.ReadCode, authz.ViewMetadata}, result.NativeActions)
			if currentArchived {
				require.Empty(t, result.RoleActions)
				require.Empty(t, result.UnresolvedActions)
				require.Empty(t, result.Conditions)
				require.Empty(t, result.Roles)
				require.Empty(t, result.Bindings)
			} else {
				require.Equal(t, []authz.Action{authz.PushBranch}, result.RoleActions)
				require.Equal(t, []authz.Action{authz.CreateBranch}, result.UnresolvedActions)
				require.Len(t, result.Conditions, 2)
				require.Equal(t, []DiagnosticRole{{ID: role.ID, Revision: 3}}, result.Roles)
				require.Equal(t, []DiagnosticBinding{{ID: binding.ID}}, result.Bindings)
			}
		})
	}
}
