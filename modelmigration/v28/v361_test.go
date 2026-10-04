// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package v28

import (
	"fmt"
	"testing"

	"gitea.dev/modelmigration/base"
	"gitea.dev/modelmigration/migrationtest"
	"gitea.dev/modules/timeutil"

	"github.com/stretchr/testify/require"
)

func TestEnterpriseAuthzFoundationMigration(t *testing.T) {
	x, cleanup := migrationtest.PrepareTestEnv(t, 0, new(authzNativeUserV361), new(authzNativeAccessV361), new(authzNativeCollaborationV361), new(authzNativeTeamV361), new(authzNativeTeamRepoV361), new(authzNativePublicKeyV361), new(authzNativeAccessTokenV361), new(legacyWeComMigrationAuthToken), new(legacyWeComMappingOrgUser), new(legacyWeComMappingTeamUser), new(authzNativeIdentityV361), new(WeComAdminAuthority), new(GovernanceAuthzMapping), new(EnterpriseWeComManagedMembership), new(EnterpriseWeComGeneratedTeam))
	defer cleanup()
	if x == nil || t.Failed() {
		return
	}
	_, err := x.NoAutoTime().Insert(
		&authzNativeUserV361{ID: 1, Name: "legacy", LowerName: "legacy", FullName: "Legacy Admin", Email: "legacy@example.invalid", Passwd: "unchanged", PasswdHashAlgo: "argon2", LoginType: 6, LoginSource: 11, LoginName: "wecom-user", IsAdmin: true, IsActive: true, IsRestricted: true, ProhibitLogin: true, Salt: "salt", Rands: "rands", Avatar: "avatar", AvatarEmail: "avatar@example.invalid", Theme: "gitea-dark", Visibility: 2, NumRepos: 3, CreatedUnix: 100, UpdatedUnix: 200},
		&authzNativeUserV361{ID: 2, Name: "member", LowerName: "member", Email: "member@example.invalid", Passwd: "member-password", IsAdmin: false, IsActive: false, CreatedUnix: 300, UpdatedUnix: 400},
		&authzNativeAccessV361{ID: 1, UserID: 1, RepoID: 9, Mode: 3},
		&authzNativeCollaborationV361{ID: 1, UserID: 1, RepoID: 9, Mode: 4, CreatedUnix: 100, UpdatedUnix: 200},
		&authzNativeTeamV361{ID: 3, OrgID: 7, Name: "Owners", LowerName: "owners", Description: "existing", AccessMode: 4, NumRepos: 1, NumMembers: 1, IncludesAllRepositories: true, CanCreateOrgRepo: true, Visibility: 2},
		&authzNativeTeamRepoV361{ID: 1, OrgID: 7, TeamID: 3, RepoID: 9},
		&authzNativePublicKeyV361{ID: 1, OwnerID: 1, Name: "ssh", Fingerprint: "SHA256:existing", Content: "ssh-ed25519 AAAAC3 existing", Mode: 2, Type: 1, LoginSourceID: 11, Verified: true, CreatedUnix: 100, UpdatedUnix: 200},
		&authzNativeAccessTokenV361{ID: 1, UID: 1, Name: "pat", TokenHash: "hash", TokenSalt: "salt", TokenLastEight: "last8pat", Scope: "read:repository", CreatedUnix: 100, UpdatedUnix: 200},
		&legacyWeComMigrationAuthToken{ID: "token", UserID: 1, TokenHash: "git-hash", ExpiresUnix: 1893456000},
		&legacyWeComMappingOrgUser{ID: 1, UID: 1, OrgID: 7, IsPublic: true},
		&legacyWeComMappingTeamUser{ID: 1, UID: 1, OrgID: 7, TeamID: 3},
		&authzNativeIdentityV361{ID: 1, UserID: 1, CorpID: "corp", WeComUserID: "wecom-user", ExternalID: "wecom:corp:wecom-user", LoginSourceID: 11, Status: "left", Name: "old name", Email: "old@example.invalid", SyncVersion: 3, LastLoginUnix: 100, LastSyncUnix: 200, CreatedUnix: 100, UpdatedUnix: 200},
		&WeComAdminAuthority{ID: 1, CorpID: "corp", AgentID: "app", WeComUserID: "wecom-user", OpenUserID: "open-user", AuthType: 1, IsManagement: true, IsActive: false, RefreshID: "refresh", RefreshTrigger: "cron", LastSeenUnix: 100, LastRefreshUnix: 200, LastError: "existing error", CreatedUnix: 100, UpdatedUnix: 200},
		&GovernanceAuthzMapping{ID: 1, CorpID: "corp", AgentID: "app", Origin: "generated", SourceType: "department", SourceID: "42", TargetType: "team", OrgID: 7, TeamID: 3, IsActive: true},
		&EnterpriseWeComManagedMembership{ID: 1, MappingID: 1, UserID: 1, TargetType: "team", OrgID: 7, TeamID: 3},
		&EnterpriseWeComGeneratedTeam{ID: 1, CorpID: "corp", AgentID: "app", SourceType: "department", SourceID: "42", OrgID: 7, TeamID: 3, Status: "applied", RunID: "run"},
	)
	require.NoError(t, err)
	nativeTables := []string{"user", "access", "collaboration", "team", "team_repo", "public_key", "access_token", "auth_token", "org_user", "team_user", "wecom_identity", "wecom_admin_authority", "enterprise_wecom_authz_mapping", "enterprise_wecom_managed_membership", "enterprise_wecom_generated_team"}
	nativeBefore := authzMigrationRows(t, x, nativeTables)
	require.NoError(t, AddEnterpriseAuthzFoundation(t.Context(), x))
	roles, err := x.Count(new(authzRoleDefinitionV361))
	require.NoError(t, err)
	require.EqualValues(t, 8, roles)
	permissions, err := x.Count(new(authzRolePermissionV361))
	require.NoError(t, err)
	require.EqualValues(t, 68, permissions)
	require.Equal(t, nativeBefore, authzMigrationRows(t, x, nativeTables))
	require.NoError(t, x.DropTables(new(authzRolePermissionV361), new(authzBindingV361), new(authzDecisionV361), new(authzRoleDefinitionV361)))
	require.NoError(t, x.Sync(new(authzRoleDefinitionV361), new(authzRolePermissionV361), new(authzBindingV361), new(authzDecisionV361)))
	guestKey := "guest"
	guest := &authzRoleDefinitionV361{ScopeType: "system", Name: "guest", LowerName: "guest", BuiltinKey: &guestKey, Revision: 1, CreatedUnix: 100, UpdatedUnix: 200}
	guestPermission := &authzRolePermissionV361{Action: "repo.view_metadata", Effect: "allow", ConditionJSON: "{}", ConditionHash: "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"}
	_, err = x.NoAutoTime().Insert(guest)
	require.NoError(t, err)
	guestPermission.RoleID = guest.ID
	_, err = x.Insert(guestPermission)
	require.NoError(t, err)
	conflict := &authzRoleDefinitionV361{ScopeType: "system", Name: "custom maintainer", LowerName: "maintainer", Revision: 1}
	_, err = x.Insert(conflict)
	require.NoError(t, err)
	partialSeed := authzMigrationRows(t, x, []string{"enterprise_role_definition", "enterprise_role_permission"})
	require.Error(t, AddEnterpriseAuthzFoundation(t.Context(), x))
	require.Equal(t, partialSeed, authzMigrationRows(t, x, []string{"enterprise_role_definition", "enterprise_role_permission"}))
	require.Equal(t, nativeBefore, authzMigrationRows(t, x, nativeTables))
	_, err = x.ID(conflict.ID).Delete(new(authzRoleDefinitionV361))
	require.NoError(t, err)
	wantPermissions := map[string][]string{
		"guest":               {"repo.view_metadata"},
		"reporter":            {"repo.view_metadata", "repo.read_code", "repo.clone"},
		"developer":           {"repo.view_metadata", "repo.read_code", "repo.clone", "repo.create_branch", "repo.push_branch", "repo.create_pull_request"},
		"reviewer":            {"repo.view_metadata", "repo.read_code", "repo.clone", "repo.review_pull_request"},
		"maintainer":          {"repo.view_metadata", "repo.read_code", "repo.clone", "repo.create_branch", "repo.push_branch", "repo.create_pull_request", "repo.review_pull_request", "repo.merge_pull_request", "repo.manage_webhook", "repo.manage_ci"},
		"security-maintainer": {"repo.view_metadata", "repo.read_code", "repo.clone", "repo.review_pull_request", "repo.manage_codeowners", "repo.manage_ci"},
		"owner":               {"repo.view_metadata", "repo.read_code", "repo.clone", "repo.create_branch", "repo.push_branch", "repo.push_protected_branch", "repo.create_pull_request", "repo.review_pull_request", "repo.merge_pull_request", "repo.manage_branch_protection", "repo.manage_codeowners", "repo.manage_webhook", "repo.manage_ci", "repo.manage_secret", "repo.manage_feature_grant", "repo.migrate", "repo.transfer", "repo.archive", "repo.delete"},
		"platform-admin":      {"repo.view_metadata", "repo.read_code", "repo.clone", "repo.create_branch", "repo.push_branch", "repo.push_protected_branch", "repo.create_pull_request", "repo.review_pull_request", "repo.merge_pull_request", "repo.manage_branch_protection", "repo.manage_codeowners", "repo.manage_webhook", "repo.manage_ci", "repo.manage_secret", "repo.manage_feature_grant", "repo.migrate", "repo.transfer", "repo.archive", "repo.delete"},
	}
	var completeSeed map[string][]map[string][]byte
	for range 2 {
		require.NoError(t, AddEnterpriseAuthzFoundation(t.Context(), x))
		var roles []authzRoleDefinitionV361
		require.NoError(t, x.Find(&roles))
		require.Len(t, roles, 8)
		keys := make([]string, 0, len(roles))
		for _, role := range roles {
			require.NotNil(t, role.BuiltinKey)
			keys = append(keys, *role.BuiltinKey)
			require.Equal(t, "system", role.ScopeType)
			require.Zero(t, role.ScopeID)
			require.EqualValues(t, 1, role.Revision)
			var permissions []authzRolePermissionV361
			require.NoError(t, x.Where("role_id = ?", role.ID).Find(&permissions))
			actions := make([]string, 0, len(permissions))
			for _, permission := range permissions {
				actions = append(actions, permission.Action)
				require.Equal(t, "allow", permission.Effect)
				require.Equal(t, "{}", permission.ConditionJSON)
				require.Equal(t, "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", permission.ConditionHash)
			}
			require.ElementsMatch(t, wantPermissions[*role.BuiltinKey], actions)
		}
		require.ElementsMatch(t, []string{"guest", "reporter", "developer", "reviewer", "maintainer", "security-maintainer", "owner", "platform-admin"}, keys)
		bindings, err := x.Count(new(authzBindingV361))
		require.NoError(t, err)
		require.Zero(t, bindings)
		decisions, err := x.Count(new(authzDecisionV361))
		require.NoError(t, err)
		require.Zero(t, decisions)
		require.Equal(t, nativeBefore, authzMigrationRows(t, x, nativeTables))
		seed := authzMigrationRows(t, x, []string{"enterprise_role_definition", "enterprise_role_permission"})
		if completeSeed != nil {
			require.Equal(t, completeSeed, seed)
		}
		completeSeed = seed
	}
	storedGuest := &authzRoleDefinitionV361{ID: guest.ID}
	has, err := x.Get(storedGuest)
	require.NoError(t, err)
	require.True(t, has)
	require.Equal(t, *guest, *storedGuest)
	indexes, err := x.Dialect().GetIndexes(x.DB(), t.Context(), "enterprise_authz_decision")
	require.NoError(t, err)
	for name, column := range map[string]string{"repo_time": "repo_id", "actor_time": "actor_id", "action_time": "action", "decision_time": "candidate_decision"} {
		require.Contains(t, indexes, name)
		require.Equal(t, []string{column, "created_unix"}, indexes[name].Cols)
	}
	for _, scope := range []struct {
		typ string
		id  int64
	}{{"system", 0}, {"org", 9}, {"repo", 9}, {"repo", 10}} {
		_, err := x.Insert(&authzRoleDefinitionV361{ScopeType: scope.typ, ScopeID: scope.id, Name: "Scoped", LowerName: "scoped", Revision: 1})
		require.NoError(t, err)
		_, err = x.Insert(&authzRoleDefinitionV361{ScopeType: scope.typ, ScopeID: scope.id, Name: "SCOPED", LowerName: "scoped", Revision: 1})
		require.Error(t, err)
	}
	permissionCopy := *guestPermission
	permissionCopy.ID = 0
	_, err = x.Insert(&permissionCopy)
	require.Error(t, err)
	binding := &authzBindingV361{SubjectType: "user", SubjectID: 1, ScopeType: "repo", ScopeID: 9, ScopeOwnerID: 7, RoleID: guest.ID, CreatedBy: 1}
	_, err = x.Insert(binding)
	require.NoError(t, err)
	duplicateBinding := *binding
	duplicateBinding.ID = 0
	_, err = x.Insert(&duplicateBinding)
	require.Error(t, err)
	decision := &authzDecisionV361{ObservationID: "migration-history-1", OperationID: "operation-1", ActorID: 1, RepoID: 9, OwnerID: 7, Action: "repo.clone", RequestSource: "api", CandidateDecision: "allow", Reason: "native_action", MissingActions: "[]", NativeOutcome: "success", NativeStage: "operation", SnapshotJSON: "{}"}
	_, err = x.Insert(decision)
	require.NoError(t, err)
	duplicateDecision := *decision
	duplicateDecision.ID = 0
	_, err = x.Insert(&duplicateDecision)
	require.Error(t, err)
	duplicateDecision.ObservationID = "migration-history-2"
	_, err = x.Insert(&duplicateDecision)
	require.NoError(t, err)
	require.Equal(t, nativeBefore, authzMigrationRows(t, x, nativeTables))
}

func authzMigrationRows(t *testing.T, x base.EngineMigration, tables []string) map[string][]map[string][]byte {
	t.Helper()
	rows := make(map[string][]map[string][]byte, len(tables))
	for _, table := range tables {
		data, err := x.Query(fmt.Sprintf("SELECT * FROM `%s` ORDER BY id", table))
		require.NoError(t, err)
		rows[table] = data
	}
	return rows
}

type authzNativeUserV361 struct {
	ID                           int64  `xorm:"pk autoincr"`
	LowerName                    string `xorm:"UNIQUE NOT NULL"`
	Name                         string `xorm:"UNIQUE NOT NULL"`
	FullName                     string
	Email                        string `xorm:"NOT NULL"`
	KeepEmailPrivate             bool
	EmailNotificationsPreference string `xorm:"VARCHAR(20) NOT NULL DEFAULT 'enabled'"`
	Passwd                       string `xorm:"NOT NULL"`
	PasswdHashAlgo               string `xorm:"NOT NULL DEFAULT 'argon2'"`
	MustChangePassword           bool   `xorm:"NOT NULL DEFAULT false"`
	LoginType                    int
	LoginSource                  int64 `xorm:"NOT NULL DEFAULT 0"`
	LoginName                    string
	Type                         int
	Location                     string
	Website                      string
	Rands                        string `xorm:"VARCHAR(32)"`
	Salt                         string `xorm:"VARCHAR(32)"`
	Language                     string `xorm:"VARCHAR(5)"`
	Description                  string
	CreatedUnix                  timeutil.TimeStamp `xorm:"INDEX created"`
	UpdatedUnix                  timeutil.TimeStamp `xorm:"INDEX updated"`
	LastLoginUnix                timeutil.TimeStamp `xorm:"INDEX"`
	LastRepoVisibility           bool
	MaxRepoCreation              int  `xorm:"NOT NULL DEFAULT -1"`
	IsActive                     bool `xorm:"INDEX"`
	IsAdmin                      bool
	IsRestricted                 bool `xorm:"NOT NULL DEFAULT false"`
	AllowGitHook                 bool
	AllowImportLocal             bool
	AllowCreateOrganization      bool   `xorm:"DEFAULT true"`
	ProhibitLogin                bool   `xorm:"NOT NULL DEFAULT false"`
	Avatar                       string `xorm:"VARCHAR(2048) NOT NULL"`
	AvatarEmail                  string `xorm:"NOT NULL"`
	UseCustomAvatar              bool
	NumFollowers                 int
	NumFollowing                 int `xorm:"NOT NULL DEFAULT 0"`
	NumStars                     int
	NumRepos                     int
	NumTeams                     int
	NumMembers                   int
	Visibility                   int    `xorm:"NOT NULL DEFAULT 0"`
	RepoAdminChangeTeamAccess    bool   `xorm:"NOT NULL DEFAULT false"`
	DiffViewStyle                string `xorm:"NOT NULL DEFAULT ''"`
	Theme                        string `xorm:"NOT NULL DEFAULT ''"`
	KeepActivityPrivate          bool   `xorm:"NOT NULL DEFAULT false"`
}

func (*authzNativeUserV361) TableName() string { return "user" }

type authzNativeAccessV361 struct {
	ID     int64 `xorm:"pk autoincr"`
	UserID int64 `xorm:"UNIQUE(s)"`
	RepoID int64 `xorm:"UNIQUE(s)"`
	Mode   int
}

func (*authzNativeAccessV361) TableName() string { return "access" }

type authzNativeCollaborationV361 struct {
	ID          int64              `xorm:"pk autoincr"`
	RepoID      int64              `xorm:"UNIQUE(s) INDEX NOT NULL"`
	UserID      int64              `xorm:"UNIQUE(s) INDEX NOT NULL"`
	Mode        int                `xorm:"DEFAULT 2 NOT NULL"`
	CreatedUnix timeutil.TimeStamp `xorm:"INDEX created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"INDEX updated"`
}

func (*authzNativeCollaborationV361) TableName() string { return "collaboration" }

type authzNativeTeamV361 struct {
	ID                      int64 `xorm:"pk autoincr"`
	OrgID                   int64 `xorm:"INDEX"`
	LowerName               string
	Name                    string
	Description             string
	AccessMode              int `xorm:"'authorize'"`
	NumRepos                int
	NumMembers              int
	IncludesAllRepositories bool `xorm:"NOT NULL DEFAULT false"`
	CanCreateOrgRepo        bool `xorm:"NOT NULL DEFAULT false"`
	Visibility              int  `xorm:"NOT NULL DEFAULT 2"`
}

func (*authzNativeTeamV361) TableName() string { return "team" }

type authzNativeTeamRepoV361 struct {
	ID     int64 `xorm:"pk autoincr"`
	OrgID  int64 `xorm:"INDEX"`
	TeamID int64 `xorm:"UNIQUE(s)"`
	RepoID int64 `xorm:"UNIQUE(s)"`
}

func (*authzNativeTeamRepoV361) TableName() string { return "team_repo" }

type authzNativePublicKeyV361 struct {
	ID            int64              `xorm:"pk autoincr"`
	OwnerID       int64              `xorm:"INDEX NOT NULL"`
	Name          string             `xorm:"NOT NULL"`
	Fingerprint   string             `xorm:"INDEX NOT NULL"`
	Content       string             `xorm:"MEDIUMTEXT NOT NULL"`
	Mode          int                `xorm:"NOT NULL DEFAULT 2"`
	Type          int                `xorm:"NOT NULL DEFAULT 1"`
	LoginSourceID int64              `xorm:"NOT NULL DEFAULT 0"`
	CreatedUnix   timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix   timeutil.TimeStamp `xorm:"updated"`
	Verified      bool               `xorm:"NOT NULL DEFAULT false"`
}

func (*authzNativePublicKeyV361) TableName() string { return "public_key" }

type authzNativeAccessTokenV361 struct {
	ID             int64 `xorm:"pk autoincr"`
	UID            int64 `xorm:"INDEX"`
	Name           string
	TokenHash      string `xorm:"UNIQUE"`
	TokenSalt      string
	TokenLastEight string `xorm:"INDEX token_last_eight"`
	Scope          string
	CreatedUnix    timeutil.TimeStamp `xorm:"INDEX created"`
	UpdatedUnix    timeutil.TimeStamp `xorm:"INDEX updated"`
}

func (*authzNativeAccessTokenV361) TableName() string { return "access_token" }

type authzNativeIdentityV361 struct {
	ID            int64  `xorm:"pk autoincr"`
	UserID        int64  `xorm:"INDEX NOT NULL"`
	CorpID        string `xorm:"VARCHAR(128) NOT NULL UNIQUE(corp_user)"`
	WeComUserID   string `xorm:"wecom_userid VARCHAR(255) NOT NULL UNIQUE(corp_user)"`
	ExternalID    string `xorm:"VARCHAR(512) UNIQUE NOT NULL"`
	LoginSourceID int64  `xorm:"INDEX NOT NULL"`
	Status        string `xorm:"VARCHAR(32) NOT NULL DEFAULT 'active'"`
	Name          string
	Email         string
	LastLoginUnix timeutil.TimeStamp
	LastSyncUnix  timeutil.TimeStamp
	SyncVersion   int64              `xorm:"INDEX NOT NULL DEFAULT 0"`
	CreatedUnix   timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix   timeutil.TimeStamp `xorm:"updated"`
}

func (*authzNativeIdentityV361) TableName() string { return "wecom_identity" }
