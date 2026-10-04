// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	"context"
	"errors"
	"slices"

	"gitea.dev/models/db"
	authz "gitea.dev/modules/enterpriseauthz"
	"gitea.dev/modules/timeutil"

	"xorm.io/builder"
)

type (
	ScopeType   string
	SubjectType string
)

const (
	ScopeSystem ScopeType   = "system"
	ScopeOrg    ScopeType   = "org"
	ScopeRepo   ScopeType   = "repo"
	SubjectUser SubjectType = "user"
	SubjectTeam SubjectType = "team"
	SubjectOrg  SubjectType = "org"
)

type Scope struct {
	Type ScopeType `json:"type"`
	ID   int64     `json:"id"`
}

func (s Scope) Valid() bool {
	return s.Type == ScopeSystem && s.ID == 0 || (s.Type == ScopeOrg || s.Type == ScopeRepo) && s.ID > 0
}

type RoleDefinition struct {
	ID          int64              `xorm:"pk autoincr"`
	ScopeType   ScopeType          `xorm:"VARCHAR(16) NOT NULL UNIQUE(scope_name)"`
	ScopeID     int64              `xorm:"NOT NULL UNIQUE(scope_name)"`
	Name        string             `xorm:"VARCHAR(64) NOT NULL"`
	LowerName   string             `xorm:"VARCHAR(64) NOT NULL UNIQUE(scope_name)"`
	Description string             `xorm:"TEXT"`
	BuiltinKey  *string            `xorm:"VARCHAR(64) UNIQUE"`
	Revision    int64              `xorm:"NOT NULL DEFAULT 1"`
	CreatedBy   int64              `xorm:"NOT NULL"`
	CreatedUnix timeutil.TimeStamp `xorm:"created"`
	UpdatedUnix timeutil.TimeStamp `xorm:"updated"`
}

func (*RoleDefinition) TableName() string { return "enterprise_role_definition" }
func (r *RoleDefinition) Scope() Scope    { return Scope{r.ScopeType, r.ScopeID} }

type RolePermission struct {
	ID            int64        `xorm:"pk autoincr"`
	RoleID        int64        `xorm:"NOT NULL UNIQUE(permission) INDEX"`
	Action        authz.Action `xorm:"VARCHAR(64) NOT NULL UNIQUE(permission)"`
	Effect        string       `xorm:"VARCHAR(16) NOT NULL"`
	ConditionJSON string       `xorm:"TEXT NOT NULL"`
	ConditionHash string       `xorm:"VARCHAR(64) NOT NULL UNIQUE(permission)"`
}

func (*RolePermission) TableName() string { return "enterprise_role_permission" }

type SubjectRoleBinding struct {
	ID           int64              `xorm:"pk autoincr"`
	SubjectType  SubjectType        `xorm:"VARCHAR(16) NOT NULL UNIQUE(binding)"`
	SubjectID    int64              `xorm:"NOT NULL UNIQUE(binding)"`
	ScopeType    ScopeType          `xorm:"VARCHAR(16) NOT NULL UNIQUE(binding)"`
	ScopeID      int64              `xorm:"NOT NULL UNIQUE(binding) INDEX"`
	ScopeOwnerID int64              `xorm:"NOT NULL UNIQUE(binding)"`
	RoleID       int64              `xorm:"NOT NULL UNIQUE(binding) INDEX"`
	CreatedBy    int64              `xorm:"NOT NULL"`
	CreatedUnix  timeutil.TimeStamp `xorm:"created"`
}

func (*SubjectRoleBinding) TableName() string { return "enterprise_subject_role_binding" }

type DecisionRecord struct {
	ID                int64              `xorm:"pk autoincr"`
	ObservationID     string             `xorm:"VARCHAR(64) NOT NULL UNIQUE"`
	OperationID       string             `xorm:"VARCHAR(64) NOT NULL INDEX"`
	ActorID           int64              `xorm:"NOT NULL INDEX(actor_time)"`
	RepoID            int64              `xorm:"NOT NULL INDEX(repo_time)"`
	OwnerID           int64              `xorm:"NOT NULL"`
	Action            authz.Action       `xorm:"VARCHAR(64) NOT NULL INDEX(action_time)"`
	RequestSource     string             `xorm:"VARCHAR(32) NOT NULL"`
	CandidateDecision string             `xorm:"VARCHAR(16) NOT NULL INDEX(decision_time)"`
	Reason            string             `xorm:"VARCHAR(64) NOT NULL"`
	MissingActions    string             `xorm:"TEXT NOT NULL"`
	NativeOutcome     string             `xorm:"VARCHAR(16) NOT NULL"`
	NativeStage       string             `xorm:"VARCHAR(64) NOT NULL"`
	SnapshotJSON      string             `xorm:"LONGTEXT NOT NULL"`
	CreatedUnix       timeutil.TimeStamp `xorm:"created INDEX(repo_time) INDEX(actor_time) INDEX(action_time) INDEX(decision_time)"`
}

func (*DecisionRecord) TableName() string { return "enterprise_authz_decision" }

func init() {
	db.RegisterModel(new(RoleDefinition))
	db.RegisterModel(new(RolePermission))
	db.RegisterModel(new(SubjectRoleBinding))
	db.RegisterModel(new(DecisionRecord))
}

func DeleteScope(ctx context.Context, scope Scope) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if err := LockScope(ctx, scope); err != nil {
			return err
		}
		cond := builder.Eq{"scope_type": scope.Type, "scope_id": scope.ID}
		ids, err := db.FindIDs(ctx, new(RoleDefinition).TableName(), "id", cond)
		if err != nil {
			return err
		}
		if len(ids) != 0 {
			if _, err := db.GetEngine(ctx).In("id", ids).Cols("revision").SetExpr("revision", "revision").NoAutoTime().Update(new(RoleDefinition)); err != nil {
				return err
			}
		}
		if _, err := db.GetEngine(ctx).Where(cond.Or(builder.In("role_id", ids))).Delete(new(SubjectRoleBinding)); err != nil {
			return err
		}
		if len(ids) != 0 {
			if _, err := db.GetEngine(ctx).In("role_id", ids).Delete(new(RolePermission)); err != nil {
				return err
			}
		}
		_, err = db.GetEngine(ctx).Where(cond).Delete(new(RoleDefinition))
		return err
	})
}

func DeleteSubject(ctx context.Context, subject SubjectType, id int64) error {
	return db.WithTx(ctx, func(tx context.Context) error {
		if err := LockSubject(tx, subject, id); err != nil {
			return err
		}
		_, err := db.GetEngine(tx).Where(builder.Eq{"subject_type": subject, "subject_id": id}).Delete(new(SubjectRoleBinding))
		return err
	})
}

func LockScope(ctx context.Context, scope Scope) error {
	if !db.InTransaction(ctx) {
		return errors.New("policy_lock_requires_transaction")
	}
	if !scope.Valid() {
		return errors.New("invalid_scope")
	}
	if scope.Type == ScopeSystem {
		return nil
	}
	table := "user"
	if scope.Type == ScopeRepo {
		table = "repository"
	}
	_, err := db.Exec(ctx, "UPDATE `"+table+"` SET id=id WHERE id=?", scope.ID)
	return err
}

func LockSubject(ctx context.Context, subject SubjectType, id int64) error {
	if !db.InTransaction(ctx) {
		return errors.New("policy_lock_requires_transaction")
	}
	if id <= 0 || subject != SubjectUser && subject != SubjectOrg && subject != SubjectTeam {
		return errors.New("invalid_subject")
	}
	table := "user"
	if subject == SubjectTeam {
		table = "team"
	}
	_, err := db.Exec(ctx, "UPDATE `"+table+"` SET id=id WHERE id=?", id)
	return err
}

func DeleteOrganization(ctx context.Context, orgID int64) error {
	return db.WithTx(ctx, func(ctx context.Context) error {
		if err := LockScope(ctx, Scope{Type: ScopeOrg, ID: orgID}); err != nil {
			return err
		}
		teams, err := db.FindIDs(ctx, "team", "id", builder.Eq{"org_id": orgID})
		if err != nil {
			return err
		}
		if len(teams) != 0 {
			slices.Sort(teams)
			for _, id := range teams {
				if err := LockSubject(ctx, SubjectTeam, id); err != nil {
					return err
				}
			}
			if _, err := db.GetEngine(ctx).Where(builder.Eq{"subject_type": SubjectTeam}.And(builder.In("subject_id", teams))).Delete(new(SubjectRoleBinding)); err != nil {
				return err
			}
		}
		if err := DeleteSubject(ctx, SubjectOrg, orgID); err != nil {
			return err
		}
		return DeleteScope(ctx, Scope{Type: ScopeOrg, ID: orgID})
	})
}
