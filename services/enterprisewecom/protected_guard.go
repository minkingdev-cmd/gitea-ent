// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"context"
	"fmt"

	audit_model "gitea.dev/models/audit"
	user_model "gitea.dev/models/user"
	audit_service "gitea.dev/services/audit"
)

type ProtectedUserOperation string

const (
	ProtectedUserOpEdit              ProtectedUserOperation = "edit"
	ProtectedUserOpDelete            ProtectedUserOperation = "delete"
	ProtectedUserOpImpersonate       ProtectedUserOperation = "impersonate"
	ProtectedUserOpAvatar            ProtectedUserOperation = "avatar"
	ProtectedUserOpCredential        ProtectedUserOperation = "credential"
	ProtectedUserOpBadge             ProtectedUserOperation = "badge"
	ProtectedUserOpOrgMembership     ProtectedUserOperation = "org_membership"
	ProtectedUserOpEmail             ProtectedUserOperation = "email"
	ProtectedUserOpDestructiveSelf   ProtectedUserOperation = "destructive_self"
	ProtectedUserOpDemoteSelf        ProtectedUserOperation = "demote_self"
	ProtectedUserOpDeactivateSelf    ProtectedUserOperation = "deactivate_self"
	ProtectedUserOpProhibitLoginSelf ProtectedUserOperation = "prohibit_login_self"
)

type ProtectedUserDenyReason string

const (
	ProtectedUserDenyOtherAdmin        ProtectedUserDenyReason = "protected_wecom_admin_other_actor"
	ProtectedUserDenySelfDestructive   ProtectedUserDenyReason = "protected_wecom_admin_self_destructive"
	ProtectedUserDenySelfDemotion      ProtectedUserDenyReason = "protected_wecom_admin_self_demotion"
	ProtectedUserDenySelfDeactivate    ProtectedUserDenyReason = "protected_wecom_admin_self_deactivate"
	ProtectedUserDenySelfProhibitLogin ProtectedUserDenyReason = "protected_wecom_admin_self_prohibit_login"
)

type ProtectedUserDeniedError struct {
	Operation ProtectedUserOperation
	Reason    ProtectedUserDenyReason
	TargetID  int64
}

func (e *ProtectedUserDeniedError) Error() string {
	return fmt.Sprintf("protected enterprise wecom administrator management denied: operation=%s reason=%s target=%d", e.Operation, e.Reason, e.TargetID)
}

func (e *ProtectedUserDeniedError) SafeAuditMetadata() map[string]any {
	return map[string]any{
		"operation": e.Operation,
		"reason":    e.Reason,
		"target_id": e.TargetID,
		"outcome":   "denied",
	}
}

func CanManageProtectedUser(ctx context.Context, actor, target *user_model.User, operation ProtectedUserOperation) error {
	if target == nil {
		return nil
	}
	protected, err := IsProtectedAdminUser(ctx, target.ID)
	if err != nil || !protected {
		return err
	}
	if actor == nil || actor.ID != target.ID {
		return denyProtectedUser(ctx, actor, target, operation, ProtectedUserDenyOtherAdmin)
	}
	switch operation {
	case ProtectedUserOpDelete, ProtectedUserOpDestructiveSelf:
		return denyProtectedUser(ctx, actor, target, operation, ProtectedUserDenySelfDestructive)
	case ProtectedUserOpDemoteSelf:
		return denyProtectedUser(ctx, actor, target, operation, ProtectedUserDenySelfDemotion)
	case ProtectedUserOpDeactivateSelf:
		return denyProtectedUser(ctx, actor, target, operation, ProtectedUserDenySelfDeactivate)
	case ProtectedUserOpProhibitLoginSelf:
		return denyProtectedUser(ctx, actor, target, operation, ProtectedUserDenySelfProhibitLogin)
	default:
		return nil
	}
}

func denyProtectedUser(ctx context.Context, actor, target *user_model.User, operation ProtectedUserOperation, reason ProtectedUserDenyReason) error {
	err := &ProtectedUserDeniedError{Operation: operation, Reason: reason, TargetID: target.ID}
	audit_service.RecordAs(ctx, actor, audit_model.EnterpriseWeComProtectedAdminDeny, target,
		"operation", operation,
		"reason", reason,
		"target_id", target.ID,
		"outcome", "denied",
	)
	return err
}

func IsProtectedAdminUser(ctx context.Context, userID int64) (bool, error) {
	users, err := ResolveProtectedAdminUsers(ctx, ProtectedAdminResolveOptions{})
	if err != nil {
		return false, err
	}
	for _, u := range users {
		if u.ID == userID {
			return true, nil
		}
	}
	return false, nil
}
