// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

import (
	authz_model "gitea.dev/models/enterpriseauthz"
	authz "gitea.dev/modules/enterpriseauthz"
	api "gitea.dev/modules/structs"
	authz_service "gitea.dev/services/enterpriseauthz"
)

func actionsDTO(actions []authz.Action) []string { return authz_service.ActionsDTO(actions) }
func roleDTO(role *authz_service.Role) (*api.EnterpriseAuthzRole, error) {
	return authz_service.RoleDTO(role)
}

func explanationDTO(native, roles []authz.Action, reason string, definitions []authz_service.DiagnosticRole, bindings []authz_service.DiagnosticBinding, conditions []authz_service.DiagnosticCondition) api.EnterpriseAuthzExplanation {
	return authz_service.ExplanationDTO(native, roles, reason, definitions, bindings, conditions)
}

func decisionDTO(record *authz_model.DecisionRecord) (*api.EnterpriseAuthzDecision, error) {
	return authz_service.DecisionDTO(record)
}
