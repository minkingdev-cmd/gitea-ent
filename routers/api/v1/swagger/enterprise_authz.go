// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package swagger

import api "gitea.dev/modules/structs"

// EnterpriseAuthzActionCatalog
// swagger:response EnterpriseAuthzActionCatalog
type swaggerResponseEnterpriseAuthzActionCatalog struct {
	// in:body
	Body api.EnterpriseAuthzActionCatalog `json:"body"`
}

// EnterpriseAuthzRole
// swagger:response EnterpriseAuthzRole
type swaggerResponseEnterpriseAuthzRole struct {
	// in:body
	Body api.EnterpriseAuthzRole `json:"body"`
}

// EnterpriseAuthzRoleList
// swagger:response EnterpriseAuthzRoleList
type swaggerResponseEnterpriseAuthzRoleList struct {
	// in:header
	TotalCount int64 `json:"X-Total-Count"`
	// in:body
	Body []api.EnterpriseAuthzRole `json:"body"`
}

// EnterpriseAuthzBindingList
// swagger:response EnterpriseAuthzBindingList
type swaggerResponseEnterpriseAuthzBindingList struct {
	// in:header
	TotalCount int64 `json:"X-Total-Count"`
	// in:body
	Body []api.EnterpriseAuthzBinding `json:"body"`
}

// EnterpriseAuthzDecision
// swagger:response EnterpriseAuthzDecision
type swaggerResponseEnterpriseAuthzDecision struct {
	// in:body
	Body api.EnterpriseAuthzDecision `json:"body"`
}

// EnterpriseAuthzDecisionList
// swagger:response EnterpriseAuthzDecisionList
type swaggerResponseEnterpriseAuthzDecisionList struct {
	// in:header
	TotalCount int64 `json:"X-Total-Count"`
	// in:body
	Body []api.EnterpriseAuthzDecision `json:"body"`
}

// EnterpriseAuthzDiagnostic
// swagger:response EnterpriseAuthzDiagnostic
type swaggerResponseEnterpriseAuthzDiagnostic struct {
	// in:body
	Body api.EnterpriseAuthzDiagnostic `json:"body"`
}

// EnterpriseAuthzEffectivePermissions
// swagger:response EnterpriseAuthzEffectivePermissions
type swaggerResponseEnterpriseAuthzEffectivePermissions struct {
	// in:body
	Body api.EnterpriseAuthzEffectivePermissions `json:"body"`
}
