// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package swagger

import api "gitea.dev/modules/structs"

// EnterpriseWeComAuthzMapping
// swagger:response EnterpriseWeComAuthzMapping
type swaggerResponseEnterpriseWeComAuthzMapping struct {
	// in:body
	Body api.EnterpriseWeComAuthzMapping `json:"body"`
}

// EnterpriseWeComAuthzMappingList
// swagger:response EnterpriseWeComAuthzMappingList
type swaggerResponseEnterpriseWeComAuthzMappingList struct {
	// in:body
	Body []api.EnterpriseWeComAuthzMapping `json:"body"`
}

// EnterpriseWeComAuthzReconcileResult
// swagger:response EnterpriseWeComAuthzReconcileResult
type swaggerResponseEnterpriseWeComAuthzReconcileResult struct {
	// in:body
	Body api.EnterpriseWeComAuthzReconcileResult `json:"body"`
}

// EnterpriseWeComAuthzMappingOption
// swagger:parameters enterpriseWeComAuthzMappingCreate enterpriseWeComAuthzMappingUpdate
type swaggerParameterEnterpriseWeComAuthzMappingOption struct {
	// in:body
	Body api.EnterpriseWeComAuthzMappingOption `json:"body"`
}

// EnterpriseWeComAuthzReconcileOption
// swagger:parameters enterpriseWeComAuthzMappingDryRun enterpriseWeComAuthzMappingApply
type swaggerParameterEnterpriseWeComAuthzReconcileOption struct {
	// in:body
	Body api.EnterpriseWeComAuthzReconcileOption `json:"body"`
}
