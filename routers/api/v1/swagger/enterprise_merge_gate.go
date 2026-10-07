// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package swagger

import api "gitea.dev/modules/structs"

// swagger:response EnterpriseProtectedPathRule
type swaggerResponseEnterpriseProtectedPathRule struct {
	// in:body
	Body api.EnterpriseProtectedPathRule
}

// swagger:response EnterpriseProtectedPathRuleList
type swaggerResponseEnterpriseProtectedPathRuleList struct {
	// in:body
	Body []api.EnterpriseProtectedPathRule
	// in:header
	TotalCount int64 `json:"X-Total-Count"`
}

// swagger:response EnterpriseMergeGateEvaluation
type swaggerResponseEnterpriseMergeGateEvaluation struct {
	// in:body
	Body api.EnterpriseMergeGateEvaluation
}

// swagger:response EnterpriseMergeGateEvaluationList
type swaggerResponseEnterpriseMergeGateEvaluationList struct {
	// in:body
	Body []api.EnterpriseMergeGateEvaluation
	// in:header
	TotalCount int64 `json:"X-Total-Count"`
}

// swagger:response EnterpriseMergeGatePreview
type swaggerResponseEnterpriseMergeGatePreview struct {
	// in:body
	Body api.EnterpriseMergeGatePreview
}
