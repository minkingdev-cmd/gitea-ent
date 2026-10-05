// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package swagger

import api "gitea.dev/modules/structs"

// EnterpriseFeatureCatalog
// swagger:response EnterpriseFeatureCatalog
type swaggerResponseEnterpriseFeatureCatalog struct {
	// in:body
	Body api.EnterpriseFeatureCatalog `json:"body"`
}

// EnterpriseFeatureEffective
// swagger:response EnterpriseFeatureEffective
type swaggerResponseEnterpriseFeatureEffective struct {
	// in:body
	Body api.EnterpriseFeatureEffective `json:"body"`
}

// EnterpriseFeaturePolicy
// swagger:response EnterpriseFeaturePolicy
type swaggerResponseEnterpriseFeaturePolicy struct {
	// in:body
	Body api.EnterpriseFeaturePolicy `json:"body"`
}

// EnterpriseFeatureEffectiveList
// swagger:response EnterpriseFeatureEffectiveList
type swaggerResponseEnterpriseFeatureEffectiveList struct {
	// in:header
	TotalCount int64 `json:"X-Total-Count"`
	// in:body
	Body []api.EnterpriseFeatureEffective `json:"body"`
}

// EnterpriseFeaturePolicyList
// swagger:response EnterpriseFeaturePolicyList
type swaggerResponseEnterpriseFeaturePolicyList struct {
	// in:header
	TotalCount int64 `json:"X-Total-Count"`
	// in:body
	Body []api.EnterpriseFeaturePolicy `json:"body"`
}
