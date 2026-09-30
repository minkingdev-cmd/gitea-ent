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
