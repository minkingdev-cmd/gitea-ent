// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package context

import (
	"gitea.dev/models/organization"
	"gitea.dev/modules/log"
)

const signedUserCanCreateOrganizationKey = "SignedUserCanCreateOrganization"

func (c TemplateContext) SignedUserCanCreateOrganization() bool {
	if cached, ok := c[signedUserCanCreateOrganizationKey].(bool); ok {
		return cached
	}
	webCtx := GetWebContext(c)
	allowed := false
	if webCtx != nil && webCtx.Doer != nil {
		err := organization.CheckCreateOrganizationAllowed(webCtx, webCtx.Doer)
		if err == nil {
			allowed = true
		} else if !organization.IsErrUserNotAllowedCreateOrg(err) && !organization.IsErrSingleOrganizationOnly(err) {
			log.Error("CheckCreateOrganizationAllowed: %v", err)
		}
	}
	c[signedUserCanCreateOrganizationKey] = allowed
	return allowed
}
