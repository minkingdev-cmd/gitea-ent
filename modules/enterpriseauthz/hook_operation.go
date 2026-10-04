// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

type HookOperationTicket string

func (HookOperationTicket) String() string   { return "<authz-hook-ticket>" }
func (HookOperationTicket) GoString() string { return "<authz-hook-ticket>" }
