// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

// swagger:operation GET /enterprise/authz/roles enterprise enterpriseAuthzSystemListRoles
// ---
// summary: System enterprise authorization ListRoles
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: page
//   in: query
//   type: integer
//   required: false
//   description: 1-based page number, default 1
//   format: int64
// - name: limit
//   in: query
//   type: integer
//   required: false
//   description: Page size, default 20, maximum 100
//   format: int64
//   maximum: 100
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzRoleList"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation POST /enterprise/authz/roles enterprise enterpriseAuthzSystemCreateRole
// ---
// summary: System enterprise authorization CreateRole
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: body
//   description: Strict JSON object, unknown/duplicate/null fields rejected; maximum 1 MiB. Conditions are bounded to 8 KiB, permissions to 128, and diagnostic paths to 1024.
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/CreateEnterpriseAuthzRoleOption"
// responses:
//   "201":
//     "$ref": "#/responses/EnterpriseAuthzRole"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"
//   "409":
//     description: Revision conflict, immutable built-in, duplicate name or referenced role

// swagger:operation GET /enterprise/authz/roles/{id} enterprise enterpriseAuthzSystemGetRole
// ---
// summary: System enterprise authorization GetRole
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: id
//   in: path
//   type: integer
//   required: true
//   description: Identifier within the authorized scope
//   format: int64
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzRole"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation PATCH /enterprise/authz/roles/{id} enterprise enterpriseAuthzSystemUpdateRole
// ---
// summary: System enterprise authorization UpdateRole
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: id
//   in: path
//   type: integer
//   required: true
//   description: Identifier within the authorized scope
//   format: int64
// - name: body
//   description: Strict JSON object, unknown/duplicate/null fields rejected; maximum 1 MiB. Conditions are bounded to 8 KiB, permissions to 128, and diagnostic paths to 1024.
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/EditEnterpriseAuthzRoleOption"
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzRole"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"
//   "409":
//     description: Revision conflict, immutable built-in, duplicate name or referenced role

// swagger:operation DELETE /enterprise/authz/roles/{id} enterprise enterpriseAuthzSystemDeleteRole
// ---
// summary: System enterprise authorization DeleteRole
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: id
//   in: path
//   type: integer
//   required: true
//   description: Identifier within the authorized scope
//   format: int64
// - name: expected_revision
//   in: query
//   type: integer
//   required: true
//   description: Current revision; missing or stale revision returns 409
//   format: int64
// responses:
//   "204":
//     "$ref": "#/responses/empty"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"
//   "409":
//     description: Revision conflict, immutable built-in, duplicate name or referenced role

// swagger:operation GET /enterprise/authz/bindings enterprise enterpriseAuthzSystemListBindings
// ---
// summary: System enterprise authorization ListBindings
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: page
//   in: query
//   type: integer
//   required: false
//   description: 1-based page number, default 1
//   format: int64
// - name: limit
//   in: query
//   type: integer
//   required: false
//   description: Page size, default 20, maximum 100
//   format: int64
//   maximum: 100
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzBindingList"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation PUT /enterprise/authz/bindings enterprise enterpriseAuthzSystemPutBinding
// ---
// summary: System enterprise authorization PutBinding
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: body
//   description: Strict JSON object, unknown/duplicate/null fields rejected; maximum 1 MiB. Conditions are bounded to 8 KiB, permissions to 128, and diagnostic paths to 1024.
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/PutEnterpriseAuthzBindingOption"
// responses:
//   "204":
//     "$ref": "#/responses/empty"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation DELETE /enterprise/authz/bindings/{id} enterprise enterpriseAuthzSystemDeleteBinding
// ---
// summary: System enterprise authorization DeleteBinding
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: id
//   in: path
//   type: integer
//   required: true
//   description: Identifier within the authorized scope
//   format: int64
// responses:
//   "204":
//     "$ref": "#/responses/empty"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation GET /enterprise/authz/decisions enterprise enterpriseAuthzSystemListDecisions
// ---
// summary: System enterprise authorization ListDecisions
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: page
//   in: query
//   type: integer
//   required: false
//   description: 1-based page number, default 1
//   format: int64
// - name: limit
//   in: query
//   type: integer
//   required: false
//   description: Page size, default 20, maximum 100
//   format: int64
//   maximum: 100
// - name: actor_id
//   in: query
//   type: integer
//   required: false
//   description: Actor filter, including anonymous 0 and native synthetic actors
//   format: int64
// - name: repo_id
//   in: query
//   type: integer
//   required: false
//   description: Repository filter cannot expand the authorized scope
//   format: int64
// - name: action
//   in: query
//   type: string
//   required: false
//   description: Stable action key
// - name: decision
//   in: query
//   type: string
//   required: false
//   description: allow, deny or error
// - name: since
//   in: query
//   type: integer
//   required: false
//   description: Inclusive Unix timestamp in seconds
//   format: int64
// - name: until
//   in: query
//   type: integer
//   required: false
//   description: Inclusive Unix timestamp in seconds
//   format: int64
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzDecisionList"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation GET /enterprise/authz/decisions/{id} enterprise enterpriseAuthzSystemGetDecision
// ---
// summary: System enterprise authorization GetDecision
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: id
//   in: path
//   type: integer
//   required: true
//   description: Identifier within the authorized scope
//   format: int64
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzDecision"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation GET /enterprise/authz/actions enterprise enterpriseAuthzSystemActions
// ---
// summary: System enterprise authorization Actions
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzActionCatalog"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation GET /orgs/{org}/enterprise/authz/roles enterprise enterpriseAuthzOrgListRoles
// ---
// summary: Org enterprise authorization ListRoles
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: page
//   in: query
//   type: integer
//   required: false
//   description: 1-based page number, default 1
//   format: int64
// - name: limit
//   in: query
//   type: integer
//   required: false
//   description: Page size, default 20, maximum 100
//   format: int64
//   maximum: 100
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzRoleList"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation POST /orgs/{org}/enterprise/authz/roles enterprise enterpriseAuthzOrgCreateRole
// ---
// summary: Org enterprise authorization CreateRole
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: org
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: body
//   description: Strict JSON object, unknown/duplicate/null fields rejected; maximum 1 MiB. Conditions are bounded to 8 KiB, permissions to 128, and diagnostic paths to 1024.
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/CreateEnterpriseAuthzRoleOption"
// responses:
//   "201":
//     "$ref": "#/responses/EnterpriseAuthzRole"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"
//   "409":
//     description: Revision conflict, immutable built-in, duplicate name or referenced role

// swagger:operation GET /orgs/{org}/enterprise/authz/roles/{id} enterprise enterpriseAuthzOrgGetRole
// ---
// summary: Org enterprise authorization GetRole
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: id
//   in: path
//   type: integer
//   required: true
//   description: Identifier within the authorized scope
//   format: int64
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzRole"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation PATCH /orgs/{org}/enterprise/authz/roles/{id} enterprise enterpriseAuthzOrgUpdateRole
// ---
// summary: Org enterprise authorization UpdateRole
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: org
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: id
//   in: path
//   type: integer
//   required: true
//   description: Identifier within the authorized scope
//   format: int64
// - name: body
//   description: Strict JSON object, unknown/duplicate/null fields rejected; maximum 1 MiB. Conditions are bounded to 8 KiB, permissions to 128, and diagnostic paths to 1024.
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/EditEnterpriseAuthzRoleOption"
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzRole"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"
//   "409":
//     description: Revision conflict, immutable built-in, duplicate name or referenced role

// swagger:operation DELETE /orgs/{org}/enterprise/authz/roles/{id} enterprise enterpriseAuthzOrgDeleteRole
// ---
// summary: Org enterprise authorization DeleteRole
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: id
//   in: path
//   type: integer
//   required: true
//   description: Identifier within the authorized scope
//   format: int64
// - name: expected_revision
//   in: query
//   type: integer
//   required: true
//   description: Current revision; missing or stale revision returns 409
//   format: int64
// responses:
//   "204":
//     "$ref": "#/responses/empty"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"
//   "409":
//     description: Revision conflict, immutable built-in, duplicate name or referenced role

// swagger:operation GET /orgs/{org}/enterprise/authz/bindings enterprise enterpriseAuthzOrgListBindings
// ---
// summary: Org enterprise authorization ListBindings
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: page
//   in: query
//   type: integer
//   required: false
//   description: 1-based page number, default 1
//   format: int64
// - name: limit
//   in: query
//   type: integer
//   required: false
//   description: Page size, default 20, maximum 100
//   format: int64
//   maximum: 100
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzBindingList"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation PUT /orgs/{org}/enterprise/authz/bindings enterprise enterpriseAuthzOrgPutBinding
// ---
// summary: Org enterprise authorization PutBinding
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: org
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: body
//   description: Strict JSON object, unknown/duplicate/null fields rejected; maximum 1 MiB. Conditions are bounded to 8 KiB, permissions to 128, and diagnostic paths to 1024.
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/PutEnterpriseAuthzBindingOption"
// responses:
//   "204":
//     "$ref": "#/responses/empty"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation DELETE /orgs/{org}/enterprise/authz/bindings/{id} enterprise enterpriseAuthzOrgDeleteBinding
// ---
// summary: Org enterprise authorization DeleteBinding
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: id
//   in: path
//   type: integer
//   required: true
//   description: Identifier within the authorized scope
//   format: int64
// responses:
//   "204":
//     "$ref": "#/responses/empty"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation GET /orgs/{org}/enterprise/authz/decisions enterprise enterpriseAuthzOrgListDecisions
// ---
// summary: Org enterprise authorization ListDecisions
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: page
//   in: query
//   type: integer
//   required: false
//   description: 1-based page number, default 1
//   format: int64
// - name: limit
//   in: query
//   type: integer
//   required: false
//   description: Page size, default 20, maximum 100
//   format: int64
//   maximum: 100
// - name: actor_id
//   in: query
//   type: integer
//   required: false
//   description: Actor filter, including anonymous 0 and native synthetic actors
//   format: int64
// - name: repo_id
//   in: query
//   type: integer
//   required: false
//   description: Repository filter cannot expand the authorized scope
//   format: int64
// - name: action
//   in: query
//   type: string
//   required: false
//   description: Stable action key
// - name: decision
//   in: query
//   type: string
//   required: false
//   description: allow, deny or error
// - name: since
//   in: query
//   type: integer
//   required: false
//   description: Inclusive Unix timestamp in seconds
//   format: int64
// - name: until
//   in: query
//   type: integer
//   required: false
//   description: Inclusive Unix timestamp in seconds
//   format: int64
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzDecisionList"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation GET /orgs/{org}/enterprise/authz/decisions/{id} enterprise enterpriseAuthzOrgGetDecision
// ---
// summary: Org enterprise authorization GetDecision
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: id
//   in: path
//   type: integer
//   required: true
//   description: Identifier within the authorized scope
//   format: int64
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzDecision"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation GET /repos/{owner}/{repo}/enterprise/authz/roles enterprise enterpriseAuthzRepoListRoles
// ---
// summary: Repo enterprise authorization ListRoles
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: repo
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: page
//   in: query
//   type: integer
//   required: false
//   description: 1-based page number, default 1
//   format: int64
// - name: limit
//   in: query
//   type: integer
//   required: false
//   description: Page size, default 20, maximum 100
//   format: int64
//   maximum: 100
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzRoleList"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation POST /repos/{owner}/{repo}/enterprise/authz/roles enterprise enterpriseAuthzRepoCreateRole
// ---
// summary: Repo enterprise authorization CreateRole
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: repo
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: body
//   description: Strict JSON object, unknown/duplicate/null fields rejected; maximum 1 MiB. Conditions are bounded to 8 KiB, permissions to 128, and diagnostic paths to 1024.
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/CreateEnterpriseAuthzRoleOption"
// responses:
//   "201":
//     "$ref": "#/responses/EnterpriseAuthzRole"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"
//   "409":
//     description: Revision conflict, immutable built-in, duplicate name or referenced role

// swagger:operation GET /repos/{owner}/{repo}/enterprise/authz/roles/{id} enterprise enterpriseAuthzRepoGetRole
// ---
// summary: Repo enterprise authorization GetRole
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: repo
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: id
//   in: path
//   type: integer
//   required: true
//   description: Identifier within the authorized scope
//   format: int64
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzRole"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation PATCH /repos/{owner}/{repo}/enterprise/authz/roles/{id} enterprise enterpriseAuthzRepoUpdateRole
// ---
// summary: Repo enterprise authorization UpdateRole
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: repo
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: id
//   in: path
//   type: integer
//   required: true
//   description: Identifier within the authorized scope
//   format: int64
// - name: body
//   description: Strict JSON object, unknown/duplicate/null fields rejected; maximum 1 MiB. Conditions are bounded to 8 KiB, permissions to 128, and diagnostic paths to 1024.
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/EditEnterpriseAuthzRoleOption"
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzRole"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"
//   "409":
//     description: Revision conflict, immutable built-in, duplicate name or referenced role

// swagger:operation DELETE /repos/{owner}/{repo}/enterprise/authz/roles/{id} enterprise enterpriseAuthzRepoDeleteRole
// ---
// summary: Repo enterprise authorization DeleteRole
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: repo
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: id
//   in: path
//   type: integer
//   required: true
//   description: Identifier within the authorized scope
//   format: int64
// - name: expected_revision
//   in: query
//   type: integer
//   required: true
//   description: Current revision; missing or stale revision returns 409
//   format: int64
// responses:
//   "204":
//     "$ref": "#/responses/empty"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"
//   "409":
//     description: Revision conflict, immutable built-in, duplicate name or referenced role

// swagger:operation GET /repos/{owner}/{repo}/enterprise/authz/bindings enterprise enterpriseAuthzRepoListBindings
// ---
// summary: Repo enterprise authorization ListBindings
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: repo
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: page
//   in: query
//   type: integer
//   required: false
//   description: 1-based page number, default 1
//   format: int64
// - name: limit
//   in: query
//   type: integer
//   required: false
//   description: Page size, default 20, maximum 100
//   format: int64
//   maximum: 100
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzBindingList"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation PUT /repos/{owner}/{repo}/enterprise/authz/bindings enterprise enterpriseAuthzRepoPutBinding
// ---
// summary: Repo enterprise authorization PutBinding
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: repo
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: body
//   description: Strict JSON object, unknown/duplicate/null fields rejected; maximum 1 MiB. Conditions are bounded to 8 KiB, permissions to 128, and diagnostic paths to 1024.
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/PutEnterpriseAuthzBindingOption"
// responses:
//   "204":
//     "$ref": "#/responses/empty"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation DELETE /repos/{owner}/{repo}/enterprise/authz/bindings/{id} enterprise enterpriseAuthzRepoDeleteBinding
// ---
// summary: Repo enterprise authorization DeleteBinding
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: repo
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: id
//   in: path
//   type: integer
//   required: true
//   description: Identifier within the authorized scope
//   format: int64
// responses:
//   "204":
//     "$ref": "#/responses/empty"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation GET /repos/{owner}/{repo}/enterprise/authz/decisions enterprise enterpriseAuthzRepoListDecisions
// ---
// summary: Repo enterprise authorization ListDecisions
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: repo
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: page
//   in: query
//   type: integer
//   required: false
//   description: 1-based page number, default 1
//   format: int64
// - name: limit
//   in: query
//   type: integer
//   required: false
//   description: Page size, default 20, maximum 100
//   format: int64
//   maximum: 100
// - name: actor_id
//   in: query
//   type: integer
//   required: false
//   description: Actor filter, including anonymous 0 and native synthetic actors
//   format: int64
// - name: repo_id
//   in: query
//   type: integer
//   required: false
//   description: Repository filter cannot expand the authorized scope
//   format: int64
// - name: action
//   in: query
//   type: string
//   required: false
//   description: Stable action key
// - name: decision
//   in: query
//   type: string
//   required: false
//   description: allow, deny or error
// - name: since
//   in: query
//   type: integer
//   required: false
//   description: Inclusive Unix timestamp in seconds
//   format: int64
// - name: until
//   in: query
//   type: integer
//   required: false
//   description: Inclusive Unix timestamp in seconds
//   format: int64
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzDecisionList"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation GET /repos/{owner}/{repo}/enterprise/authz/decisions/{id} enterprise enterpriseAuthzRepoGetDecision
// ---
// summary: Repo enterprise authorization GetDecision
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: repo
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: id
//   in: path
//   type: integer
//   required: true
//   description: Identifier within the authorized scope
//   format: int64
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzDecision"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation GET /repos/{owner}/{repo}/enterprise/authz/effective-permissions enterprise enterpriseAuthzRepoEffectivePermissions
// ---
// summary: Repo enterprise authorization EffectivePermissions
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: repo
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: user_id
//   in: query
//   type: integer
//   required: false
//   description: Defaults to self; another user requires native repository management authority
//   format: int64
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzEffectivePermissions"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"

// swagger:operation POST /repos/{owner}/{repo}/enterprise/authz/evaluate enterprise enterpriseAuthzRepoEvaluate
// ---
// summary: Repo enterprise authorization Evaluate
// description: Native token scopes and authority are required; shadow roles never grant API access. Disabled authz returns 404 after native authorization. Decision list/detail require an unrestricted token (public-only is rejected); diagnostic source is fixed to diagnostic; candidate_only is true and safety_guards_evaluated is false. POST requires write scope, GET requires read scope.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: repo
//   in: path
//   type: string
//   required: true
//   description: Resource resolved by the server
// - name: body
//   description: Strict JSON object, unknown/duplicate/null fields rejected; maximum 1 MiB. Conditions are bounded to 8 KiB, permissions to 128, and diagnostic paths to 1024.
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/EvaluateEnterpriseAuthzOption"
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseAuthzDiagnostic"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "500":
//     "$ref": "#/responses/error"
