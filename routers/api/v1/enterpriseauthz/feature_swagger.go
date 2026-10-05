// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

// swagger:operation GET /enterprise/authz/features enterprise enterpriseFeatureGlobalList
// ---
// summary: Enterprise feature policy GlobalList
// description: Global requires current system management authority and admin scope; org requires current org management authority and organization scope; repo effective GET requires authenticated native visibility and repository read scope. Raw GET requires existing repository management authority. PUT/DELETE additionally require repository write scope and repo.manage_feature_grant even in shadow. Feature policy never grants native permission. Reader projection omits config, actor and ancestor IDs. required reports pending rather than creating native resources; external keys are policy_only, not scanner or merge-gate execution. Strict JSON rejects unknown, duplicate, null, invalid UTF-8 and trailing data. Config max 16 KiB, max 64 contexts of 1-128 bytes.
// produces:
// - application/json
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseFeatureCatalog"
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

// swagger:operation GET /enterprise/authz/features/{key}/grants/global enterprise enterpriseFeatureGlobalGet
// ---
// summary: Enterprise feature policy GlobalGet
// description: Global requires current system management authority and admin scope; org requires current org management authority and organization scope; repo effective GET requires authenticated native visibility and repository read scope. Raw GET requires existing repository management authority. PUT/DELETE additionally require repository write scope and repo.manage_feature_grant even in shadow. Feature policy never grants native permission. Reader projection omits config, actor and ancestor IDs. required reports pending rather than creating native resources; external keys are policy_only, not scanner or merge-gate execution. Strict JSON rejects unknown, duplicate, null, invalid UTF-8 and trailing data. Config max 16 KiB, max 64 contexts of 1-128 bytes.
// produces:
// - application/json
// parameters:
// - name: key
//   in: path
//   type: string
//   required: true
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseFeaturePolicy"
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

// swagger:operation PUT /enterprise/authz/features/{key}/grants/global enterprise enterpriseFeatureGlobalPut
// ---
// summary: Enterprise feature policy GlobalPut
// description: Global requires current system management authority and admin scope; org requires current org management authority and organization scope; repo effective GET requires authenticated native visibility and repository read scope. Raw GET requires existing repository management authority. PUT/DELETE additionally require repository write scope and repo.manage_feature_grant even in shadow. Feature policy never grants native permission. Reader projection omits config, actor and ancestor IDs. required reports pending rather than creating native resources; external keys are policy_only, not scanner or merge-gate execution. Strict JSON rejects unknown, duplicate, null, invalid UTF-8 and trailing data. Config max 16 KiB, max 64 contexts of 1-128 bytes.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: key
//   in: path
//   type: string
//   required: true
// - name: body
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/PutEnterpriseFeatureGrantOption"
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseFeaturePolicy"
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
//     description: revision_conflict or feature_parent_locked

// swagger:operation DELETE /enterprise/authz/features/{key}/grants/global enterprise enterpriseFeatureGlobalDelete
// ---
// summary: Enterprise feature policy GlobalDelete
// description: Global requires current system management authority and admin scope; org requires current org management authority and organization scope; repo effective GET requires authenticated native visibility and repository read scope. Raw GET requires existing repository management authority. PUT/DELETE additionally require repository write scope and repo.manage_feature_grant even in shadow. Feature policy never grants native permission. Reader projection omits config, actor and ancestor IDs. required reports pending rather than creating native resources; external keys are policy_only, not scanner or merge-gate execution. Strict JSON rejects unknown, duplicate, null, invalid UTF-8 and trailing data. Config max 16 KiB, max 64 contexts of 1-128 bytes.
// produces:
// - application/json
// parameters:
// - name: key
//   in: path
//   type: string
//   required: true
// - name: expected_revision
//   in: query
//   type: integer
//   format: int64
//   minimum: 0
//   required: true
//   description: CAS reset to inherited; monotonic revision prevents ABA. Matching no-op does not increment revision or audit.
// responses:
//   "204":
//     description: Reset to inherited, or matching no-op
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
//     description: revision_conflict or feature_parent_locked

// swagger:operation GET /orgs/{org}/enterprise/authz/features enterprise enterpriseFeatureOrgList
// ---
// summary: Enterprise feature policy OrgList
// description: Global requires current system management authority and admin scope; org requires current org management authority and organization scope; repo effective GET requires authenticated native visibility and repository read scope. Raw GET requires existing repository management authority. PUT/DELETE additionally require repository write scope and repo.manage_feature_grant even in shadow. Feature policy never grants native permission. Reader projection omits config, actor and ancestor IDs. required reports pending rather than creating native resources; external keys are policy_only, not scanner or merge-gate execution. Strict JSON rejects unknown, duplicate, null, invalid UTF-8 and trailing data. Config max 16 KiB, max 64 contexts of 1-128 bytes.
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   type: string
//   required: true
// - name: page
//   in: query
//   type: integer
//   format: int64
//   description: 1-based page, default 1
// - name: limit
//   in: query
//   type: integer
//   format: int64
//   description: Page size, default 20, max 100
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseFeaturePolicyList"
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

// swagger:operation GET /orgs/{org}/enterprise/authz/features/{key} enterprise enterpriseFeatureOrgGet
// ---
// summary: Enterprise feature policy OrgGet
// description: Global requires current system management authority and admin scope; org requires current org management authority and organization scope; repo effective GET requires authenticated native visibility and repository read scope. Raw GET requires existing repository management authority. PUT/DELETE additionally require repository write scope and repo.manage_feature_grant even in shadow. Feature policy never grants native permission. Reader projection omits config, actor and ancestor IDs. required reports pending rather than creating native resources; external keys are policy_only, not scanner or merge-gate execution. Strict JSON rejects unknown, duplicate, null, invalid UTF-8 and trailing data. Config max 16 KiB, max 64 contexts of 1-128 bytes.
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   type: string
//   required: true
// - name: key
//   in: path
//   type: string
//   required: true
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseFeaturePolicy"
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

// swagger:operation PUT /orgs/{org}/enterprise/authz/features/{key} enterprise enterpriseFeatureOrgPut
// ---
// summary: Enterprise feature policy OrgPut
// description: Global requires current system management authority and admin scope; org requires current org management authority and organization scope; repo effective GET requires authenticated native visibility and repository read scope. Raw GET requires existing repository management authority. PUT/DELETE additionally require repository write scope and repo.manage_feature_grant even in shadow. Feature policy never grants native permission. Reader projection omits config, actor and ancestor IDs. required reports pending rather than creating native resources; external keys are policy_only, not scanner or merge-gate execution. Strict JSON rejects unknown, duplicate, null, invalid UTF-8 and trailing data. Config max 16 KiB, max 64 contexts of 1-128 bytes.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: org
//   in: path
//   type: string
//   required: true
// - name: key
//   in: path
//   type: string
//   required: true
// - name: body
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/PutEnterpriseFeatureGrantOption"
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseFeaturePolicy"
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
//     description: revision_conflict or feature_parent_locked

// swagger:operation DELETE /orgs/{org}/enterprise/authz/features/{key} enterprise enterpriseFeatureOrgDelete
// ---
// summary: Enterprise feature policy OrgDelete
// description: Global requires current system management authority and admin scope; org requires current org management authority and organization scope; repo effective GET requires authenticated native visibility and repository read scope. Raw GET requires existing repository management authority. PUT/DELETE additionally require repository write scope and repo.manage_feature_grant even in shadow. Feature policy never grants native permission. Reader projection omits config, actor and ancestor IDs. required reports pending rather than creating native resources; external keys are policy_only, not scanner or merge-gate execution. Strict JSON rejects unknown, duplicate, null, invalid UTF-8 and trailing data. Config max 16 KiB, max 64 contexts of 1-128 bytes.
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   type: string
//   required: true
// - name: key
//   in: path
//   type: string
//   required: true
// - name: expected_revision
//   in: query
//   type: integer
//   format: int64
//   minimum: 0
//   required: true
//   description: CAS reset to inherited; monotonic revision prevents ABA. Matching no-op does not increment revision or audit.
// responses:
//   "204":
//     description: Reset to inherited, or matching no-op
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
//     description: revision_conflict or feature_parent_locked

// swagger:operation GET /repos/{owner}/{repo}/enterprise/authz/features enterprise enterpriseFeatureRepoList
// ---
// summary: Enterprise feature policy RepoList
// description: Global requires current system management authority and admin scope; org requires current org management authority and organization scope; repo effective GET requires authenticated native visibility and repository read scope. Raw GET requires existing repository management authority. PUT/DELETE additionally require repository write scope and repo.manage_feature_grant even in shadow. Feature policy never grants native permission. Reader projection omits config, actor and ancestor IDs. required reports pending rather than creating native resources; external keys are policy_only, not scanner or merge-gate execution. Strict JSON rejects unknown, duplicate, null, invalid UTF-8 and trailing data. Config max 16 KiB, max 64 contexts of 1-128 bytes.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
// - name: repo
//   in: path
//   type: string
//   required: true
// - name: page
//   in: query
//   type: integer
//   format: int64
//   description: 1-based page, default 1
// - name: limit
//   in: query
//   type: integer
//   format: int64
//   description: Page size, default 20, max 100
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseFeatureEffectiveList"
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

// swagger:operation GET /repos/{owner}/{repo}/enterprise/authz/features/{key} enterprise enterpriseFeatureRepoGet
// ---
// summary: Enterprise feature policy RepoGet
// description: Global requires current system management authority and admin scope; org requires current org management authority and organization scope; repo effective GET requires authenticated native visibility and repository read scope. Raw GET requires existing repository management authority. PUT/DELETE additionally require repository write scope and repo.manage_feature_grant even in shadow. Feature policy never grants native permission. Reader projection omits config, actor and ancestor IDs. required reports pending rather than creating native resources; external keys are policy_only, not scanner or merge-gate execution. Strict JSON rejects unknown, duplicate, null, invalid UTF-8 and trailing data. Config max 16 KiB, max 64 contexts of 1-128 bytes.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
// - name: repo
//   in: path
//   type: string
//   required: true
// - name: key
//   in: path
//   type: string
//   required: true
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseFeatureEffective"
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

// swagger:operation PUT /repos/{owner}/{repo}/enterprise/authz/features/{key} enterprise enterpriseFeatureRepoPut
// ---
// summary: Enterprise feature policy RepoPut
// description: Global requires current system management authority and admin scope; org requires current org management authority and organization scope; repo effective GET requires authenticated native visibility and repository read scope. Raw GET requires existing repository management authority. PUT/DELETE additionally require repository write scope and repo.manage_feature_grant even in shadow. Feature policy never grants native permission. Reader projection omits config, actor and ancestor IDs. required reports pending rather than creating native resources; external keys are policy_only, not scanner or merge-gate execution. Strict JSON rejects unknown, duplicate, null, invalid UTF-8 and trailing data. Config max 16 KiB, max 64 contexts of 1-128 bytes.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
// - name: repo
//   in: path
//   type: string
//   required: true
// - name: key
//   in: path
//   type: string
//   required: true
// - name: body
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/PutEnterpriseFeatureGrantOption"
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseFeaturePolicy"
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
//     description: revision_conflict or feature_parent_locked

// swagger:operation DELETE /repos/{owner}/{repo}/enterprise/authz/features/{key} enterprise enterpriseFeatureRepoDelete
// ---
// summary: Enterprise feature policy RepoDelete
// description: Global requires current system management authority and admin scope; org requires current org management authority and organization scope; repo effective GET requires authenticated native visibility and repository read scope. Raw GET requires existing repository management authority. PUT/DELETE additionally require repository write scope and repo.manage_feature_grant even in shadow. Feature policy never grants native permission. Reader projection omits config, actor and ancestor IDs. required reports pending rather than creating native resources; external keys are policy_only, not scanner or merge-gate execution. Strict JSON rejects unknown, duplicate, null, invalid UTF-8 and trailing data. Config max 16 KiB, max 64 contexts of 1-128 bytes.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
// - name: repo
//   in: path
//   type: string
//   required: true
// - name: key
//   in: path
//   type: string
//   required: true
// - name: expected_revision
//   in: query
//   type: integer
//   format: int64
//   minimum: 0
//   required: true
//   description: CAS reset to inherited; monotonic revision prevents ABA. Matching no-op does not increment revision or audit.
// responses:
//   "204":
//     description: Reset to inherited, or matching no-op
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
//     description: revision_conflict or feature_parent_locked

// swagger:operation GET /repos/{owner}/{repo}/enterprise/authz/features/{key}/grant enterprise enterpriseFeatureRepoRaw
// ---
// summary: Enterprise feature policy RepoRaw
// description: Global requires current system management authority and admin scope; org requires current org management authority and organization scope; repo effective GET requires authenticated native visibility and repository read scope. Raw GET requires existing repository management authority. PUT/DELETE additionally require repository write scope and repo.manage_feature_grant even in shadow. Feature policy never grants native permission. Reader projection omits config, actor and ancestor IDs. required reports pending rather than creating native resources; external keys are policy_only, not scanner or merge-gate execution. Strict JSON rejects unknown, duplicate, null, invalid UTF-8 and trailing data. Config max 16 KiB, max 64 contexts of 1-128 bytes.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   type: string
//   required: true
// - name: repo
//   in: path
//   type: string
//   required: true
// - name: key
//   in: path
//   type: string
//   required: true
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseFeaturePolicy"
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
