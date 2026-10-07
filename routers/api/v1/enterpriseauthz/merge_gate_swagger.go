// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterpriseauthz

// swagger:operation GET /admin/enterprise/authz/protected-path-rules enterprise enterpriseMergeGateGlobalListRule
// ---
// summary: Global protected path rule list
// description: Requires current scope management authority and matching token read/write scope; public-only credentials are rejected. Repository writes also require native code visibility and repo.manage_sensitive_paths, including in shadow. Rules accumulate; they do not grant native access. Strict JSON rejects duplicate, unknown and null fields. Config max 16 KiB; patterns max 256 bytes; at most 64 exact contexts of 128 bytes. New rules use expected_revision 0; edits and deletion require current revision. Deleted IDs cannot be reused. Disabled merge gate returns 404.
// produces:
// - application/json
// parameters:
// - name: page
//   in: query
//   type: integer
//   default: 1
//   minimum: 1
// - name: limit
//   in: query
//   type: integer
//   default: 20
//   minimum: 1
//   maximum: 100
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseProtectedPathRuleList"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "503":
//     "$ref": "#/responses/error"

// swagger:operation POST /admin/enterprise/authz/protected-path-rules enterprise enterpriseMergeGateGlobalCreateRule
// ---
// summary: Global protected path rule create
// description: Requires current scope management authority and matching token read/write scope; public-only credentials are rejected. Repository writes also require native code visibility and repo.manage_sensitive_paths, including in shadow. Rules accumulate; they do not grant native access. Strict JSON rejects duplicate, unknown and null fields. Config max 16 KiB; patterns max 256 bytes; at most 64 exact contexts of 128 bytes. New rules use expected_revision 0; edits and deletion require current revision. Deleted IDs cannot be reused. Disabled merge gate returns 404.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: body
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/PutEnterpriseProtectedPathRuleOption"
// responses:
//   "201":
//     "$ref": "#/responses/EnterpriseProtectedPathRule"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "503":
//     "$ref": "#/responses/error"
//   "409":
//     description: revision_conflict

// swagger:operation GET /admin/enterprise/authz/protected-path-rules/{id} enterprise enterpriseMergeGateGlobalGetRule
// ---
// summary: Global protected path rule get
// description: Requires current scope management authority and matching token read/write scope; public-only credentials are rejected. Repository writes also require native code visibility and repo.manage_sensitive_paths, including in shadow. Rules accumulate; they do not grant native access. Strict JSON rejects duplicate, unknown and null fields. Config max 16 KiB; patterns max 256 bytes; at most 64 exact contexts of 128 bytes. New rules use expected_revision 0; edits and deletion require current revision. Deleted IDs cannot be reused. Disabled merge gate returns 404.
// produces:
// - application/json
// parameters:
// - name: id
//   in: path
//   required: true
//   type: integer
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseProtectedPathRule"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "503":
//     "$ref": "#/responses/error"

// swagger:operation PATCH /admin/enterprise/authz/protected-path-rules/{id} enterprise enterpriseMergeGateGlobalUpdateRule
// ---
// summary: Global protected path rule update
// description: Requires current scope management authority and matching token read/write scope; public-only credentials are rejected. Repository writes also require native code visibility and repo.manage_sensitive_paths, including in shadow. Rules accumulate; they do not grant native access. Strict JSON rejects duplicate, unknown and null fields. Config max 16 KiB; patterns max 256 bytes; at most 64 exact contexts of 128 bytes. New rules use expected_revision 0; edits and deletion require current revision. Deleted IDs cannot be reused. Disabled merge gate returns 404.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: id
//   in: path
//   required: true
//   type: integer
// - name: body
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/PutEnterpriseProtectedPathRuleOption"
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseProtectedPathRule"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "503":
//     "$ref": "#/responses/error"
//   "409":
//     description: revision_conflict

// swagger:operation DELETE /admin/enterprise/authz/protected-path-rules/{id} enterprise enterpriseMergeGateGlobalDeleteRule
// ---
// summary: Global protected path rule delete
// description: Requires current scope management authority and matching token read/write scope; public-only credentials are rejected. Repository writes also require native code visibility and repo.manage_sensitive_paths, including in shadow. Rules accumulate; they do not grant native access. Strict JSON rejects duplicate, unknown and null fields. Config max 16 KiB; patterns max 256 bytes; at most 64 exact contexts of 128 bytes. New rules use expected_revision 0; edits and deletion require current revision. Deleted IDs cannot be reused. Disabled merge gate returns 404.
// produces:
// - application/json
// parameters:
// - name: id
//   in: path
//   required: true
//   type: integer
// - name: expected_revision
//   in: query
//   required: true
//   type: integer
//   format: int64
//   minimum: 1
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
//   "503":
//     "$ref": "#/responses/error"
//   "409":
//     description: revision_conflict

// swagger:operation GET /orgs/{org}/enterprise/authz/protected-path-rules enterprise enterpriseMergeGateOrgListRule
// ---
// summary: Org protected path rule list
// description: Requires current scope management authority and matching token read/write scope; public-only credentials are rejected. Repository writes also require native code visibility and repo.manage_sensitive_paths, including in shadow. Rules accumulate; they do not grant native access. Strict JSON rejects duplicate, unknown and null fields. Config max 16 KiB; patterns max 256 bytes; at most 64 exact contexts of 128 bytes. New rules use expected_revision 0; edits and deletion require current revision. Deleted IDs cannot be reused. Disabled merge gate returns 404.
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   required: true
//   type: string
// - name: page
//   in: query
//   type: integer
//   default: 1
//   minimum: 1
// - name: limit
//   in: query
//   type: integer
//   default: 20
//   minimum: 1
//   maximum: 100
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseProtectedPathRuleList"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "503":
//     "$ref": "#/responses/error"

// swagger:operation POST /orgs/{org}/enterprise/authz/protected-path-rules enterprise enterpriseMergeGateOrgCreateRule
// ---
// summary: Org protected path rule create
// description: Requires current scope management authority and matching token read/write scope; public-only credentials are rejected. Repository writes also require native code visibility and repo.manage_sensitive_paths, including in shadow. Rules accumulate; they do not grant native access. Strict JSON rejects duplicate, unknown and null fields. Config max 16 KiB; patterns max 256 bytes; at most 64 exact contexts of 128 bytes. New rules use expected_revision 0; edits and deletion require current revision. Deleted IDs cannot be reused. Disabled merge gate returns 404.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: org
//   in: path
//   required: true
//   type: string
// - name: body
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/PutEnterpriseProtectedPathRuleOption"
// responses:
//   "201":
//     "$ref": "#/responses/EnterpriseProtectedPathRule"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "503":
//     "$ref": "#/responses/error"
//   "409":
//     description: revision_conflict

// swagger:operation GET /orgs/{org}/enterprise/authz/protected-path-rules/{id} enterprise enterpriseMergeGateOrgGetRule
// ---
// summary: Org protected path rule get
// description: Requires current scope management authority and matching token read/write scope; public-only credentials are rejected. Repository writes also require native code visibility and repo.manage_sensitive_paths, including in shadow. Rules accumulate; they do not grant native access. Strict JSON rejects duplicate, unknown and null fields. Config max 16 KiB; patterns max 256 bytes; at most 64 exact contexts of 128 bytes. New rules use expected_revision 0; edits and deletion require current revision. Deleted IDs cannot be reused. Disabled merge gate returns 404.
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   required: true
//   type: string
// - name: id
//   in: path
//   required: true
//   type: integer
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseProtectedPathRule"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "503":
//     "$ref": "#/responses/error"

// swagger:operation PATCH /orgs/{org}/enterprise/authz/protected-path-rules/{id} enterprise enterpriseMergeGateOrgUpdateRule
// ---
// summary: Org protected path rule update
// description: Requires current scope management authority and matching token read/write scope; public-only credentials are rejected. Repository writes also require native code visibility and repo.manage_sensitive_paths, including in shadow. Rules accumulate; they do not grant native access. Strict JSON rejects duplicate, unknown and null fields. Config max 16 KiB; patterns max 256 bytes; at most 64 exact contexts of 128 bytes. New rules use expected_revision 0; edits and deletion require current revision. Deleted IDs cannot be reused. Disabled merge gate returns 404.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: org
//   in: path
//   required: true
//   type: string
// - name: id
//   in: path
//   required: true
//   type: integer
// - name: body
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/PutEnterpriseProtectedPathRuleOption"
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseProtectedPathRule"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "503":
//     "$ref": "#/responses/error"
//   "409":
//     description: revision_conflict

// swagger:operation DELETE /orgs/{org}/enterprise/authz/protected-path-rules/{id} enterprise enterpriseMergeGateOrgDeleteRule
// ---
// summary: Org protected path rule delete
// description: Requires current scope management authority and matching token read/write scope; public-only credentials are rejected. Repository writes also require native code visibility and repo.manage_sensitive_paths, including in shadow. Rules accumulate; they do not grant native access. Strict JSON rejects duplicate, unknown and null fields. Config max 16 KiB; patterns max 256 bytes; at most 64 exact contexts of 128 bytes. New rules use expected_revision 0; edits and deletion require current revision. Deleted IDs cannot be reused. Disabled merge gate returns 404.
// produces:
// - application/json
// parameters:
// - name: org
//   in: path
//   required: true
//   type: string
// - name: id
//   in: path
//   required: true
//   type: integer
// - name: expected_revision
//   in: query
//   required: true
//   type: integer
//   format: int64
//   minimum: 1
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
//   "503":
//     "$ref": "#/responses/error"
//   "409":
//     description: revision_conflict

// swagger:operation GET /repos/{owner}/{repo}/enterprise/authz/protected-path-rules enterprise enterpriseMergeGateRepoListRule
// ---
// summary: Repo protected path rule list
// description: Requires current scope management authority and matching token read/write scope; public-only credentials are rejected. Repository writes also require native code visibility and repo.manage_sensitive_paths, including in shadow. Rules accumulate; they do not grant native access. Strict JSON rejects duplicate, unknown and null fields. Config max 16 KiB; patterns max 256 bytes; at most 64 exact contexts of 128 bytes. New rules use expected_revision 0; edits and deletion require current revision. Deleted IDs cannot be reused. Disabled merge gate returns 404.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   required: true
//   type: string
// - name: repo
//   in: path
//   required: true
//   type: string
// - name: page
//   in: query
//   type: integer
//   default: 1
//   minimum: 1
// - name: limit
//   in: query
//   type: integer
//   default: 20
//   minimum: 1
//   maximum: 100
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseProtectedPathRuleList"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "503":
//     "$ref": "#/responses/error"

// swagger:operation POST /repos/{owner}/{repo}/enterprise/authz/protected-path-rules enterprise enterpriseMergeGateRepoCreateRule
// ---
// summary: Repo protected path rule create
// description: Requires current scope management authority and matching token read/write scope; public-only credentials are rejected. Repository writes also require native code visibility and repo.manage_sensitive_paths, including in shadow. Rules accumulate; they do not grant native access. Strict JSON rejects duplicate, unknown and null fields. Config max 16 KiB; patterns max 256 bytes; at most 64 exact contexts of 128 bytes. New rules use expected_revision 0; edits and deletion require current revision. Deleted IDs cannot be reused. Disabled merge gate returns 404.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: owner
//   in: path
//   required: true
//   type: string
// - name: repo
//   in: path
//   required: true
//   type: string
// - name: body
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/PutEnterpriseProtectedPathRuleOption"
// responses:
//   "201":
//     "$ref": "#/responses/EnterpriseProtectedPathRule"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "503":
//     "$ref": "#/responses/error"
//   "409":
//     description: revision_conflict

// swagger:operation GET /repos/{owner}/{repo}/enterprise/authz/protected-path-rules/{id} enterprise enterpriseMergeGateRepoGetRule
// ---
// summary: Repo protected path rule get
// description: Requires current scope management authority and matching token read/write scope; public-only credentials are rejected. Repository writes also require native code visibility and repo.manage_sensitive_paths, including in shadow. Rules accumulate; they do not grant native access. Strict JSON rejects duplicate, unknown and null fields. Config max 16 KiB; patterns max 256 bytes; at most 64 exact contexts of 128 bytes. New rules use expected_revision 0; edits and deletion require current revision. Deleted IDs cannot be reused. Disabled merge gate returns 404.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   required: true
//   type: string
// - name: repo
//   in: path
//   required: true
//   type: string
// - name: id
//   in: path
//   required: true
//   type: integer
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseProtectedPathRule"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "503":
//     "$ref": "#/responses/error"

// swagger:operation PATCH /repos/{owner}/{repo}/enterprise/authz/protected-path-rules/{id} enterprise enterpriseMergeGateRepoUpdateRule
// ---
// summary: Repo protected path rule update
// description: Requires current scope management authority and matching token read/write scope; public-only credentials are rejected. Repository writes also require native code visibility and repo.manage_sensitive_paths, including in shadow. Rules accumulate; they do not grant native access. Strict JSON rejects duplicate, unknown and null fields. Config max 16 KiB; patterns max 256 bytes; at most 64 exact contexts of 128 bytes. New rules use expected_revision 0; edits and deletion require current revision. Deleted IDs cannot be reused. Disabled merge gate returns 404.
// produces:
// - application/json
// consumes:
// - application/json
// parameters:
// - name: owner
//   in: path
//   required: true
//   type: string
// - name: repo
//   in: path
//   required: true
//   type: string
// - name: id
//   in: path
//   required: true
//   type: integer
// - name: body
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/PutEnterpriseProtectedPathRuleOption"
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseProtectedPathRule"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "503":
//     "$ref": "#/responses/error"
//   "409":
//     description: revision_conflict

// swagger:operation DELETE /repos/{owner}/{repo}/enterprise/authz/protected-path-rules/{id} enterprise enterpriseMergeGateRepoDeleteRule
// ---
// summary: Repo protected path rule delete
// description: Requires current scope management authority and matching token read/write scope; public-only credentials are rejected. Repository writes also require native code visibility and repo.manage_sensitive_paths, including in shadow. Rules accumulate; they do not grant native access. Strict JSON rejects duplicate, unknown and null fields. Config max 16 KiB; patterns max 256 bytes; at most 64 exact contexts of 128 bytes. New rules use expected_revision 0; edits and deletion require current revision. Deleted IDs cannot be reused. Disabled merge gate returns 404.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   required: true
//   type: string
// - name: repo
//   in: path
//   required: true
//   type: string
// - name: id
//   in: path
//   required: true
//   type: integer
// - name: expected_revision
//   in: query
//   required: true
//   type: integer
//   format: int64
//   minimum: 1
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
//   "503":
//     "$ref": "#/responses/error"
//   "409":
//     description: revision_conflict

// swagger:operation GET /repos/{owner}/{repo}/enterprise/merge-gate/{index}/evaluations enterprise enterpriseMergeGateListEvaluations
// ---
// summary: List PR merge gate evaluation history
// description: Requires current repository policy management authority, code and PR visibility and read repository token scope. Public-only credentials are rejected. Evaluation IDs are scoped to this repository and pull request. Unknown snapshot versions fail closed. Disabled merge gate returns 404. Records are evidence, never reusable execution permission.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   required: true
//   type: string
// - name: repo
//   in: path
//   required: true
//   type: string
// - name: index
//   in: path
//   required: true
//   type: integer
//   format: int64
//   minimum: 1
// - name: page
//   in: query
//   type: integer
//   default: 1
//   minimum: 1
// - name: limit
//   in: query
//   type: integer
//   default: 20
//   minimum: 1
//   maximum: 100
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseMergeGateEvaluationList"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "503":
//     "$ref": "#/responses/error"

// swagger:operation GET /repos/{owner}/{repo}/enterprise/merge-gate/{index}/evaluations/{id} enterprise enterpriseMergeGateGetEvaluation
// ---
// summary: Get PR merge gate evaluation history
// description: Requires current repository policy management authority, code and PR visibility and read repository token scope. Public-only credentials are rejected. Evaluation IDs are scoped to this repository and pull request. Unknown snapshot versions fail closed. Disabled merge gate returns 404. Records are evidence, never reusable execution permission.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   required: true
//   type: string
// - name: repo
//   in: path
//   required: true
//   type: string
// - name: index
//   in: path
//   required: true
//   type: integer
//   format: int64
//   minimum: 1
// - name: id
//   in: path
//   required: true
//   type: integer
//   format: int64
//   minimum: 1
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseMergeGateEvaluation"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "503":
//     "$ref": "#/responses/error"

// swagger:operation GET /repos/{owner}/{repo}/enterprise/merge-gate/{index} enterprise enterpriseMergeGatePreview
// ---
// summary: Preview current PR merge gate conditions
// description: Requires authentication, current code and PR visibility and read repository token scope. Returns safe reasons only, without raw contexts, policy IDs, configuration, history or bypass text. This read-only candidate is not execution permission and does not write admission evidence. Disabled merge gate returns 404.
// produces:
// - application/json
// parameters:
// - name: owner
//   in: path
//   required: true
//   type: string
// - name: repo
//   in: path
//   required: true
//   type: string
// - name: index
//   in: path
//   required: true
//   type: integer
//   format: int64
//   minimum: 1
// - name: style
//   in: query
//   type: string
//   enum: [merge, rebase, rebase-merge, squash, fast-forward-only, manually-merged]
// - name: commit_id
//   in: query
//   type: string
//   description: Full commit ID for read-only manual recognition preview
// responses:
//   "200":
//     "$ref": "#/responses/EnterpriseMergeGatePreview"
//   "401":
//     "$ref": "#/responses/error"
//   "403":
//     "$ref": "#/responses/forbidden"
//   "404":
//     "$ref": "#/responses/notFound"
//   "422":
//     "$ref": "#/responses/validationError"
//   "503":
//     "$ref": "#/responses/error"
