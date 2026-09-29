// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"errors"
	"net/http"

	wecom_model "gitea.dev/models/enterprisewecom"
	api "gitea.dev/modules/structs"
	"gitea.dev/services/context"
	wecom_service "gitea.dev/services/enterprisewecom"
)

// ListAuthzMappings lists Enterprise WeCom authorization mappings.
func ListAuthzMappings(ctx *context.APIContext) {
	// swagger:operation GET /enterprise/wecom/mappings enterprise enterpriseWeComAuthzMappingList
	// ---
	// summary: List Enterprise WeCom authorization mappings
	// produces:
	// - application/json
	// parameters:
	// - name: include_inactive
	//   in: query
	//   description: include disabled mappings
	//   type: boolean
	// responses:
	//   "200":
	//     "$ref": "#/responses/EnterpriseWeComAuthzMappingList"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	mappings, err := wecom_service.ListAuthzMappings(ctx, wecom_service.AuthzMappingListOptions{IncludeInactive: ctx.FormBool("include_inactive")})
	if err != nil {
		ctx.APIErrorInternal(err)
		return
	}
	resp := make([]api.EnterpriseWeComAuthzMapping, 0, len(mappings))
	for _, mapping := range mappings {
		resp = append(resp, convertAuthzMapping(mapping))
	}
	ctx.JSON(http.StatusOK, resp)
}

// GetAuthzMapping returns one Enterprise WeCom authorization mapping.
func GetAuthzMapping(ctx *context.APIContext) {
	// swagger:operation GET /enterprise/wecom/mappings/{id} enterprise enterpriseWeComAuthzMappingGet
	// ---
	// summary: Get an Enterprise WeCom authorization mapping
	// produces:
	// - application/json
	// parameters:
	// - name: id
	//   in: path
	//   description: mapping id
	//   type: integer
	//   required: true
	// responses:
	//   "200":
	//     "$ref": "#/responses/EnterpriseWeComAuthzMapping"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	mapping, err := wecom_service.GetAuthzMapping(ctx, ctx.PathParamInt64("id"))
	if err != nil {
		handleMappingLookupError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, convertAuthzMapping(mapping))
}

// CreateAuthzMapping creates an Enterprise WeCom authorization mapping.
func CreateAuthzMapping(ctx *context.APIContext) {
	// swagger:operation POST /enterprise/wecom/mappings enterprise enterpriseWeComAuthzMappingCreate
	// ---
	// summary: Create an Enterprise WeCom authorization mapping
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/EnterpriseWeComAuthzMappingOption"
	// responses:
	//   "201":
	//     "$ref": "#/responses/EnterpriseWeComAuthzMapping"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "422":
	//     "$ref": "#/responses/validationError"
	rejectManualMappingWorkflow(ctx)
}

// UpdateAuthzMapping updates an Enterprise WeCom authorization mapping.
func UpdateAuthzMapping(ctx *context.APIContext) {
	// swagger:operation PATCH /enterprise/wecom/mappings/{id} enterprise enterpriseWeComAuthzMappingUpdate
	// ---
	// summary: Update an Enterprise WeCom authorization mapping
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: id
	//   in: path
	//   description: mapping id
	//   type: integer
	//   required: true
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/EnterpriseWeComAuthzMappingOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/EnterpriseWeComAuthzMapping"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	//   "422":
	//     "$ref": "#/responses/validationError"
	rejectManualMappingWorkflow(ctx)
}

// DisableAuthzMapping disables an Enterprise WeCom authorization mapping.
func DisableAuthzMapping(ctx *context.APIContext) {
	// swagger:operation DELETE /enterprise/wecom/mappings/{id} enterprise enterpriseWeComAuthzMappingDelete
	// ---
	// summary: Disable an Enterprise WeCom authorization mapping
	// produces:
	// - application/json
	// parameters:
	// - name: id
	//   in: path
	//   description: mapping id
	//   type: integer
	//   required: true
	// responses:
	//   "204":
	//     "$ref": "#/responses/empty"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	rejectManualMappingWorkflow(ctx)
}

// DryRunAuthzMappings dry-runs active Enterprise WeCom authorization mappings.
func DryRunAuthzMappings(ctx *context.APIContext) {
	// swagger:operation POST /enterprise/wecom/mappings/dry-run enterprise enterpriseWeComAuthzMappingDryRun
	// ---
	// summary: Dry-run Enterprise WeCom authorization mapping reconciliation
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/EnterpriseWeComAuthzReconcileOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/EnterpriseWeComAuthzReconcileResult"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	rejectManualMappingWorkflow(ctx)
}

// ApplyAuthzMappings applies active Enterprise WeCom authorization mappings.
func ApplyAuthzMappings(ctx *context.APIContext) {
	// swagger:operation POST /enterprise/wecom/mappings/apply enterprise enterpriseWeComAuthzMappingApply
	// ---
	// summary: Apply Enterprise WeCom authorization mappings
	// consumes:
	// - application/json
	// produces:
	// - application/json
	// parameters:
	// - name: body
	//   in: body
	//   schema:
	//     "$ref": "#/definitions/EnterpriseWeComAuthzReconcileOption"
	// responses:
	//   "200":
	//     "$ref": "#/responses/EnterpriseWeComAuthzReconcileResult"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "422":
	//     "$ref": "#/responses/validationError"
	rejectManualMappingWorkflow(ctx)
}

func rejectManualMappingWorkflow(ctx *context.APIContext) {
	ctx.APIError(http.StatusGone, "enterprise wecom authorization is generated by scheduled automation; manual mapping maintenance is not available")
}

func convertAuthzMapping(mapping *wecom_model.AuthzMapping) api.EnterpriseWeComAuthzMapping {
	return api.EnterpriseWeComAuthzMapping{
		ID:         mapping.ID,
		CorpID:     mapping.CorpID,
		SourceType: string(mapping.SourceType),
		SourceID:   mapping.SourceID,
		TargetType: string(mapping.TargetType),
		OrgID:      mapping.OrgID,
		TeamID:     mapping.TeamID,
		Active:     mapping.IsActive,
		CreatedBy:  mapping.CreatedBy,
		Created:    mapping.CreatedUnix.AsTime(),
		Updated:    mapping.UpdatedUnix.AsTime(),
	}
}

func handleMappingLookupError(ctx *context.APIContext, err error) {
	if errors.Is(err, wecom_service.ErrInvalidAuthzMapping) {
		ctx.APIErrorNotFound()
		return
	}
	ctx.APIErrorInternal(err)
}
