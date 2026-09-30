// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package enterprisewecom

import (
	"errors"
	"net/http"

	audit_model "gitea.dev/models/audit"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/modules/setting"
	api "gitea.dev/modules/structs"
	"gitea.dev/services/audit"
	"gitea.dev/services/context"
	wecom_service "gitea.dev/services/enterprisewecom"
)

// ListAuthzMappings lists Enterprise WeCom authorization mappings.
func ListAuthzMappings(ctx *context.APIContext) {
	// swagger:operation GET /enterprise/wecom/mappings enterprise enterpriseWeComAuthzMappingList
	// ---
	// summary: List current application generated Enterprise WeCom mappings
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
	//   "401":
	//     "$ref": "#/responses/unauthorized"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	if !setting.EnterpriseWeCom.Enabled {
		ctx.APIErrorNotFound()
		return
	}
	mappings, err := wecom_service.ListGeneratedAuthzMappings(ctx, wecom_service.AuthzMappingListOptions{IncludeInactive: ctx.FormBool("include_inactive")})
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
	// summary: Get a current application generated Enterprise WeCom mapping
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
	//   "401":
	//     "$ref": "#/responses/unauthorized"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "404":
	//     "$ref": "#/responses/notFound"
	if !setting.EnterpriseWeCom.Enabled {
		ctx.APIErrorNotFound()
		return
	}
	mapping, err := wecom_service.GetGeneratedAuthzMapping(ctx, ctx.PathParamInt64("id"))
	if err != nil {
		handleMappingLookupError(ctx, err)
		return
	}
	ctx.JSON(http.StatusOK, convertAuthzMapping(mapping))
}

// CreateAuthzMapping rejects legacy manual mapping maintenance.
func CreateAuthzMapping(ctx *context.APIContext) {
	// swagger:operation POST /enterprise/wecom/mappings enterprise enterpriseWeComAuthzMappingCreate
	// ---
	// summary: Reject legacy manual Enterprise WeCom mapping maintenance
	// deprecated: true
	// produces:
	// - application/json
	// responses:
	//   "401":
	//     "$ref": "#/responses/unauthorized"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "410":
	//     description: Manual mapping maintenance is unavailable (manual_mapping_unavailable)
	rejectManualMappingWorkflow(ctx)
}

// UpdateAuthzMapping rejects legacy manual mapping maintenance.
func UpdateAuthzMapping(ctx *context.APIContext) {
	// swagger:operation PATCH /enterprise/wecom/mappings/{id} enterprise enterpriseWeComAuthzMappingUpdate
	// ---
	// summary: Reject legacy manual Enterprise WeCom mapping maintenance
	// deprecated: true
	// produces:
	// - application/json
	// parameters:
	// - name: id
	//   in: path
	//   description: legacy mapping id (not looked up)
	//   type: integer
	//   required: true
	// responses:
	//   "401":
	//     "$ref": "#/responses/unauthorized"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "410":
	//     description: Manual mapping maintenance is unavailable (manual_mapping_unavailable)
	rejectManualMappingWorkflow(ctx)
}

// DisableAuthzMapping rejects legacy manual mapping maintenance.
func DisableAuthzMapping(ctx *context.APIContext) {
	// swagger:operation DELETE /enterprise/wecom/mappings/{id} enterprise enterpriseWeComAuthzMappingDelete
	// ---
	// summary: Reject legacy manual Enterprise WeCom mapping maintenance
	// deprecated: true
	// produces:
	// - application/json
	// parameters:
	// - name: id
	//   in: path
	//   description: legacy mapping id (not looked up)
	//   type: integer
	//   required: true
	// responses:
	//   "401":
	//     "$ref": "#/responses/unauthorized"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "410":
	//     description: Manual mapping maintenance is unavailable (manual_mapping_unavailable)
	rejectManualMappingWorkflow(ctx)
}

// DryRunAuthzMappings rejects legacy manual mapping maintenance.
func DryRunAuthzMappings(ctx *context.APIContext) {
	// swagger:operation POST /enterprise/wecom/mappings/dry-run enterprise enterpriseWeComAuthzMappingDryRun
	// ---
	// summary: Reject legacy manual Enterprise WeCom mapping maintenance
	// deprecated: true
	// produces:
	// - application/json
	// responses:
	//   "401":
	//     "$ref": "#/responses/unauthorized"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "410":
	//     description: Manual mapping maintenance is unavailable (manual_mapping_unavailable)
	rejectManualMappingWorkflow(ctx)
}

// ApplyAuthzMappings rejects legacy manual mapping maintenance.
func ApplyAuthzMappings(ctx *context.APIContext) {
	// swagger:operation POST /enterprise/wecom/mappings/apply enterprise enterpriseWeComAuthzMappingApply
	// ---
	// summary: Reject legacy manual Enterprise WeCom mapping maintenance
	// deprecated: true
	// produces:
	// - application/json
	// responses:
	//   "401":
	//     "$ref": "#/responses/unauthorized"
	//   "403":
	//     "$ref": "#/responses/forbidden"
	//   "410":
	//     description: Manual mapping maintenance is unavailable (manual_mapping_unavailable)
	rejectManualMappingWorkflow(ctx)
}

func rejectManualMappingWorkflow(ctx *context.APIContext) {
	audit.Record(ctx, audit_model.EnterpriseWeComMappingUpdate, nil, "mapping_id", ctx.PathParamInt64("id"), "outcome", "denied", "reason", "manual_mapping_unavailable")
	ctx.APIError(http.StatusGone, "manual_mapping_unavailable")
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
