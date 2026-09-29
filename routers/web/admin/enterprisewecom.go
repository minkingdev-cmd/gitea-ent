// Copyright 2026 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package admin

import (
	"net/http"
	"time"

	"gitea.dev/models/db"
	wecom_model "gitea.dev/models/enterprisewecom"
	"gitea.dev/models/organization"
	"gitea.dev/modules/log"
	"gitea.dev/modules/setting"
	"gitea.dev/modules/templates"
	"gitea.dev/services/context"
	"gitea.dev/services/cron"
	wecom_service "gitea.dev/services/enterprisewecom"
	repo_service "gitea.dev/services/repository"
)

const tplEnterpriseWeCom templates.TplName = "admin/enterprisewecom/overview"

type enterpriseWeComCronStatus struct {
	Enabled     bool
	Schedule    string
	Status      string
	LastMessage string
	LastDoer    string
	ExecTimes   int64
	Next        time.Time
	Prev        time.Time
}

func EnterpriseWeCom(ctx *context.Context) {
	renderEnterpriseWeCom(ctx, "overview")
}

func EnterpriseWeComGeneratedMappings(ctx *context.Context) {
	renderEnterpriseWeCom(ctx, "mappings")
}

func EnterpriseWeComGeneratedTeams(ctx *context.Context) {
	renderEnterpriseWeCom(ctx, "teams")
}

func EnterpriseWeComReconciliationRuns(ctx *context.Context) {
	renderEnterpriseWeCom(ctx, "runs")
}

func EnterpriseWeComAuthority(ctx *context.Context) {
	renderEnterpriseWeCom(ctx, "authority")
}

func EnterpriseWeComOrgRepoRequests(ctx *context.Context) {
	renderEnterpriseWeCom(ctx, "repo-requests")
}

func EnterpriseWeComApproveOrgRepoRequest(ctx *context.Context) {
	if !enterpriseWeComAdminIsSuperAdmin(ctx) {
		ctx.HTTPError(http.StatusForbidden)
		return
	}
	if _, err := repo_service.ApproveOrganizationRepositoryRequest(ctx, ctx.Doer, ctx.PathParamInt64("id"), ctx.FormString("reason")); err != nil {
		log.Error("ApproveOrganizationRepositoryRequest: %v", err)
		ctx.Flash.Error(err.Error())
	} else {
		ctx.Flash.Success(ctx.Tr("admin.enterprise_wecom.org_repo_request_approved"))
	}
	ctx.Redirect(setting.AppSubURL + "/-/admin/enterprise/wecom/org-repo-requests")
}

func EnterpriseWeComRejectOrgRepoRequest(ctx *context.Context) {
	if !enterpriseWeComAdminIsSuperAdmin(ctx) {
		ctx.HTTPError(http.StatusForbidden)
		return
	}
	if err := repo_service.RejectOrganizationRepositoryRequest(ctx, ctx.Doer, ctx.PathParamInt64("id"), ctx.FormString("reason")); err != nil {
		log.Error("RejectOrganizationRepositoryRequest: %v", err)
		ctx.Flash.Error(err.Error())
	} else {
		ctx.Flash.Success(ctx.Tr("admin.enterprise_wecom.org_repo_request_rejected"))
	}
	ctx.Redirect(setting.AppSubURL + "/-/admin/enterprise/wecom/org-repo-requests")
}

func renderEnterpriseWeCom(ctx *context.Context, tab string) {
	ctx.Data["Title"] = ctx.Tr("admin.enterprise_wecom")
	ctx.Data["PageIsAdminEnterpriseWeCom"] = true
	ctx.Data["EnterpriseWeComTab"] = tab
	ctx.Data["EnterpriseWeComCron"] = enterpriseWeComCron()

	diagnostics, err := wecom_service.BuildAdminAuthorityDiagnostics(ctx, wecom_service.AdminAuthorityDiagnosticsOptions{})
	if err != nil {
		ctx.ServerError("BuildAdminAuthorityDiagnostics", err)
		return
	}
	ctx.Data["AuthorityDiagnostics"] = diagnostics

	if err := loadEnterpriseWeComAdminData(ctx); err != nil {
		ctx.ServerError("loadEnterpriseWeComAdminData", err)
		return
	}
	ctx.HTML(http.StatusOK, tplEnterpriseWeCom)
}

func enterpriseWeComAdminIsSuperAdmin(ctx *context.Context) bool {
	ok, err := wecom_model.IsActiveManagementAuthorityBoundUser(ctx, setting.EnterpriseWeCom.CorpID, setting.EnterpriseWeCom.AgentID, ctx.Doer.ID)
	if err != nil {
		log.Error("IsActiveManagementAuthorityBoundUser: %v", err)
		return false
	}
	return ok
}

func enterpriseWeComCron() enterpriseWeComCronStatus {
	task := cron.GetTask("sync_enterprise_wecom_directory")
	if task == nil {
		return enterpriseWeComCronStatus{}
	}
	config := task.GetConfig()
	status := enterpriseWeComCronStatus{
		Enabled:     task.IsEnabled(),
		Schedule:    config.GetSchedule(),
		Status:      task.Status,
		LastMessage: task.LastMessage,
		LastDoer:    task.LastDoer,
		ExecTimes:   task.ExecTimes,
	}
	for _, row := range cron.ListTasks() {
		if row.Name == task.Name {
			status.Next = row.Next
			status.Prev = row.Prev
			break
		}
	}
	return status
}

func loadEnterpriseWeComAdminData(ctx *context.Context) error {
	var runs []wecom_model.ReconcileRun
	if err := db.GetEngine(ctx).Desc("id").Limit(20).Find(&runs); err != nil {
		return err
	}
	ctx.Data["ReconcileRuns"] = runs
	if len(runs) > 0 {
		ctx.Data["LastReconcileRun"] = runs[0]
	}

	var mappings []wecom_model.GeneratedMapping
	if err := db.GetEngine(ctx).Desc("id").Limit(50).Find(&mappings); err != nil {
		return err
	}
	ctx.Data["GeneratedMappings"] = mappings

	var teams []wecom_model.GeneratedTeam
	if err := db.GetEngine(ctx).Desc("id").Limit(50).Find(&teams); err != nil {
		return err
	}
	ctx.Data["GeneratedTeams"] = teams

	var teamAdmins []wecom_model.GeneratedTeamAdmin
	if err := db.GetEngine(ctx).Desc("id").Limit(50).Find(&teamAdmins); err != nil {
		return err
	}
	ctx.Data["GeneratedTeamAdmins"] = teamAdmins

	var authorities []wecom_model.AdminAuthority
	if err := db.GetEngine(ctx).Desc("id").Limit(50).Find(&authorities); err != nil {
		return err
	}
	ctx.Data["AdminAuthorities"] = authorities

	var requests []wecom_model.OrgRepoRequest
	if err := db.GetEngine(ctx).Desc("id").Limit(50).Find(&requests); err != nil {
		return err
	}
	ctx.Data["OrgRepoRequests"] = requests
	ctx.Data["EnterpriseWeComSuperAdmin"] = enterpriseWeComAdminIsSuperAdmin(ctx)

	orgCount, err := organization.CountOrganizations(ctx)
	if err != nil {
		return err
	}
	ctx.Data["SingleOrgCount"] = orgCount
	ctx.Data["SingleOrgViolation"] = false
	return nil
}
