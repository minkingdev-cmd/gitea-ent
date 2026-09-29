# Implementation Notes: wecom-directory-authz-mapping

## Task 1.1 hook points

- WeCom sync entry point: `services/enterprisewecom/sync.go:SyncDirectory` wraps `syncDirectory`, records `enterprise:wecom:sync:start/finish`, and commits directory snapshot inside `db.WithTx` in `syncDirectory`.
- Cron entry point: `services/cron/tasks_basic.go:registerEnterpriseWeComDirectorySync` calls `enterprisewecom_service.SyncDirectory(ctx, enterprisewecom_service.NewClientFromSettings())`.
- WeCom config: `modules/setting/enterprise_wecom.go` owns `[enterprise.wecom]`; add disabled-by-default `ApplyAuthzMappingsOnSync` there and document in `custom/conf/app.example.ini`.
- WeCom models: `models/enterprisewecom` already registers identity, department, tag, membership models; additive mapping models should live there and avoid changing `team_user` / `org_user`.
- Explicit migrations: current WeCom migrations are `modelmigration/v28/v354.go` and `v355.go`, registered in `modelmigration/migrations.go`; new tables should use the next IDs after 355.
- Team membership add/remove: `services/org/team.go:AddTeamMember` and `RemoveTeamMember` preserve Gitea side effects and audit. Use these for team targets rather than direct writes.
- Org membership removal: `services/org/user.go:RemoveOrgUser` is destructive and removes team membership; org-target removal must be conservative and only call it when safe.
- Membership queries: `models/organization/team_user.go` and `org_user.go` provide `IsTeamMember` / `IsOrganizationMember` and related helpers.
- Audit action definitions: `models/audit/action.go` has existing `EnterpriseWeCom*` actions; add mapping config/apply actions there and record via `services/audit` helpers.
- Admin API guard: `routers/api/v1/api.go:reqSiteAdmin` and `/admin` group show the existing site-admin pattern with `tokenRequiresScopes(admin)`, `reqToken()`, `reqSiteAdmin()`.
- API route placement: either under existing `/admin` group or a new `/enterprise/wecom/mappings` group with equivalent `reqToken()` + `reqSiteAdmin()` guard; design selected `/enterprise/wecom/mappings` semantics.
- Swagger pattern: handlers use `// swagger:operation ...` comments and require `make generate-swagger` / `make swagger-validate` after API changes.
