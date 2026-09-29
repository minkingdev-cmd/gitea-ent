# Implementation notes

## 2026-09-29 baseline inventory

### Development targets

- Ran `make help`; relevant targets include `fmt`, `generate-swagger`, `lint-go`, `lint-templates`, `test-backend[#TestSpecificName]`, and `test-integration[#TestSpecificName]`.

### Existing product paths inspected before product-code edits

- Enterprise WeCom settings and sync:
  - `modules/setting/enterprise_wecom.go`
  - `services/enterprisewecom/sync.go`
  - `services/cron/tasks_basic.go`
- Existing manual mapping/reconciliation work that must stop being a normal operator workflow:
  - `models/enterprisewecom/mapping.go`
  - `services/enterprisewecom/mapping.go`
  - `services/enterprisewecom/reconcile.go`
  - `routers/api/v1/enterprisewecom/mapping.go`
  - `routers/api/v1/api.go` `/enterprise/wecom/mappings` group
- Admin Web/API user mutation entry points:
  - Web admin group under `routers/web/web.go` (`/-/admin/users`, edit, impersonate, delete, avatar, access token, org membership removal, emails)
  - Admin API group under `routers/api/v1/api.go` and handlers under `routers/api/v1/admin/`
  - User-facing service paths under `services/user/`, `models/user/`, and admin templates under `templates/admin/`
- Organization, team, and repository governance entry points:
  - Organization create: `routers/web/org/org.go`, `routers/api/v1/org/org.go`, `models/organization/org.go`
  - Team Web/API routes: `routers/web/web.go`, `routers/api/v1/org/team.go`, `routers/api/v1/api.go`
  - Repository create: `routers/web/repo/repo.go`, `routers/api/v1/repo/repo.go`, `routers/api/v1/admin/repo.go`, `services/repository/create.go`, `services/repository/repository.go`
  - Collaborator/team grants: `routers/web/repo/setting/collaboration.go`, `routers/api/v1/repo/collaborators.go`, `routers/api/v1/repo/teams.go`, `services/repository/collaboration.go`, `services/repository/repo_team.go`
- Audit patterns:
  - `models/audit/action.go`
  - `services/enterprisewecom/audit_test.go`
- Locale/template conventions:
  - Edit English locale only at `options/locale/locale_en-US.json`.
  - Admin UI uses existing server-rendered admin layout, menu page-state flags, tables, attached segments, and `tw-*` utilities where custom spacing is needed.

### Enterprise WeCom administrator authority contract verification

- Administrator-list API: `POST /cgi-bin/service/get_admin_list?suite_access_token=SUITE_ACCESS_TOKEN`.
  - Request identifies `auth_corpid` and `agentid`.
  - Response includes `admin[]`, with `userid`, optional/mode-dependent `open_userid`, and `auth_type`.
  - `auth_type=1` is management authority; `auth_type=0` is message permission and must not grant protected Gitea root authority.
- Administrator-change callback: event `change_app_admin`.
  - The callback notifies that application administrator/owner authority changed.
  - Implementation must validate/decrypt the callback through existing callback trust boundaries, mark authority stale, and then call the administrator-list API; callback payload alone is not the final authority source.
- Self-built app fallback: `GET /cgi-bin/tag/list` locates the configured Enterprise WeCom contact tag `超管`, then `GET /cgi-bin/tag/get` supplies explicit `userlist[]` members that are treated as management-authority users for this Gitea instance.
  - The tag is maintained in Enterprise WeCom, not in local Gitea config as a user list.
  - `partylist[]` is not expanded for super-admin authority to avoid broad department-level root grants.
- This implementation must not use a local username, local user ID, environment variable, or manually configured WeCom `userid` override to pick the protected super administrator.

### Enterprise WeCom department/member/tag contract verification

- Department detail: `GET /cgi-bin/department/get` returns `department.department_leader[]`; these values may derive generated team administrators for department-generated teams.
- Department member detail: `GET /cgi-bin/user/list` returns user `department[]` and `is_leader_in_dept[]`; the arrays must be interpreted by position and only when scoped to the department that generated the Gitea team.
- Gitea's current `team_user` model has no per-member administrator column. Generated team administrators are therefore reconciled as WeCom-derived admin state plus managed membership in the generated team; implementation must not grant broad Owners-team or whole-team owner permission as a local substitute.
- Tag member API: `GET /cgi-bin/tag/get` returns `userlist[]` and `partylist[]`.
  - Tag membership can generate team membership.
  - Tag API alone does not provide a team-administrator signal, so tag-generated teams remain unresolved for admin derivation unless another supported WeCom-derived source supplies leadership metadata.

### Manual mapping inventory and conversion boundary

- Existing API exposes manual CRUD plus dry-run/apply:
  - `GET /api/v1/enterprise/wecom/mappings`
  - `POST /api/v1/enterprise/wecom/mappings`
  - `PATCH/DELETE /api/v1/enterprise/wecom/mappings/{id}`
  - `POST /api/v1/enterprise/wecom/mappings/dry-run`
  - `POST /api/v1/enterprise/wecom/mappings/apply`
- Normal product workflow must reject/hide manual create/update/disable/apply. Service-level planning helpers may remain internal for tests and the scheduled actor, but Web/admin UI must be read-only generated automation state.

### User mutation entry points that need protected-admin guard

- Web admin:
  - user edit/rename, delete/purge, impersonation, avatar update/delete, access token panel/delete, organization membership removal, and email activation/deletion.
  - 2FA/bot-token panels must be guarded where present in the current admin template/handler version.
- API admin:
  - update/rename/delete user, create/delete user public keys, badge mutation, organization membership mutation, and any admin-only credential/account mutation path for another user.
- Self operations:
  - Non-destructive self-updates by a protected administrator should keep existing Gitea behavior.
  - Self-delete, self-purge, self-deactivation, self-prohibit-login, and self-demotion must be rejected.

### Organization/repository/team governance entry points

- Organization creation: Web, API, service, and admin API creation paths must allow only the Enterprise WeCom-derived system super administrator; ordinary users and ordinary site administrators are denied even when local Gitea org-creation flags would otherwise allow creation.
- Repository creation: Web, user API, org API, admin API, migration/push-create paths must default/force governed repositories to Private and enforce personal quota/org approval policy.
- Repository transfer and visibility update paths must not create a non-private or bypassed governed state.
- Repository authorization grants: collaborator add/update/delete, repository team add/delete/update, and org-team repository grant/revoke paths need creator/owner/super-admin guard.
- Team governance: Web/API team create/delete/rename, membership edits, repo grants, and team-admin-equivalent updates must reject local maintenance for WeCom-managed teams outside the internal scheduled reconciliation actor.

### Static prototype confirmation

- Updated prototype: `openspec/changes/enterprise-wecom-admin-ui-super-admin/prototypes/wecom-admin-ui.html`.
- The prototype is inside a Gitea-like site-admin frame with top header, left admin nav, attached headers/segments, labels, tabs, tables, role-switch views, and audit/status links.
- It shows scheduled sync status, next run, last outcome, generated mappings, generated teams, WeCom-derived team administrator state, reconciliation summaries, WeCom authority snapshot, protected administrator state, single-org state, org repo request queue, personal private repo quota, repository authorization guard, protected-account audit feedback, and permission visibility.
- It intentionally contains no manual mapping create/edit/disable, no manual dry-run, and no manual apply controls.
- Permission visibility covers ordinary/non-admin users, ordinary local site administrators without WeCom management authority, ordinary members, repository creators, owner-level repository users, WeCom-protected management administrators, and system/API-only scheduled capabilities.
- Production UI is not implemented yet; any intentional differences from this prototype will be recorded when implementing tasks 10.x.

## Production UI notes

- The production UI is implemented as server-rendered Gitea admin pages under `/-/admin/enterprise/wecom*` and uses the existing admin layout, navbar, attached headers, segments, secondary pointing tabs, and tables rather than the richer static prototype styling.
- The prototype's role-switch panels are not shipped as product controls. Production permission visibility is enforced by routes and templates: non-admin users and ordinary local site admins without WeCom management authority receive 403 and do not see the admin backend entry; Enterprise WeCom-derived system super administrators see the read-only status pages and organization-repository approval buttons.
- The prototype's manual-looking status actions are intentionally omitted in production. Generated mapping/team/team-admin state remains read-only; no mapping create/edit/disable, dry-run, manual apply, or local team-admin maintenance controls are exposed.
- The production UI includes an admin audit-log link filtered to the `enterprise:wecom` action family instead of embedding a full audit timeline in the Enterprise WeCom status page.

## Migration judgment

- DB/modelmigration is required for WeCom administrator snapshots, generated mapping/team/run state, organization repository requests, and repository creator/governance metadata.
- OpenFGA migration is not required for this repository/change.
- Keycloak migration is not required for this repository/change.
- Swagger regeneration is required only if public API contracts are added/changed or existing generated Swagger is intentionally updated.
