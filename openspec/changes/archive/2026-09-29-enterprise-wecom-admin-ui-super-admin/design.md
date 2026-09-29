## Context

See `proposal.md` for motivation. The current Enterprise WeCom work already provides login-only Web authentication, directory sync, API-only authorization mappings, managed membership reconciliation, and audit events. Earlier planning described manual mapping CRUD and manual dry-run/apply UI, but the desired operating model is now fully automated: Gitea periodically synchronizes WeCom, derives mappings, applies them, and shows status only.

The existing admin UI is server-rendered under `/-/admin`. When Enterprise WeCom governance is enabled, admin panel access is additionally gated by active Enterprise WeCom management authority resolved to the signed-in local account, so local Gitea site-admin status alone is not enough to see or open admin backend URLs. Gitea users remain the local subject for repository permissions, teams, SSH keys, PATs, Git HTTP tokens, and audit ownership.

Enterprise WeCom documentation describes an application-admin change callback (`change_app_admin`) that notifies the service provider to refresh authorization by calling the administrator-list API; the administrator-list API returns administrator entries including `userid` and an `auth_type` permission classification. For self-built app deployments where that service-provider authority API is unavailable, this change uses the Enterprise WeCom contact tag named `超管` as the configured remote authority source by resolving it through `tag/list` and `tag/get`. It does not introduce a local super-admin user selector.

## Goals / Non-Goals

**Goals:**

- Run Enterprise WeCom directory sync and authorization reconciliation on a schedule without requiring manual mapping maintenance.
- Automatically derive mappings, Gitea teams, team membership, and team administrators from WeCom directory/authority data and deterministic Gitea naming/policy rules.
- Automatically apply generated mapping reconciliation after successful scheduled sync.
- Provide a Gitea-framed read-only UI for status, generated mappings, reconciliation history, skipped/protected items, and audit links to the Enterprise WeCom-derived system super administrator.
- Provide a static UI prototype for visual review before product template implementation.
- Automatically derive protected administrator status from Enterprise WeCom callback/API authority or the configured Enterprise WeCom `超管` contact tag in self-built app mode, not from a local environment variable or local config naming a user.
- Protect resolved local WeCom management administrators from other users across Web admin and admin API mutation paths.
- Preserve SSH key, PAT/API token, Git HTTP token, and native repository permission behavior.
- Restrict organization creation to the Enterprise WeCom-derived system super administrator and forbid organization creation by ordinary users or ordinary site administrators.
- Route organization repository creation through a super-admin approval workflow for ordinary users.
- Allow private personal repositories without approval up to 10 per user.
- Ensure all repository creation paths default to Private and repository authorization changes are restricted to the creator, owner-level users, or the system super administrator.

**Non-Goals:**

- Do not provide manual mapping create/update/disable workflows for ordinary operation.
- Do not provide local Gitea team creation, team membership, or team administrator maintenance for WeCom-managed teams.
- Do not provide a manual apply button as the normal authorization-change path.
- Do not implement a new general role/permission engine or OpenFGA/Keycloak integration.
- Do not replace Gitea `User.IsAdmin` with a manually edited local super-admin database role.
- Do not make Enterprise WeCom OAuth part of SSH/PAT/Git HTTP token authentication.
- Do not add org/repo-scoped WeCom mapping edit UI in this phase.
- Do not allow ordinary users or ordinary site administrators to create organizations or directly create organization repositories without super-admin approval.
- Do not make public/internal repository visibility a user-selectable default in governed creation flows.
- Do not allow any local username, local user ID, or configured WeCom `userid` to override WeCom API/callback-reported administrator authority.

## Decisions

### 1. Use a scheduled automation pipeline, not manual mapping maintenance

Enterprise WeCom authorization changes should flow through one scheduled pipeline:

```text
cron.sync_enterprise_wecom_directory
  -> fetch WeCom directory snapshot
  -> refresh WeCom administrator authority when due/stale
  -> derive generated authorization mappings
  -> plan reconciliation
  -> apply mapping-managed membership changes
  -> persist run result and audit summary
```

The UI shows status and history for this pipeline. It does not ask site admins to create mapping rows, run dry-run, or click apply for normal operation.

Rationale:

- The desired source of truth is Enterprise WeCom, not a manually maintained local mapping table.
- Scheduled reconciliation reduces drift and avoids a human handoff between sync and apply.
- A single pipeline makes failure handling and audit easier to reason about.

Alternatives considered:

- Keep manual mapping CRUD with an optional auto-apply switch: rejected because it still creates a local maintenance process.
- Keep manual dry-run/apply buttons: rejected for normal operation because scheduled sync must be responsible for applying authorization. Implementation may keep test-only service methods, but product UI should not expose them as an operational workflow.

### 2. Derive mappings deterministically from WeCom data and Gitea policy

Generated mappings should be derived rather than hand-authored. The derivation policy should be deterministic and auditable. Recommended initial rules:

- WeCom departments under a configured sync root map to Gitea organizations and teams by normalized path/name convention.
- WeCom tags map to predefined capability teams by normalized tag key convention.
- WeCom management-authority users map to protected local site administrators after identity binding.
- Missing Gitea targets are reported as skipped/errors according to rollout policy; auto-create behavior, if implemented, must be explicit and audited.

Persist generated mapping/run state separately from manual mapping intent, for example with `wecom_generated_authz_mapping` and `wecom_authz_reconcile_run`, or by extending existing mapping tables with a non-editable `managed_by=auto`/generation metadata if that is safer for the current code. The important behavior is that local admins do not maintain mapping records by hand.

Rationale:

- Deterministic rules make the system explainable and testable.
- Persisted generated state lets UI explain what happened without allowing mutation.
- Reporting missing targets is safer than silently granting broad access.

Alternatives considered:

- Directly mutate teams from raw WeCom data without generated mapping state: rejected because operators need observability and audit trails.
- Let admins fix generated mappings one-by-one in UI: rejected because it reintroduces manual maintenance.


### 3. Derive teams and team administrators from WeCom API snapshots

Gitea teams under the managed organization target are generated from WeCom API snapshots and deterministic policy:

- WeCom departments generate organization teams by normalized department path/name convention.
- WeCom department membership generates Gitea team membership.
- WeCom department leadership metadata from department detail snapshots, such as `department_leader`, and member detail snapshots, such as `is_leader_in_dept` aligned with the returned `department` array, generates Gitea team administrator/owner-level team role where Gitea's team model supports it.
- WeCom tags may generate capability teams and membership from tag-member API snapshots such as `userlist` and `partylist`.
- Tag APIs do not provide a team-administrator signal by themselves; a tag-generated team receives a generated administrator only when another supported WeCom API source or deterministic WeCom-derived policy supplies leadership/management metadata for that same generated team.
- If a WeCom source can generate a team but the API snapshot does not provide an administrator/leader signal for that source, the generated team admin state is marked unresolved/system-managed in status UI and audit. The system must not let admins fill in a local team admin manually as a substitute for missing WeCom metadata.

Local team maintenance restrictions:

- For WeCom-managed teams, local Web/API routes must reject manual team creation, deletion, rename, membership edits, and team administrator changes unless the operation is an internal scheduled reconciliation action.
- Operators should fix team structure, membership, and leadership in Enterprise WeCom or in deterministic policy configuration, not in Gitea.
- Existing unmanaged Gitea teams, if any, should remain outside this automation only when explicitly classified as unmanaged; they must not be used to bypass WeCom-derived authorization.

Rationale:

- Team structure and team administrators are part of the corporate directory authority model.
- Using WeCom leadership fields keeps Gitea team administration aligned with corporate hierarchy.
- Reporting unresolved admin metadata is safer than inventing local team admins.

### 4. Use WeCom API/callback or WeCom tag authority snapshots, not a local user selector

Implement an Enterprise WeCom admin-authority provider that can:

- receive WeCom administrator-change callbacks and mark the admin-authority snapshot stale;
- call the supported WeCom administrator-list API for the configured app/corp;
- for self-built app deployments without a suite/provider administrator-list token, resolve the Enterprise WeCom contact tag configured by `SUPER_ADMIN_TAG_NAME` (default `超管`) and treat its explicit `userlist` members as management-authority users;
- persist the returned `userid`, `open_userid` when present, permission classification such as `auth_type`, active state, and refresh metadata;
- classify which WeCom users have root-management authority for Gitea.

`auth_type=1` represents management authority for the application; `auth_type=0` represents message permission and is not enough for Gitea root authority. In tag-source mode, only explicit members returned in the `超管` tag's `userlist` are treated as management authority; `partylist` departments are not expanded into super administrators. If a future approved WeCom endpoint exposes a more precise enterprise-super-admin role, add it behind the same provider and prefer the more precise role.

If the configured WeCom app mode cannot enumerate administrator authority through an approved callback/API path or the configured WeCom tag source, the system reports authority as unresolved/unsupported and grants no protected-super-admin fallback. It must not ask operators to fill in a local super-admin user variable.

### 5. Persist automation snapshots and run history explicitly

Add additive model migrations for:

- WeCom administrator-authority snapshots.
- Generated mapping/team state or generated mapping run items.
- WeCom-derived team administrator state and unresolved team-admin diagnostics.
- Reconciliation run history with outcome, counts, schedule trigger, and safe reason codes.

Refresh semantics:

- Successful complete directory sync and authority refresh update generated state and apply reconciliation.
- Failed sync/refresh does not clear previous valid authority or generated mapping state.
- Reconciliation failures must not commit partial authorization changes for the selected run.

### 6. Resolve protection dynamically and promote site-admin status idempotently

The resolver returns protected Gitea user IDs by joining active administrator-authority rows to active Enterprise WeCom identities for the same `corp_id` and `userid`, then loading individual Gitea users.

On successful WeCom login, directory sync, or admin-authority refresh for a management-authority identity, ensure the bound user has `IsAdmin=true`. Do not persist a manually editable local protected flag; protection is derived from the current WeCom authority snapshot and identity binding.

If an authority row is not yet bound to a Gitea user, no local fallback becomes protected. Admin dashboard/self-check should show a non-sensitive warning so operators know the WeCom administrator has not logged in or bound yet.

### 7. Centralize protected-user management checks

Add a reusable guard for admin mutation paths, conceptually:

```text
CanManageUserFromAdmin(actor, target, operation) -> allow/deny(reason)
```

The guard denies when `target` is currently protected by WeCom management authority and `actor` is missing or is not that same protected user. For destructive self-actions, it also denies when `actor == target` and the operation would delete, purge, deactivate, prohibit login, or demote site-admin authority.

Apply this guard before mutation in Web admin and admin API handlers that can affect the protected account.

### 8. Build and review a Gitea-framed read-only UI prototype before product templates

Create a static prototype under `openspec/changes/enterprise-wecom-admin-ui-super-admin/prototypes/`. The prototype must mirror the existing Gitea admin frame: top header, left admin navigation, `admin-setting-content`, attached headers/segments, basic tables, small buttons/links, labels, and flash/alert messaging. It must not introduce a detached “control center” aesthetic that cannot be mapped to current templates.

The prototype should show:

- scheduled sync status, next run, last run, and last outcome;
- WeCom authority sync status and currently protected administrator(s);
- generated mapping/team list with derivation source, target status, and WeCom-derived team admin status;
- reconciliation result summaries from the last scheduled run;
- protected-account management lockout messaging and audit trail;
- permission visibility states for non-admin, ordinary local site admin without WeCom management authority, WeCom-protected management admin, and system job/API-only capabilities.

The prototype is not product code and does not replace implementation tests. It exists so UI placement, visibility, and information hierarchy can be reviewed before wiring server-rendered templates.

### 9. Build status UI as server-rendered admin pages

Add Web routes under the existing admin group, for example:

```text
GET /-/admin/enterprise/wecom
GET /-/admin/enterprise/wecom/generated-mappings
GET /-/admin/enterprise/wecom/generated-teams
GET /-/admin/enterprise/wecom/reconciliation-runs
GET /-/admin/enterprise/wecom/authority
```

Handlers call Enterprise WeCom services directly and render read-only state. Under Enterprise WeCom governance, the shared admin middleware must deny direct `/-/admin*` URL access unless the signed-in user resolves to an active WeCom management-authority identity. Locale changes go only to `options/locale/locale_en-US.json`.


### 10. Restrict organization creation to the system super administrator

Add an organization creation guard to all Web/API/service paths that can create organizations. Behavior:

- Only the system super administrator derived from Enterprise WeCom management authority can create organizations.
- Ordinary users and ordinary site administrators who are not the system super administrator are rejected even if Gitea's local `AllowCreateOrganization` flag or site-admin status would otherwise allow creation.
- Existing organizations are not deleted or auto-repaired. Multiple organizations may exist, but future organization creation remains restricted to the system super administrator.

Rationale: organization lifecycle control belongs to the Enterprise WeCom root authority, while repository creation inside organizations remains governed separately through direct super-admin creation or approval workflows.

### 11. Add organization repository request and super-admin approval flow

Ordinary signed-in members cannot directly create repositories under an organization. They submit an organization repository request containing at least repository name, description, requested owner organization, intended collaborators/teams if any, and reason. The request flow is available even before the requester is a local Gitea member of the target organization; local organization membership or owner-team permission is not required to ask for a repository. After submission, the user is redirected to an existing Gitea-framed user settings page that lists their own organization repository requests and decision status so the flow is not mistaken for an invisible repository. Only the system super administrator can approve or reject.

On approval, the system creates a Private repository in the requested organization, records the requester as repository creator, grants the requester owner-level repository permission or equivalent existing Gitea permission, writes audit metadata, and links the request to the created repository. On rejection, no repository is created and the reason is audited.

Super administrators may create organization repositories directly, but the direct path must still create Private repositories and record creator/governance metadata.

### 12. Allow quota-limited personal private repositories

Ordinary members may create repositories in their personal namespace without approval when all conditions hold:

- The repository is Private.
- The user owns fewer than 10 personal repositories at creation time.
- The repository is created under the user's own namespace, not the organization.

The quota counts non-deleted personal repositories owned by the user, including archived repositories and forks unless implementation finds an existing Gitea convention that must be preserved and documents it. Organization repositories do not count against this personal quota.

### 13. Restrict repository authorization changes

Repository authorization changes include adding/removing collaborators, changing collaborator access mode, and adding/removing team access where applicable. The actor may perform these changes only when at least one condition is true:

- actor is the recorded repository creator;
- actor has owner-level permission on the repository according to existing Gitea permission loading;
- actor is the system super administrator derived from WeCom management authority.

Ordinary site-admin status alone is not enough to manage another repository's authorization when the actor is not also the system super administrator. This keeps repository grants tied to the creator/owner/super-admin model requested by policy.

### 14. Permission matrix

| Entry/API | Backend guard | External auth model | Default authorized role | Frontend entry key |
| --- | --- | --- | --- | --- |
| scheduled WeCom sync/reconcile | system cron/job context | Enterprise WeCom directory + authority API | System job | No manual UI |
| WeCom admin-authority refresh callback | WeCom callback verification + system job context | Enterprise WeCom admin-list API / admin-change callback | System job | Status only |
| `/-/admin*` admin backend entry and direct URLs | Admin-required Web middleware plus Enterprise WeCom super-admin access guard | Active WeCom management-authority snapshot joined to active bound identity | System super admin | Avatar menu admin panel entry only for super admin |
| `/-/admin/enterprise/wecom*` status pages | Admin-required Web middleware plus Enterprise WeCom super-admin access guard | Active WeCom management-authority snapshot joined to active bound identity | System super admin, read-only status | Admin nav: Enterprise WeCom |
| generated mapping list/status | Enterprise WeCom super-admin access guard | WeCom-derived generated mapping snapshots | System super admin, read-only | Read-only status table |
| generated team/team-admin list/status | Enterprise WeCom super-admin access guard | WeCom department/tag API snapshots and leadership metadata | System super admin, read-only | Read-only status table |
| manual team creation/membership/admin maintenance for WeCom-managed teams | Internal reconciliation guard; reject Web/API manual mutation | WeCom API is source of truth | None for normal operation | None |
| organization creation | Enterprise WeCom super-admin guard | WeCom-derived system super admin | System super admin | Existing org creation entries for super admin only |
| organization repository request creation/tracking | signed-in user + organization target exists; local org membership not required | Existing Gitea user identity | Ordinary member | User/org repo request form and user settings request list |
| organization repository request approval/rejection | super-admin guard | WeCom-derived system super admin | System super admin | Admin approval queue |
| personal repository creation | signed-in user + personal namespace + private visibility + quota guard | Existing Gitea user identity | Ordinary member under quota | Existing new repo form, personal owner only |
| repository visibility on creation | creation service forces Private | N/A | All creators | Visibility fixed/hidden as Private |
| repository authorization grant/revoke | repo creator OR owner-level permission OR super-admin guard | Existing Gitea repo permission + governance creator metadata | Repo creator, repo owner-level user, or system super admin | Repo collaborators/team settings |
| manual WeCom mapping create/update/disable/apply | Not exposed; reject or hide if legacy route remains | N/A | None for normal operation | None |
| Web admin user mutation routes targeting protected admin | Admin-required Web middleware plus Enterprise WeCom super-admin access guard plus protected-user guard | Active WeCom admin-authority snapshot | Protected target user only for non-destructive own-account updates; nobody for destructive self-removal | Existing admin user pages hidden from non-super admins |
| `/api/v1/admin/users/{username}*` mutation routes targeting protected admin | Admin API guard plus Enterprise WeCom super-admin access guard plus protected-user guard | Active WeCom admin-authority snapshot | Protected target user only for non-destructive own-account updates; nobody for destructive self-removal | API-only |

No OpenFGA relation/scope/role or Keycloak role changes are used in this repository for this feature.

### 15. Audit and privacy

Add audit action names for scheduled sync, generated mapping derivation, reconciliation apply, admin-authority refresh, protected-admin resolution, and denied management attempts. Metadata should include operation class, actor/system identity, target user ID when applicable, WeCom authority reason code, outcome, counts, schedule trigger, and refresh status. It must not include corp secrets, suite tokens, access tokens, OAuth codes, raw callback URLs, phone numbers, or private profile fields.

## Risks / Trade-offs

- **WeCom directory structure does not match Gitea org/team naming** → Report generated mapping skips/errors in status UI and audit; do not silently grant broad access.
- **Scheduled apply changes too much after a bad WeCom snapshot** → Apply only after complete committed sync; fail closed on reconciliation planner errors; preserve manual memberships unless explicitly mapping-managed.
- **Missed callback** → Scheduled authority refresh still runs; callback only reduces latency.
- **Operators want one-off fixes** → Prefer fixing WeCom source data or deterministic naming/policy rules; do not add local per-mapping edits.
- **Route-level guard misses a mutation path** → Enumerate Web/API admin user mutation routes in tasks and add negative tests.
- **Old protected user remains a normal site admin after WeCom authority changes** → This avoids accidental lockout; operators can remove normal admin status explicitly after the account is no longer protected.

## Migration Plan

- **DB schema/data:** Required. Add explicit `modelmigration` entries for WeCom administrator-authority snapshots, scheduled/generated reconciliation state, WeCom-generated team/team-admin state, organization repository requests, repository creator/governance metadata, and any approval/run history needed for audit. Add migration tests proving existing users, SSH keys, PATs, Git HTTP tokens, WeCom identity rows, org users, team users, repositories, collaborators, and existing Gitea memberships are not mutated by migration.
- **OpenFGA:** Not required.
- **Keycloak:** Not required.
- **Swagger:** Regenerate Swagger only if API request/response contracts are changed; the admin UI is server-rendered read-only status.
- **Locale/UI:** Add English locale keys only in `options/locale/locale_en-US.json`.
- **Prototype:** Keep `prototypes/wecom-admin-ui.html` in the change directory for review; it is not shipped product code.
- **Rollout:** Deploy migration and code, verify scheduled cron configuration, verify WeCom callback configuration, let scheduled sync produce generated mappings, verify status UI and audit, and verify protected-account mutations are denied.
- **Rollback:** Disable scheduled WeCom automation if a rollback switch is added, or disable the cron/callback route. Existing `IsAdmin` status and Gitea memberships remain ordinary Gitea state and can be managed after automated protection is inactive.
