## Why

Enterprise WeCom authorization mapping should not require ongoing local maintenance. Operators need Gitea to periodically synchronize WeCom directory and administrator authority, automatically derive repository membership mappings, automatically apply safe changes, and expose only status, audit, and troubleshooting UI inside the existing Gitea admin framework.

## What Changes

- Replace manual WeCom mapping maintenance with an automated scheduled pipeline: WeCom directory sync, administrator-authority refresh, deterministic organization/team/member/admin derivation, reconciliation, apply, and audit.
- Do not provide site-admin create/update/disable mapping workflows, manual team/team-admin maintenance workflows, manual dry-run workflows, or manual apply workflows for normal operation.
- Add a Gitea-framed read-only admin UI for Enterprise WeCom automation status: schedule, next run, last run, authority snapshot, generated mappings, reconciliation result, skipped/protected items, and audit links.
- Add a reviewable static UI prototype before product UI implementation; the prototype must stay inside the existing Gitea admin layout/navigation model and show which permission level can see each entry and status.
- Introduce Enterprise WeCom administrator-authority synchronization through WeCom API/callback events, falling back in self-built app mode to the Enterprise WeCom contact tag named `超管`, rather than a local environment/config user selector.
- Resolve protected local administrator status from WeCom-reported administrator authority and the bound Enterprise WeCom `userid`; Gitea SHALL NOT accept a local username, local user ID, or manually configured WeCom user ID as the source of truth for the protected root identity.
- Keep Gitea users as the local subject for repos, teams, SSH keys, PATs, Git HTTP tokens, and audit ownership, while automatically ensuring users with WeCom management authority have site-admin authority and are protected from other administrators.
- Preserve existing SSH key, PAT/API token, Git HTTP token, and repository permission behavior; the new automation only changes scheduled membership reconciliation, protected account-management rules, organization/repository creation governance, and repository authorization guards.
- Generate and reconcile Gitea teams, team membership, and team administrators from Enterprise WeCom API snapshots; team administrators must come from WeCom-reported leadership/management metadata such as department leaders or department-member leader flags rather than local Gitea maintenance.
- Restrict organization creation to the Enterprise WeCom-derived system super administrator; ordinary users and ordinary site administrators cannot create organizations.
- Route ordinary users' organization repository creation through a super-admin approval workflow; approved requests create private repositories in the requested organization.
- Allow ordinary users to create private personal repositories without approval up to 10 personal repositories per user; creation beyond the quota is forbidden.
- Force repository creation defaults to Private and restrict repository authorization changes to the repository creator, users with owner-level repository permission, or the system super administrator.

## Capabilities

### New Capabilities
- `identity/wecom-admin-ui-super-admin`: Gitea-framed status UI for scheduled Enterprise WeCom authorization automation plus WeCom API/callback-derived protected administrator behavior.
- `repository/single-org-repo-governance`: Super-admin-only organization creation policy, organization repository approval workflow, personal private repository quota, private-by-default repository creation, and repository authorization guards.
- `organization/wecom-team-governance`: Enterprise WeCom API-derived Gitea team generation, membership reconciliation, team administrator derivation, and local team-maintenance restrictions.

### Modified Capabilities
- `identity/wecom-web-login`: Enterprise WeCom identity binding and directory sync also consume WeCom administrator authority snapshots to identify protected local administrator users and keep local site-admin status aligned with WeCom-reported authority.

## Impact

- Web UI/routes/templates under the existing site admin area, admin navigation, and English locale entries for read-only status/troubleshooting pages.
- UI prototype artifact under this OpenSpec change for visual review before implementation, explicitly aligned to existing Gitea admin layout rather than a standalone dashboard.
- Enterprise WeCom service/model areas for scheduled sync orchestration, generated mapping derivation, admin authority API calls, callback-triggered refresh, persisted authority snapshots, reconciliation run history, protected administrator resolution, and audit.
- Existing manual mapping API/UI scope must be removed, hidden, or converted to internal automation/status behavior so local admins are not asked to maintain mapping records.
- Admin user Web routes and admin user APIs that mutate or impersonate a target user.
- Organization creation Web/API routes, repository creation Web/API routes, organization repository request/approval UI and services, repository collaboration/team authorization routes, organization team management routes, team membership/admin routes, and repository visibility handling.
- Tests for scheduled automation, generated mapping/team behavior, UI visibility, Web/API 403 protections, WeCom authority refresh, callback-triggered update, protected-admin resolution, WeCom-derived team admin reconciliation, local team-maintenance denial, super-admin-only organization creation, repository request approval, personal quota enforcement, private visibility defaults, repository authorization guard behavior, audit metadata, and compatibility regressions for SSH/PAT/Git HTTP token paths.
- DB/modelmigration is expected for persisted WeCom administrator-authority snapshots, scheduled reconciliation run/generated mapping/team state, WeCom-derived team admin state, organization repository creation requests, and repository creator/governance metadata; OpenFGA and Keycloak migrations are not required for this repository.
