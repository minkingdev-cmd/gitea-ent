## 1. Baseline, WeCom authority contract, and automation inventory

- [x] 1.1 Run `make help` and inspect current admin Web/API route patterns, Enterprise WeCom sync service, mapping/reconciliation service, cron task patterns, user mutation services, organization creation paths, repository creation paths, repository collaborator/team authorization paths, admin templates, locale conventions, callback patterns, and audit action patterns before editing product code.
- [x] 1.2 Verify the supported Enterprise WeCom administrator-authority API and administrator-change callback contract for the configured app mode, including response fields such as `userid`, `open_userid`, and permission classification such as `auth_type`.
- [x] 1.3 Verify the Enterprise WeCom department, member-detail, and tag APIs that will feed generated teams, membership, and team administrators, including fields such as `department_leader`, `department`, `is_leader_in_dept`, `userlist`, and `partylist`.
- [x] 1.4 Inventory existing manual mapping API/service/UI work and identify what must be removed, hidden, rejected, or converted to generated automation state so site admins do not maintain mapping records manually.
- [x] 1.5 Enumerate all Web admin and admin API entry points that can mutate, impersonate, or manage another user, including user edit/delete/rename, impersonation, avatar, 2FA, email, SSH key, token, badge, and organization membership routes.
- [x] 1.6 Enumerate organization creation, repository creation, repository transfer, visibility update, collaborator grant, team grant, team creation/deletion/rename, team membership, team administrator, and access-mode update entry points that must be governed.
- [x] 1.7 Confirm implementation will not use a local username, local user ID, environment variable, or manual WeCom `userid` override to select the protected super administrator.

## 2. Gitea-framed read-only UI prototype for review

- [x] 2.1 Update the static prototype under `openspec/changes/enterprise-wecom-admin-ui-super-admin/prototypes/` before product UI implementation.
- [x] 2.2 Prototype scheduled sync status, next run, last run outcome, generated mapping/team list, WeCom-derived team administrator status, reconciliation summary, WeCom authority sync status, protected administrator status, organization creation governance status, organization repository request queue, personal repository quota behavior, repository grant guard, and protected-account audit feedback inside a Gitea-like admin frame using existing navigation/table/form conventions.
- [x] 2.3 Do not include manual mapping create/edit/disable, manual dry-run, or manual apply controls in the prototype.
- [x] 2.4 Show permission visibility in the prototype for non-admin users, ordinary members, ordinary site administrators, repository creators, repository owner-level users, WeCom-protected management administrators, and system/API-only capabilities.
- [x] 2.5 Record in implementation notes or final summary when production UI intentionally differs from the prototype.

## 3. WeCom authority, generated mapping, and run-history state

- [x] 3.1 Add additive model(s) for persisted WeCom administrator-authority snapshots, including corp/app identity, WeCom user identity, permission classification, active state, refresh metadata, and timestamps.
- [x] 3.2 Add additive model(s) for generated mapping/team state, WeCom-derived team administrator state, unresolved team-admin diagnostics, and scheduled reconciliation run history, including derivation rule, source, target, status, skip/error reason, run ID, trigger, counts, and timestamps.
- [x] 3.3 Add explicit `modelmigration` entries and migration tests proving existing users, SSH keys, PATs, Git HTTP tokens, WeCom identity rows, org users, team users, manual memberships, and prior mapping-managed memberships are not mutated by migration.
- [x] 3.4 Implement a WeCom admin-authority client/provider that calls the supported administrator-list API and normalizes authority classifications into management vs non-management local decisions.
- [x] 3.5 Implement snapshot refresh semantics: successful complete refresh activates current returned admins and marks missing prior rows inactive; failed refresh does not clear the previous snapshot.
- [x] 3.6 Implement generated mapping and generated team derivation from synchronized WeCom departments/tags/users and deterministic Gitea naming/policy rules.
- [x] 3.7 Implement generated team administrator derivation from WeCom API leadership/management metadata, including department detail `department_leader` and member-detail `is_leader_in_dept` fields where available.
- [x] 3.8 Ensure missing or ambiguous generated targets and sources without admin metadata are recorded as skipped/unresolved/errors and never result in broad fallback grants or local manual team admins.
- [x] 3.9 Implement Enterprise WeCom administrator-change callback handling that validates the callback, triggers authority refresh, and does not trust callback payload alone for final authority decisions.
- [x] 3.10 Add unit tests for API success, API failure preserving previous snapshot, callback-triggered refresh, message-only admin exclusion, management admin inclusion, multiple management admins, unsupported authority source behavior, generated target resolution, generated team/admin derivation, missing target skip, missing admin metadata unresolved, and ambiguous target skip.

## 4. Scheduled automation pipeline

- [x] 4.1 Wire the existing Enterprise WeCom directory sync cron task to run the full automation pipeline after a successful committed directory snapshot.
- [x] 4.2 Ensure scheduled runs refresh due/stale administrator authority, derive generated mappings and teams, derive team administrators, plan reconciliation, apply mapping/team-managed membership/admin changes, persist run results, and audit summary counts.
- [x] 4.3 Remove manual dry-run/apply as a normal product workflow; if service methods remain for tests, keep them internal and do not expose them through admin UI.
- [x] 4.4 Reject, disable, or hide legacy manual mapping create/update/disable/apply routes for normal operation if they remain reachable from prior work.
- [x] 4.5 Ensure failed sync, failed authority refresh, failed generated mapping derivation, or failed reconciliation does not commit partial authorization changes.
- [x] 4.6 Add scheduled pipeline tests for successful run, failed sync no mutation, failed authority refresh preserving previous snapshot, generated mapping/team skips, team admin reconciliation, idempotent repeated run, and stale generated membership/admin removal.

## 5. Protected administrator resolution and promotion

- [x] 5.1 Implement a resolver that joins active management-authority snapshot rows to active Enterprise WeCom identities and bound individual Gitea users.
- [x] 5.2 Ensure successful WeCom login for a management-authority user creates/binds the local user according to existing login rules and promotes the bound user to site admin idempotently after authority confirmation.
- [x] 5.3 Ensure scheduled sync and authority refresh re-evaluate protected administrators and promote active bound management-authority users to site admin without choosing a local fallback.
- [x] 5.4 Add self-check/admin warning data for unsupported authority API, stale refresh, unbound authority identity, inactive/out-of-scope identity, multiple equivalent management admins, and generated mapping failures without exposing sensitive WeCom data.
- [x] 5.5 Add service tests for disabled Enterprise WeCom, unsupported authority source, unbound authority rows, active bound management rows, authority removal, multiple management rows, and promotion idempotency.

## 6. Protected administrator guards

- [x] 6.1 Add a shared protected-user admin mutation guard with operation reason codes and safe denied-audit metadata.
- [x] 6.2 Apply the guard to Web admin user edit, rename, delete/purge, impersonation, avatar, 2FA reset, bot-token panels where applicable, and organization membership removal paths.
- [x] 6.3 Apply the guard to admin API user edit, rename, delete/purge, SSH public key creation/deletion, user badge mutation, and other enumerated user-management mutation paths.
- [x] 6.4 Apply equivalent protection to admin email activation/deletion paths when the target email belongs to a protected administrator.
- [x] 6.5 Keep non-destructive self-updates by a protected administrator available where existing Gitea self/admin behavior allows them, while rejecting self-delete, self-purge, self-deactivation, self-prohibit-login, and self-demotion.
- [x] 6.6 Add Web/API tests covering ordinary site admin 403/flash failure against protected users and protected administrator success for allowed non-destructive own-account updates.

## 7. WeCom-managed team governance

- [x] 7.1 Implement generated Gitea team creation/update under the managed organization target from WeCom department/tag API snapshots and deterministic policy.
- [x] 7.2 Implement generated team membership reconciliation from active bound WeCom department/tag members.
- [x] 7.3 Implement generated team administrator reconciliation from WeCom API leadership/management metadata, including department detail `department_leader` and member-detail `is_leader_in_dept` metadata where supported.
- [x] 7.4 Mark generated teams whose WeCom source lacks supported administrator metadata as unresolved/system-managed and surface this in status UI and audit without allowing local manual admin assignment.
- [x] 7.5 Reject local Web/API team creation/deletion/rename, membership edits, and team administrator edits for WeCom-managed teams outside the internal scheduled reconciliation actor.
- [x] 7.6 Add tests for generated department team, generated tag team, member add/remove, department leader admin grant/remove, source-without-admin-metadata unresolved, local team membership denial, local team admin denial, and local team deletion/rename denial.

## 8. Organization and repository creation governance

- [x] 8.1 Add an organization creation guard to service/Web/API/admin API paths: only the system super administrator can create organizations; ordinary users and ordinary site administrators are rejected.
- [x] 8.2 Add governance status reporting for organization count without auto-deleting organizations.
- [x] 8.3 Add model(s) and `modelmigration` for organization repository creation requests, approvals/rejections, and repository creator/governance metadata.
- [x] 8.4 Implement ordinary member organization repository request submission under an organization without creating a repository immediately.
- [x] 8.5 Implement system-super-admin-only approval/rejection; approval creates a Private organization repository, records requester as creator, grants requester owner-level/equivalent authority, links request to repository, and audits the outcome.
- [x] 8.6 Implement personal repository creation guard: own namespace only, Private visibility, no approval, and fewer than 10 personal repositories.
- [x] 8.7 Ensure governed repository creation paths force or reject to Private visibility and do not create Public/Internal repositories.
- [x] 8.8 Add tests for super-admin organization creation, ordinary org creation rejection, ordinary site-admin org creation rejection, admin API owner assignment by super admin, org repo request submit/approve/reject, non-super-admin approval rejection, personal repo under quota success, quota exceeded rejection, and private visibility enforcement.

## 9. Repository authorization governance

- [x] 9.1 Implement repository creator metadata read/write for personal repos, approved organization repos, and super-admin direct organization repo creation.
- [x] 9.2 Add a shared repository authorization guard allowing only recorded repository creator, owner-level repository permission holder, or system super administrator to grant/revoke/update repository access.
- [x] 9.3 Apply the guard to Web/API collaborator grant/revoke/update paths and organization team access grant/revoke/update paths where applicable.
- [x] 9.4 Ensure ordinary site-admin status alone is not sufficient to manage a repository's authorization unless the actor also satisfies creator, owner-level, or super-admin rules.
- [x] 9.5 Add tests for creator grant success, owner-level grant success, super-admin grant success, ordinary site admin denial, write/admin non-owner collaborator denial, and audit metadata for grant/revoke/denial.

## 10. Enterprise WeCom and repository governance admin UI

- [x] 10.1 Add server-rendered Web routes under the site admin group for Enterprise WeCom automation overview, generated mappings, generated teams/team administrators, reconciliation runs, authority snapshot status, organization creation governance status, and organization repository approval queue.
- [x] 10.2 Add templates under `templates/admin/enterprisewecom/` or another existing admin location using existing admin layout conventions and `tw-*` utilities where styling is needed.
- [x] 10.3 Add admin navigation entry and page-state flags for Enterprise WeCom automation and repository governance status under the existing admin navigation framework.
- [x] 10.4 Render schedule, next run, last run, generated mappings, run history, authority sync status, protected-admin warnings, single-org status, org repo requests, skipped/protected items, and audit links without exposing WeCom secrets or private profile data.
- [x] 10.5 Ensure the WeCom mapping UI is read-only for generated mapping state: no create/edit/disable mapping forms, no manual dry-run button, and no manual apply button.
- [x] 10.6 Ensure admin backend entry, Enterprise WeCom status pages, and org repo approval controls are visible only to the system super administrator; ordinary local site admins without WeCom management authority do not see the admin entry and receive 403 on direct admin URLs.
- [x] 10.7 Add English locale keys only in `options/locale/locale_en-US.json` for all new UI text and errors.

## 11. Audit, privacy, and documentation

- [x] 11.1 Add or reuse audit actions for scheduled sync start/finish, generated mapping derivation, automatic reconciliation apply, admin-authority refresh, callback-triggered refresh, promotion, unresolved outcomes, denied protected-user management attempts, organization creation denial, org repo request/approval/rejection, personal quota denial, repository visibility enforcement, and repository authorization grant/revoke/denial.
- [x] 11.2 Add tests proving audit metadata excludes corp secrets, suite tokens, access tokens, OAuth codes, raw callback URLs, phone numbers, and private profile fields.
- [x] 11.3 Update `docs/enterprise-authz/implementation-plan.md` with the scheduled automation scope, generated mapping rules, WeCom API/callback-derived admin authority source, super-admin-only organization creation policy, org repo approval flow, personal private repo quota, repository grant guard, read-only UI boundary, rollout, and rollback behavior.
- [x] 11.4 Record migration judgment in documentation: DB schema required for authority snapshots, run/generated mapping state, org repo requests, and repo creator/governance metadata; OpenFGA not required; Keycloak not required; Swagger only if API contracts changed.

## 12. Tests and compatibility verification

- [x] 12.1 Add Web integration tests for status UI non-admin rejection, ordinary site-admin admin-entry hiding/direct-URL rejection, system-super-admin generated mapping list visibility, generated team/team-admin list visibility, run history visibility, single-org status visibility, org repo approval visibility, and absence of manual mapping/team mutation controls.
- [x] 12.2 Add API or route integration tests proving manual mapping mutation routes are not exposed or are rejected for normal operation.
- [x] 12.3 Add API integration tests for protected administrator denial on edit, rename, delete/purge, key mutation, badge mutation, and allowed/denied self-operation boundaries.
- [x] 12.4 Add integration or service tests for WeCom admin-authority refresh, callback-triggered update, scheduled generated mapping apply, and skipped target reporting.
- [x] 12.5 Add integration tests for organization creation restriction, org repo request approval creation, personal private repo quota, private default visibility, and repository authorization guard behavior.
- [x] 12.6 Re-run existing Enterprise WeCom mapping API/service tests and update expectations from manual mapping to generated automation where needed.
- [x] 12.7 Re-run or extend regressions proving SSH key authentication remains unchanged for normal users and protected administrators.
- [x] 12.8 Re-run or extend regressions proving PAT/API token and Git HTTP token behavior remain unchanged for normal users and protected administrators.
- [x] 12.9 Re-run existing Enterprise WeCom login-only forbidden Web login path tests to confirm password, registration, OpenID, Passkey, reverse-proxy, SSPI, and non-WeCom OAuth Web login remain blocked.

## 13. Final verification

- [x] 13.1 Run `make fmt` after Go edits.
- [x] 13.2 Run targeted Go tests for changed setting, Enterprise WeCom model/service, cron, org, repo, user service, admin Web/API, audit, migration, and integration packages.
- [x] 13.3 Run `make lint-go` and fix causes rather than suppressing lints.
- [x] 13.4 Run `make lint-templates` if admin templates changed.
- [x] 13.5 Run `make generate-swagger` only if API request/response contracts changed.
- [x] 13.6 Run `openspec validate enterprise-wecom-admin-ui-super-admin --strict` before requesting implementation review.

## 14. Self-built app super-admin tag source

- [x] 14.1 Support the Enterprise WeCom contact tag `超管` as the self-built app super-admin authority source when suite/provider administrator APIs are unavailable.
- [x] 14.2 Verify and document WeCom department leader metadata fields `department_leader` and `is_leader_in_dept`.
