## Context

See `proposal.md` for motivation. The current codebase already has Enterprise WeCom Web login, `wecom_identity`, `wecom_department`, `wecom_tag`, `wecom_membership`, explicit `modelmigration` entries, cron-driven directory sync, audit events, and tests proving SSH/PAT/Git HTTP token behavior is unchanged.

The next layer must remain additive: synchronized WeCom directory data becomes inputs for Gitea organization/team membership, but Gitea users remain the local subject for repository permissions, audit, SSH keys, PATs, and Git HTTP tokens. This design avoids introducing OpenFGA, Keycloak, or an external PDP.

## Goals / Non-Goals

**Goals:**

- Add explicit, auditable mappings from WeCom user/department/tag subjects to Gitea org/team membership.
- Reconcile mappings idempotently with dry-run support.
- Safely remove stale mapping-managed memberships without deleting manually managed memberships.
- Integrate optional post-directory-sync reconciliation without applying failed or partial snapshots.
- Expose site-admin-only management/apply API boundaries and keep front-end UI out of this phase.
- Keep repository permissions, SSH, PAT/API token, and Git HTTP token authentication on existing Gitea paths.

**Non-Goals:**

- No enterprise role definition, repo action evaluator, feature grant, merge gate, sensitive path enforcement, or default governance template.
- No replacement of Gitea teams with WeCom groups.
- No automatic deletion of Gitea users, SSH keys, PATs, Git HTTP tokens, repositories, or manually managed memberships.
- No organization/repository settings UI in this phase; API and service behavior are sufficient.

## Decisions

### 1. Store mapping definitions and managed membership state separately

Add two explicit `modelmigration` tables:

- `enterprise_wecom_authz_mapping`
  - `corp_id`
  - `source_type`: `user`, `department`, `tag`
  - `source_id`: WeCom userid, department ID, or tag ID as a string
  - `target_type`: `org` or `team`
  - `org_id`
  - `team_id` nullable for org targets
  - `is_active`
  - `created_by`, `created_unix`, `updated_unix`
- `enterprise_wecom_managed_membership`
  - `mapping_id`
  - `user_id`
  - `org_id`
  - `team_id` nullable for org targets
  - `target_type`: `org` or `team`
  - `last_apply_unix`
  - `last_seen_apply_id`
  - uniqueness over `mapping_id + user_id + target_type + org_id + team_id`

Rationale: mapping definitions answer “what should be applied”; managed membership state answers “what this integration is allowed to remove.” This prevents stale WeCom data from deleting manually added team members.

Alternatives considered:

- Add columns to `team_user` / `org_user`: rejected because it deepens the fork in core organization models.
- Recompute removals without state: rejected because the system cannot distinguish manually added membership from mapping-created membership.

### 2. Reconciliation uses existing Gitea membership services

Team targets use existing org/team membership behavior so access recalculation, watches, subscriptions, audit side effects, and consistency checks stay aligned with Gitea. Org targets add organization membership only and do not grant repository access unless existing Gitea permissions already do so.

Removal is conservative:

- Remove only memberships that have a matching managed-membership row and no remaining active mapping still requiring the same membership.
- For team targets, call the existing team removal path so repository access is recalculated.
- For org targets, remove org membership only when no unmanaged team membership or other active managed membership still requires the user to remain in the org.
- If Gitea refuses removal, such as last owner protection, report the item as skipped/error rather than bypassing native safety rules.

Alternatives considered:

- Direct SQL writes to `team_user` / `org_user`: rejected because it bypasses Gitea side effects and consistency safeguards.
- Never remove stale mapped memberships: rejected because offboarding and scope changes would leave stale authorization.

### 3. Dry-run and apply share the same planner

Implement a single reconciliation planner that returns additions, removals, skipped identities, protected removals, and errors. Dry-run returns the plan without mutation. Apply executes the plan inside bounded transactions and records the resulting managed membership state.

Rationale: dry-run must be trustworthy, and apply must not diverge from what operators preview.

Alternatives considered:

- Separate dry-run and apply code paths: rejected because drift between the two paths would be likely.

### 4. Post-sync reconciliation is opt-in

Add a disabled-by-default configuration switch under `[enterprise.wecom]`, for example `APPLY_AUTHZ_MAPPINGS_ON_SYNC = false`. When enabled, successful directory sync calls mapping reconciliation after the directory snapshot transaction commits. Failed or cancelled sync never applies mappings from the attempted snapshot.

Rationale: existing deployments can roll out mapping definitions and dry-run first, then enable automatic apply after validating results.

Alternatives considered:

- Always apply mappings after every sync: rejected because an incorrect mapping could immediately change authorization.

### 5. API is site-admin-only in this phase

Add API endpoints under `/api/v1/enterprise/wecom/mappings` guarded by existing site-admin API protection:

- list/create/update/delete mappings;
- dry-run active mappings;
- apply active mappings;
- optionally inspect the latest apply result summary.

Do not add org/repo settings UI yet. Future Platform Admin role support can replace or supplement site-admin guards after repo role overlay exists.

Permission matrix for this phase:

| Entry/API | Backend guard | External auth model | Default authorized role | Frontend entry key |
| --- | --- | --- | --- | --- |
| `GET /api/v1/enterprise/wecom/mappings` | site admin API guard | Not applicable | Site admin | API-only |
| `POST /api/v1/enterprise/wecom/mappings` | site admin API guard | Not applicable | Site admin | API-only |
| `PATCH/PUT /api/v1/enterprise/wecom/mappings/{id}` | site admin API guard | Not applicable | Site admin | API-only |
| `DELETE /api/v1/enterprise/wecom/mappings/{id}` | site admin API guard | Not applicable | Site admin | API-only |
| `POST /api/v1/enterprise/wecom/mappings/dry-run` | site admin API guard | Not applicable | Site admin | API-only |
| `POST /api/v1/enterprise/wecom/mappings/apply` | site admin API guard | Not applicable | Site admin or system job after sync | API-only |
| post-sync automatic apply | system job after successful WeCom sync | Not applicable | System job | None |

### 6. Audit records summarize outcomes, not private data

Add audit actions for mapping configuration and application. Metadata should include IDs, source/target types, counts, outcome, and reason codes. It must not include CorpSecret, access tokens, OAuth codes, raw callback URLs, phone numbers, or private profile fields.

Rationale: operators need explainability for authorization changes without creating a new sensitive-data store.

## Risks / Trade-offs

- Incorrect mapping grants broad team access → require site-admin-only management, dry-run first, audit every apply, and keep automatic apply disabled by default.
- Stale directory snapshot removes valid membership → only apply after successful committed sync; preserve manual membership and report skipped removals.
- Native Gitea membership side effects are complex → call existing organization/team services instead of direct SQL.
- Owner team or last owner edge cases can block removals → rely on existing Gitea safety checks and surface protected removals in reconciliation results.
- Org-only membership semantics grant less than team membership → document that org targets create org membership, while repository access remains governed by existing Gitea teams/repos.

## Migration Plan

- DB/modelmigration: required. Add explicit migration entries for mapping and managed membership tables, with tests proving existing users, SSH keys, PATs, Git HTTP tokens, WeCom identity tables, and Gitea team membership are not mutated by migration.
- OpenFGA: not required; this repository does not use OpenFGA for this feature.
- Keycloak: not required; Enterprise WeCom remains the external identity source and Gitea users remain local subjects.
- Swagger: required if API endpoints are added.
- Locale/UI: no UI in this phase; locale changes should be limited to API error text only if needed.

Deployment sequence:

1. Deploy migrations and API/service code with `APPLY_AUTHZ_MAPPINGS_ON_SYNC=false`.
2. Create mappings through the site-admin API.
3. Run dry-run and inspect additions/removals/skips.
4. Manually apply mappings once results are acceptable.
5. Enable post-sync apply only after operators validate repeated dry-run/apply behavior.

Rollback:

- Disable `APPLY_AUTHZ_MAPPINGS_ON_SYNC`.
- Stop using mapping apply API.
- Existing mapping-managed Gitea memberships are ordinary Gitea memberships after rollback; operators may remove them through Gitea admin tools or a follow-up repair if needed.
