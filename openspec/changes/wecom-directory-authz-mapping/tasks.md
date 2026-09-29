## 1. Baseline and migration model

- [x] 1.1 Inspect existing WeCom directory sync, organization/team membership, audit, admin API, and swagger patterns; record exact hook points before editing code.
- [x] 1.2 Add additive mapping and managed-membership models under the Enterprise WeCom model area without modifying core `team_user` or `org_user` schemas.
- [x] 1.3 Add explicit `modelmigration` entries for `enterprise_wecom_authz_mapping` and `enterprise_wecom_managed_membership`.
- [x] 1.4 Add migration tests proving the new tables are created and existing users, SSH keys, PATs, Git HTTP tokens, WeCom identity rows, org users, and team users are not mutated.
- [x] 1.5 Add `[enterprise.wecom] APPLY_AUTHZ_MAPPINGS_ON_SYNC = false` with disabled-by-default behavior, config loading tests, and `custom/conf/app.example.ini` documentation.

## 2. Mapping persistence and validation

- [x] 2.1 Implement create, update, disable/delete, list, and get operations for WeCom authorization mappings.
- [x] 2.2 Validate mapping source types `user`, `department`, and `tag` against the synchronized WeCom snapshot and configured CorpID.
- [x] 2.3 Validate mapping targets for existing org/team, including rejecting missing targets, unsupported target types, and teams outside the selected organization.
- [x] 2.4 Add model/service tests for valid user, department, and tag mappings plus invalid source/target rejection.
- [x] 2.5 Add audit events for mapping create, update, disable/delete, and validation failure outcomes without sensitive metadata.

## 3. Reconciliation planner and apply engine

- [x] 3.1 Implement a shared reconciliation planner that resolves active mappings to bound active Gitea users and reports additions, removals, skipped identities, protected removals, and errors.
- [x] 3.2 Add dry-run tests proving no team or org membership changes are written while planned additions/removals/skips are reported.
- [x] 3.3 Implement apply for team targets using existing Gitea team membership services and managed-membership state.
- [x] 3.4 Implement apply for org targets conservatively, preserving existing team-derived or manual org membership and respecting native last-owner protections.
- [x] 3.5 Add idempotency tests proving repeated apply creates no duplicate memberships or extra changes.
- [x] 3.6 Add reconciliation tests proving inactive, left, out-of-scope, and unbound WeCom identities are skipped or removed from mapping-managed membership as specified.
- [x] 3.7 Add tests proving stale mapping-managed membership is removed, manual membership is preserved, and shared membership remains while another active mapping still applies.
- [x] 3.8 Ensure reconciliation failures do not commit partial authorization results for the selected mapping set.

## 4. API and sync integration

- [x] 4.1 Add site-admin-only API routes under `/api/v1/enterprise/wecom/mappings` for list, create, update, delete/disable, dry-run, and apply.
- [x] 4.2 Add API tests covering non-admin 403, site-admin success, invalid payload rejection, dry-run no mutation, and apply mutation.
- [x] 4.3 Regenerate and validate swagger for the new API endpoints.
- [x] 4.4 Integrate optional post-sync reconciliation so successful directory sync applies mappings only when `APPLY_AUTHZ_MAPPINGS_ON_SYNC=true`.
- [x] 4.5 Add sync integration tests proving successful sync can trigger mapping apply and failed/cancelled sync does not change mapped authorization.
- [x] 4.6 Add audit events for manual apply, dry-run if recorded, and post-sync apply with summary counts and no sensitive values.

## 5. Compatibility, documentation, and verification

- [x] 5.1 Add or extend regression tests proving SSH key authentication behavior is unchanged after mappings are configured and applied.
- [x] 5.2 Add or extend regression tests proving PAT/API token behavior is unchanged after mappings are configured and applied.
- [x] 5.3 Add or extend regression tests proving Git HTTP token behavior is unchanged after mappings are configured and applied.
- [x] 5.4 Re-run existing Enterprise WeCom login-only tests covering forbidden Web login paths to confirm mapping changes do not reopen password, registration, OpenID, Passkey, reverse-proxy, SSPI, or non-WeCom OAuth sign-in.
- [x] 5.5 Update `docs/enterprise-authz/implementation-plan.md` to mark the current WeCom login baseline accurately and document the new Phase 2 mapping scope and rollout sequence.
- [x] 5.6 Run `make fmt` after Go edits.
- [x] 5.7 Run targeted Go tests for changed model, service, auth, cron, API, audit, migration, and integration packages.
- [x] 5.8 Run `make lint-go` and fix causes rather than suppressing lint.
- [x] 5.9 Run `openspec validate wecom-directory-authz-mapping --strict` before requesting implementation review.
