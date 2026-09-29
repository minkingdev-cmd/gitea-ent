## Why

Enterprise WeCom Web login and directory snapshots are now in place, but directory identities cannot yet be applied to Gitea authorization subjects. Without an explicit, audited mapping layer, future repo roles and policy evaluators would either rely on stale manual team membership or couple directly to WeCom directory structures.

This change adds the Phase 2 authorization mapping foundation from `docs/enterprise-authz/implementation-plan.md`: map visible WeCom users, departments, and tags to existing Gitea organizations and teams, while keeping Gitea users and native team membership as the local authorization subject.

## What Changes

- Add an Enterprise WeCom authorization mapping capability that lets site administrators map WeCom users, departments, or tags to existing Gitea organizations or teams.
- Apply mappings idempotently after successful directory synchronization and through an explicit manual apply path.
- Track which team memberships were created by WeCom mappings so future reconciliation can safely remove stale mapped memberships without deleting manually managed memberships.
- Treat inactive, left, or out-of-scope WeCom identities as ineligible for new mapped team membership.
- Record mapping create/update/delete/apply decisions in audit logs without storing WeCom secrets, access tokens, OAuth codes, or private profile data.
- Provide read, dry-run, and apply service/API boundaries for mapping management guarded by site admin permissions in this phase.
- Preserve existing SSH key, PAT/API token, Git HTTP token, and native Gitea repository permission behavior; this change does not introduce repo action overlay enforcement.

## Capabilities

### New Capabilities

- `identity/wecom-directory-authz-mapping`: Enterprise WeCom directory subjects can be mapped to existing Gitea organizations and teams, reconciled idempotently, and audited.

### Modified Capabilities

- None.

## Impact

- Affected code areas:
  - `models/enterprisewecom` or a new additive model package for mapping definitions and managed membership state.
  - `modelmigration/v28` and `modelmigration/migrations.go` for explicit mapping tables.
  - `services/enterprisewecom` for mapping resolution, dry-run, reconciliation, and post-sync apply integration.
  - Admin/API routing only if management endpoints are added; swagger must be regenerated for API changes.
  - `models/audit` / `services/audit` for mapping update and apply events.
  - Tests for migration safety, idempotent reconciliation, stale mapped membership removal, manual membership preservation, and unchanged token/Git auth behavior.
- Affected external systems:
  - Existing Enterprise WeCom directory APIs remain the source of department, tag, and member snapshots.
  - Existing Gitea organizations and teams remain the authorization target; this change does not create a new external PDP.
- Compatibility:
  - No breaking change to SSH key authentication.
  - No breaking change to PAT/API token authentication.
  - No breaking change to Git HTTP token authentication.
  - No repo role overlay, feature grant, merge gate, or branch protection enforcement is introduced by this change.
