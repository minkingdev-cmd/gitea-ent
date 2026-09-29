# identity/wecom-admin-ui-super-admin Specification

## Purpose
Enterprise WeCom scheduled authorization automation and protected administrator behavior let Gitea automatically apply WeCom-derived access changes while exposing read-only status to Enterprise WeCom-derived system super administrators inside the existing Gitea admin interface.

## Requirements

### Requirement: WeCom authorization synchronization is scheduled and automatic
The system SHALL periodically synchronize Enterprise WeCom directory and administrator authority, derive authorization mappings, and apply reconciliation without requiring administrators to manually maintain mapping records.

#### Scenario: Scheduled sync derives and applies mappings
- **WHEN** the configured Enterprise WeCom synchronization schedule runs successfully
- **THEN** the system synchronizes WeCom directory data, refreshes due administrator authority, derives generated mappings and generated teams/team administrators, reconciles Gitea membership and managed team state, persists run results, and audits the outcome

#### Scenario: Failed sync does not apply partial authorization
- **WHEN** Enterprise WeCom directory synchronization, authority refresh, or generated mapping derivation fails before a complete run is available
- **THEN** the system does not apply partial authorization changes from that failed run and records a non-sensitive failure reason

#### Scenario: Manual mapping maintenance is not exposed
- **WHEN** the system super administrator opens the Enterprise WeCom admin UI
- **THEN** the system shows automation status and generated mapping state but does not provide create, update, disable, dry-run, or apply controls for mapping records

#### Scenario: Legacy manual mutation route is rejected if reachable
- **WHEN** a request attempts to manually create, update, disable, or apply Enterprise WeCom mappings through a legacy or direct route that remains present for compatibility
- **THEN** the system rejects the request for normal operation without changing generated mappings or membership

### Requirement: Generated mappings are derived from WeCom data and deterministic policy
The system SHALL generate authorization mappings from synchronized WeCom directory and authority data using deterministic Gitea mapping policy rather than local per-mapping edits.

#### Scenario: Department generates target membership mapping
- **WHEN** a synchronized WeCom department matches the configured Gitea organization/team naming policy
- **THEN** the system generates a mapping from that department's active bound members to the matching Gitea target

#### Scenario: Tag generates target membership mapping
- **WHEN** a synchronized WeCom tag matches the configured Gitea team or capability naming policy
- **THEN** the system generates a mapping from that tag's active bound members to the matching Gitea target

#### Scenario: Missing generated target is reported, not silently granted
- **WHEN** a WeCom department or tag cannot be resolved to an allowed Gitea organization or team target
- **THEN** the system records the generated item as skipped or errored and does not grant broad fallback access

#### Scenario: Generated mapping state is explainable
- **WHEN** administrators inspect generated mapping status
- **THEN** the system shows the WeCom source, derived Gitea target, derivation rule, current status, last run, and non-sensitive skip/error reason when applicable

### Requirement: Scheduled reconciliation preserves safety boundaries
The system SHALL apply generated mapping reconciliation idempotently and preserve authorization safety boundaries.

#### Scenario: Repeated scheduled runs are idempotent
- **WHEN** scheduled synchronization runs repeatedly without relevant WeCom or Gitea target changes
- **THEN** repeated reconciliation does not create duplicate memberships or additional membership mutations

#### Scenario: Manual memberships are preserved
- **WHEN** a Gitea user has membership that was not created by generated WeCom mapping automation
- **THEN** scheduled reconciliation preserves that manual membership unless another existing Gitea safety rule removes it

#### Scenario: Stale generated membership is removed
- **WHEN** a Gitea membership was created by generated WeCom mapping automation and no active generated mapping still requires it
- **THEN** scheduled reconciliation removes the stale mapping-managed membership while respecting native Gitea last-owner and safety checks

#### Scenario: Protected administrator is not removed by generated mapping
- **WHEN** generated mapping reconciliation would remove membership needed by an active WeCom-protected management administrator
- **THEN** the system reports the item as protected or skipped rather than bypassing the protected administrator rule

### Requirement: Only WeCom system super administrators can observe admin UI status
The system SHALL expose Enterprise WeCom automation status in the site administrator Web UI with read-only status and troubleshooting views only after confirming Enterprise WeCom-derived system super-administrator authority.

#### Scenario: System super administrator opens WeCom automation status page
- **WHEN** a signed-in user whose active Enterprise WeCom management-authority identity resolves to the local account opens the Enterprise WeCom admin page
- **THEN** the system displays schedule, next run, last run outcome, authority snapshot status, generated mapping summary, generated team/team-admin summary, reconciliation counts, skipped/protected/unresolved items, and links to audit details

#### Scenario: Ordinary user or ordinary site administrator cannot open admin UI
- **WHEN** a signed-in user without active Enterprise WeCom management authority, including a local Gitea site administrator, opens any site admin or Enterprise WeCom admin status URL directly
- **THEN** the system rejects the request without disclosing WeCom automation state

#### Scenario: Admin navigation shows WeCom status entry only to authorized users
- **WHEN** the system super administrator views navigation
- **THEN** the system shows an Enterprise WeCom status entry under the existing admin navigation framework
- **WHEN** an unauthorized user views navigation
- **THEN** the system does not show the admin panel entry or the Enterprise WeCom status entry

### Requirement: WeCom administrator authority is discovered automatically
The system SHALL discover protected administrator authority from Enterprise WeCom callback/API data or the configured Enterprise WeCom contact tag source and SHALL NOT require or accept a local user selector for the protected super administrator identity.

#### Scenario: API refresh stores administrator authority snapshot
- **WHEN** the system successfully calls the supported Enterprise WeCom administrator authority API for the configured enterprise application
- **THEN** it stores the returned administrator identities, permission classification, active state, and refresh metadata as the current authority snapshot

#### Scenario: Self-built app tag refresh stores administrator authority snapshot
- **WHEN** the configured Enterprise WeCom app mode uses the contact tag `超管` as the administrator authority source
- **THEN** the system resolves the tag through Enterprise WeCom tag APIs and stores the tag's explicit `userlist` members as management-authority identities in the current authority snapshot
- **AND** it does not expand `partylist` departments into protected super administrators

#### Scenario: Administrator-change callback triggers refresh
- **WHEN** the system receives and validates an Enterprise WeCom administrator-change callback
- **THEN** it refreshes administrator authority from the supported WeCom API before changing protected local administrator decisions

#### Scenario: Message-only WeCom administrator is not local root
- **WHEN** the authority snapshot classifies a WeCom user as message-only or otherwise not having management authority
- **THEN** the system does not treat the bound Gitea user as a protected local super administrator because of that authority row

#### Scenario: Local user selector is not accepted
- **WHEN** an operator attempts to configure a local Gitea username, local Gitea user ID, or manual WeCom `userid` override as the protected super administrator source
- **THEN** the system ignores or rejects that selector and uses only WeCom API/callback-derived or configured WeCom tag-derived authority snapshots

#### Scenario: Unsupported authority API grants no fallback
- **WHEN** the configured WeCom app mode cannot expose administrator authority through a supported callback/API path or configured WeCom tag source
- **THEN** the system reports the authority source as unsupported or unresolved and does not grant protected-super-administrator status to any local fallback account

### Requirement: Protected administrator follows WeCom management authority
The system SHALL derive protected local administrator status from active WeCom management-authority snapshot rows that resolve to active bound Gitea users.

#### Scenario: Bound WeCom management administrator becomes protected local administrator
- **WHEN** an active WeCom administrator authority row with management authority resolves to an active bound Gitea user
- **THEN** that Gitea user is treated as protected from other administrators and has site administrator authority for the whole system

#### Scenario: WeCom authority removal changes protection
- **WHEN** a WeCom user no longer appears with management authority in a successfully refreshed authority snapshot
- **THEN** the bound Gitea user is no longer protected by this WeCom administrator rule after the refresh completes

#### Scenario: Multiple equivalent WeCom management administrators are mirrored
- **WHEN** WeCom reports multiple active users with equivalent management authority and does not expose a more precise single super-administrator role
- **THEN** the system protects every active bound management administrator from other administrators rather than selecting one locally

#### Scenario: Unbound WeCom administrator grants no local fallback
- **WHEN** an active WeCom management administrator identity is not yet bound to an active Gitea user
- **THEN** the system does not grant protected-super-administrator status to any local fallback account and surfaces a non-sensitive administrator warning or self-check failure

### Requirement: Other users cannot manage protected WeCom administrators
The system SHALL prevent every other user, including ordinary site administrators, from mutating or impersonating accounts protected by active WeCom management authority through Web admin routes or admin APIs.

#### Scenario: Ordinary site administrator cannot edit protected administrator
- **WHEN** a site administrator who is not the protected target user attempts to edit the protected user's profile, authentication source, login name, password, active state, restricted state, visibility, user type, site-admin flag, organization creation flag, repository limits, or other admin-editable account settings
- **THEN** the system rejects the request without mutating the protected user

#### Scenario: Ordinary site administrator cannot delete, purge, deactivate, prohibit, or demote protected administrator
- **WHEN** a site administrator who is not the protected target user attempts to delete, purge, deactivate, prohibit login for, or remove site-admin authority from the protected user
- **THEN** the system rejects the request without mutating the protected user

#### Scenario: Ordinary site administrator cannot rename or impersonate protected administrator
- **WHEN** a site administrator who is not the protected target user attempts to rename or impersonate the protected user
- **THEN** the system rejects the request without mutating the protected user or creating an impersonation session

#### Scenario: Protected administrator cannot remove its own root recoverability
- **WHEN** a protected administrator attempts to use an admin route or API to delete, purge, deactivate, prohibit login for, or remove site-admin authority from its own account
- **THEN** the system rejects the destructive request without mutating the protected user

### Requirement: Automation and protected administrator events are audited safely
The system SHALL audit scheduled sync, generated mapping derivation, reconciliation apply, WeCom authority refresh, protected-administrator resolution, denied management attempts, and allowed protected-user updates without storing sensitive WeCom values.

#### Scenario: Scheduled reconciliation is audited
- **WHEN** the scheduled automation pipeline completes, skips, or fails
- **THEN** the audit log records trigger, outcome, generated mapping counts, membership mutation counts, protected/skipped counts, and non-sensitive reason codes

#### Scenario: WeCom authority refresh is audited
- **WHEN** the system refreshes administrator authority from Enterprise WeCom API or callback-triggered refresh
- **THEN** the audit log records outcome, counts, non-sensitive reason codes, and refresh source

#### Scenario: Denied management attempt is audited
- **WHEN** a user is denied while attempting to manage a protected administrator
- **THEN** the audit log records the actor, target user, attempted operation class, outcome, and reason without changing the protected user

#### Scenario: Sensitive values are excluded from audit metadata
- **WHEN** automation or protected-administrator audit metadata is recorded
- **THEN** the metadata does not include Enterprise WeCom secrets, suite tokens, access tokens, OAuth authorization codes, raw callback URLs, phone numbers, or private profile fields

### Requirement: UI features provide Gitea-framed reviewable prototypes before implementation
For Enterprise WeCom admin functionality that changes user-visible Web UI, the change SHALL include a static prototype artifact that reviewers can open before production templates are implemented, and that prototype SHALL fit the existing Gitea admin interface framework.

#### Scenario: Automation status prototype is available inside the Gitea admin frame
- **WHEN** reviewers inspect the OpenSpec change before implementation
- **THEN** a static prototype shows scheduled sync status, generated mappings, generated teams/team administrators, authority sync, protected administrator status, reconciliation summary, and audit-feedback UI states using Gitea-style admin navigation, attached headers, segments, labels, buttons or links, and tables

#### Scenario: Prototype distinguishes permission visibility
- **WHEN** reviewers inspect the prototype
- **THEN** it shows which navigation entries, pages, and actions are visible to non-admin users, ordinary site administrators, WeCom-protected management administrators, and system/API-only actors

#### Scenario: Prototype is not treated as production code
- **WHEN** implementation begins
- **THEN** the prototype guides layout and behavior review but does not replace production templates, backend guards, or tests

### Requirement: Existing Git, token, and repository permission behavior remains compatible
Scheduled WeCom authorization automation and protected-administrator behavior SHALL NOT replace Gitea users as authorization subjects and SHALL NOT add WeCom-specific checks to existing SSH key, PAT/API token, Git HTTP token, or native repository permission flows.

#### Scenario: Protected administrator SSH key authentication remains unchanged
- **WHEN** a protected administrator authenticates using an existing SSH key
- **THEN** the system evaluates authentication and repository access using the existing Gitea SSH key behavior

#### Scenario: Protected administrator PAT authentication remains unchanged
- **WHEN** a protected administrator authenticates an API request using an existing PAT or API token
- **THEN** the system evaluates authentication and token scope using the existing Gitea token behavior

#### Scenario: Protected administrator Git HTTP token authentication remains unchanged
- **WHEN** a protected administrator authenticates a Git HTTP operation using an existing token-supported mechanism
- **THEN** the system evaluates authentication and repository access using the existing Gitea Git HTTP behavior
