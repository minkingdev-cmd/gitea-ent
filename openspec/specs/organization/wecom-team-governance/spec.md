# organization/wecom-team-governance Specification

## Purpose
Enterprise WeCom team governance makes Gitea teams, team membership, and team administrators a derived projection of Enterprise WeCom API data instead of locally maintained authorization state.

## Requirements

### Requirement: Teams are generated from Enterprise WeCom API data
The system SHALL generate Gitea teams in the managed organization target from Enterprise WeCom directory and tag snapshots using deterministic policy.

#### Scenario: Department generates Gitea team
- **WHEN** a synchronized Enterprise WeCom department matches the configured team derivation policy
- **THEN** the system generates or updates the corresponding Gitea team under the managed organization target

#### Scenario: Tag generates Gitea team
- **WHEN** a synchronized Enterprise WeCom tag matches the configured capability-team derivation policy
- **THEN** the system generates or updates the corresponding Gitea team under the managed organization target

#### Scenario: Missing team derivation target is reported
- **WHEN** a WeCom department or tag cannot be mapped to an allowed Gitea team name or organization target
- **THEN** the system records a skipped or errored generated-team item and does not create a broad fallback team

### Requirement: Team membership is reconciled from WeCom API data
The system SHALL reconcile membership of WeCom-managed Gitea teams from active bound Enterprise WeCom identities returned by the WeCom API snapshots.

#### Scenario: Department members become team members
- **WHEN** a WeCom-managed team is generated from a department and active bound WeCom users are members of that department
- **THEN** scheduled reconciliation ensures those bound Gitea users are members of the generated Gitea team

#### Scenario: Tag members become team members
- **WHEN** a WeCom-managed team is generated from a tag and active bound WeCom users are members of that tag
- **THEN** scheduled reconciliation ensures those bound Gitea users are members of the generated Gitea team

#### Scenario: Stale generated team membership is removed
- **WHEN** a user was added to a WeCom-managed team by automation and no active WeCom source still requires that membership
- **THEN** scheduled reconciliation removes that mapping-managed membership while respecting native Gitea safety checks

#### Scenario: Unbound or inactive WeCom user is skipped
- **WHEN** a WeCom user appears in a department or tag snapshot but is inactive, out of scope, or not bound to a Gitea user
- **THEN** the system does not add that user to the generated Gitea team and records a non-sensitive skip reason

### Requirement: Team administrators are derived from WeCom leadership or management metadata
The system SHALL derive team administrator status for WeCom-managed teams from Enterprise WeCom API metadata and SHALL NOT allow local manual team-admin assignment as the source of truth.

#### Scenario: Department leader becomes generated team administrator
- **WHEN** a WeCom department detail or member detail snapshot marks a bound active user as leader for the department that generated a Gitea team
- **THEN** scheduled reconciliation grants that user the appropriate Gitea team administrator or owner-level team role for the generated team

#### Scenario: Removed department leader loses generated team administrator role
- **WHEN** a user no longer appears as a WeCom leader for the department that generated the team
- **THEN** scheduled reconciliation removes the generated team administrator role unless another active WeCom API-derived source still grants it

#### Scenario: Source without admin metadata is unresolved, not locally patched
- **WHEN** a generated team source provides membership but no supported WeCom API metadata for team administrators
- **THEN** the system marks team administrator derivation as unresolved or system-managed and does not permit administrators to manually assign a local team admin as a substitute

#### Scenario: Tag-generated team uses only WeCom-derived administrator metadata
- **WHEN** a WeCom tag generates a team and the tag member API only provides membership data
- **THEN** the generated team does not receive a locally assigned administrator unless another supported WeCom API source or deterministic WeCom-derived policy supplies administrator metadata for that same generated team

#### Scenario: WeCom management administrator remains protected
- **WHEN** a WeCom management-authority user is also a generated team administrator
- **THEN** protected-administrator account rules still apply and local administrators cannot manage that user's account or remove the protected role manually

### Requirement: Local maintenance of WeCom-managed teams is blocked
The system SHALL block local Web/API maintenance of WeCom-managed team structure, membership, and team administrators outside the scheduled reconciliation pipeline.

#### Scenario: Local team membership edit is rejected
- **WHEN** a user attempts to manually add or remove members of a WeCom-managed team through Web or API routes
- **THEN** the system rejects the request without changing team membership

#### Scenario: Local team admin edit is rejected
- **WHEN** a user attempts to manually grant or revoke administrator or owner-level team role for a WeCom-managed team
- **THEN** the system rejects the request without changing team administrator state

#### Scenario: Local team rename or deletion is rejected
- **WHEN** a user attempts to rename or delete a WeCom-managed team through Web or API routes
- **THEN** the system rejects the request without changing the generated team

#### Scenario: Internal reconciliation may update managed team state
- **WHEN** the scheduled Enterprise WeCom reconciliation pipeline updates team structure, membership, or team administrator state
- **THEN** the system applies the change if it is derived from the committed WeCom snapshot and records the reconciliation outcome

### Requirement: Team governance is visible but read-only in admin UI
The system SHALL expose WeCom-generated team status, membership counts, team administrator source, and unresolved reasons in the site admin UI only to Enterprise WeCom-derived system super administrators, without allowing local mutation of managed teams.

#### Scenario: System super administrator views generated teams
- **WHEN** the system super administrator opens the Enterprise WeCom team status page
- **THEN** the system displays generated team source, Gitea team target, member count, administrator source, unresolved reasons, last run, and audit link

#### Scenario: Non-super-administrator cannot view generated teams
- **WHEN** a user without active Enterprise WeCom management authority, including an ordinary local site administrator, opens the generated team status page
- **THEN** the system rejects the request without disclosing team governance state

### Requirement: Team governance events are audited safely
The system SHALL audit generated team creation/update, team membership reconciliation, team administrator reconciliation, local maintenance denials, and unresolved administrator metadata without storing sensitive WeCom data.

#### Scenario: Team administrator reconciliation is audited
- **WHEN** scheduled reconciliation grants or removes generated team administrator status
- **THEN** the audit log records the generated team, WeCom source reference, target Gitea user, outcome, and non-sensitive reason code

#### Scenario: Local team maintenance denial is audited
- **WHEN** a user is denied while attempting to locally maintain a WeCom-managed team
- **THEN** the audit log records actor, team, attempted operation, outcome, and reason code
