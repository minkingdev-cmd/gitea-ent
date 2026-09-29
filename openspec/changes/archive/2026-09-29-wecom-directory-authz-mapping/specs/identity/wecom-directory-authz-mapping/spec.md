## Purpose

Enterprise WeCom directory authorization mapping turns synchronized corporate identities into existing Gitea organization and team membership while keeping Gitea users as the local authorization subject.

## ADDED Requirements

### Requirement: Site administrators can manage WeCom authorization mappings
The system SHALL let authorized administrators define mappings from Enterprise WeCom directory subjects to existing Gitea authorization targets.

#### Scenario: Site administrator creates a department-to-team mapping
- **WHEN** a site administrator creates a mapping from a visible WeCom department to an existing Gitea team
- **THEN** the system stores the mapping as active and makes it available for reconciliation

#### Scenario: Site administrator creates a tag-to-team mapping
- **WHEN** a site administrator creates a mapping from a visible WeCom tag to an existing Gitea team
- **THEN** the system stores the mapping as active and makes it available for reconciliation

#### Scenario: Site administrator creates a user-to-team mapping
- **WHEN** a site administrator creates a mapping from a visible WeCom user to an existing Gitea team
- **THEN** the system stores the mapping as active and makes it available for reconciliation

#### Scenario: Non-administrator cannot manage mappings
- **WHEN** a user without site administrator permission attempts to create, update, delete, dry-run, or apply a WeCom authorization mapping
- **THEN** the system rejects the request without changing mappings or team membership

#### Scenario: Invalid mapping target is rejected
- **WHEN** an administrator attempts to map a WeCom subject to a missing organization, missing team, unsupported target type, or a team outside the selected organization
- **THEN** the system rejects the mapping without changing existing authorization state

### Requirement: Mapping reconciliation uses active synchronized WeCom identities
The system SHALL resolve mappings from the current synchronized Enterprise WeCom directory snapshot and SHALL apply only active identities that are bound to Gitea users.

#### Scenario: Active department members are added to the mapped team
- **WHEN** a mapping from a WeCom department to a Gitea team is applied and the department contains active bound WeCom identities
- **THEN** the corresponding Gitea users are members of the mapped team after reconciliation

#### Scenario: Active tag members are added to the mapped team
- **WHEN** a mapping from a WeCom tag to a Gitea team is applied and the tag contains active bound WeCom identities
- **THEN** the corresponding Gitea users are members of the mapped team after reconciliation

#### Scenario: Unbound WeCom identity is not added to a team
- **WHEN** a mapping resolves a WeCom identity that is not bound to a Gitea user
- **THEN** the system does not add any Gitea team membership for that identity and reports it as skipped in the reconciliation result

#### Scenario: Inactive identity is not authorized through mapping
- **WHEN** a mapping resolves a WeCom identity whose status is inactive, left, or out of application-visible scope
- **THEN** the system does not add that identity's Gitea user to the mapped team

### Requirement: Mapping reconciliation is idempotent and supports dry-run
The system SHALL expose reconciliation results before mutation and SHALL make repeated mapping application safe.

#### Scenario: Dry-run reports planned membership changes
- **WHEN** an administrator dry-runs active WeCom authorization mappings
- **THEN** the system reports planned team membership additions, removals, skipped identities, and errors without changing team membership

#### Scenario: Applying the same mapping twice is idempotent
- **WHEN** an administrator applies the same active WeCom authorization mappings twice without directory changes between runs
- **THEN** the second application produces no duplicate team memberships and no additional membership changes

#### Scenario: Failed reconciliation does not apply a partial snapshot
- **WHEN** mapping reconciliation fails before completing the selected mapping set
- **THEN** the system does not commit a partial authorization result for that mapping set

### Requirement: Reconciliation preserves manually managed team membership
The system SHALL distinguish team memberships managed by WeCom mappings from team memberships managed manually or by other Gitea features.

#### Scenario: Stale mapped membership is removed
- **WHEN** a Gitea user was added to a team by a WeCom mapping and no longer matches any active source subject for that mapping
- **THEN** the system removes that mapping-managed team membership during reconciliation

#### Scenario: Manual team membership is preserved
- **WHEN** a Gitea user is a team member through manual administration and no longer matches a WeCom mapping source
- **THEN** the system preserves the manual team membership during reconciliation

#### Scenario: Shared membership remains when one mapping still applies
- **WHEN** multiple active WeCom mappings manage the same Gitea user's membership in the same team and only one mapping stops matching
- **THEN** the system preserves the team membership while at least one active mapping still applies

### Requirement: Directory sync can trigger mapping reconciliation safely
The system SHALL be able to reconcile mappings after a successful Enterprise WeCom directory synchronization and SHALL NOT apply mappings from a failed or partial directory synchronization.

#### Scenario: Successful directory sync triggers mapping reconciliation when enabled
- **WHEN** Enterprise WeCom directory synchronization completes successfully and automatic mapping reconciliation is enabled
- **THEN** the system reconciles active mappings using the completed synchronized snapshot

#### Scenario: Failed directory sync does not change mapped authorization
- **WHEN** Enterprise WeCom directory synchronization fails or is cancelled before committing a complete snapshot
- **THEN** the system does not apply WeCom authorization mappings from that failed synchronization attempt

### Requirement: Mapping changes and applications are audited without sensitive data
The system SHALL record audit events for WeCom authorization mapping management and reconciliation without storing secrets, access tokens, OAuth codes, or private profile data.

#### Scenario: Mapping configuration change is audited
- **WHEN** an administrator creates, updates, disables, or deletes a WeCom authorization mapping
- **THEN** the audit log records the actor, mapping identifier, source type, target type, outcome, and non-sensitive reason metadata

#### Scenario: Mapping application is audited
- **WHEN** WeCom authorization mappings are applied manually or after directory sync
- **THEN** the audit log records the actor or system job identity, reconciliation outcome, affected mapping count, and non-sensitive summary counts

#### Scenario: Sensitive values are not stored in audit metadata
- **WHEN** mapping management or reconciliation records audit metadata
- **THEN** the audit metadata does not contain Enterprise WeCom secrets, access tokens, OAuth authorization codes, raw callback URLs, phone numbers, or private profile fields

### Requirement: Existing authentication and repository permission behavior remains unchanged
WeCom authorization mapping SHALL NOT replace Gitea users as authorization subjects and SHALL NOT add WeCom-specific checks to existing SSH key, PAT/API token, Git HTTP token, or native repository permission flows.

#### Scenario: SSH key authentication remains unchanged
- **WHEN** a user authenticates using an existing SSH key after WeCom mappings are configured or reconciled
- **THEN** the system evaluates authentication and repository access using the existing Gitea SSH key behavior

#### Scenario: PAT authentication remains unchanged
- **WHEN** a user authenticates an API request using an existing PAT or API token after WeCom mappings are configured or reconciled
- **THEN** the system evaluates authentication and token scope using the existing Gitea token behavior

#### Scenario: Git HTTP token authentication remains unchanged
- **WHEN** a user authenticates a Git HTTP operation using an existing token-supported mechanism after WeCom mappings are configured or reconciled
- **THEN** the system evaluates authentication and repository access using the existing Gitea Git HTTP behavior

#### Scenario: Repository permissions continue to use Gitea subjects
- **WHEN** WeCom mappings add or remove Gitea team memberships
- **THEN** repository access continues to be determined by existing Gitea user, organization, team, and repository permission behavior rather than a new external authorization provider
