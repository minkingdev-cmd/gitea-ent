## Purpose

Enterprise WeCom Web Login provides a single trusted corporate Web sign-in path and binds each Gitea user to a WeCom `userid` while preserving existing Git and token authentication behavior.

## ADDED Requirements

### Requirement: Enterprise WeCom login-only mode
When Enterprise WeCom login-only mode is enabled, the system SHALL allow Web sign-in only through the configured Enterprise WeCom application.

#### Scenario: Login page redirects to WeCom when it is the only Web sign-in source
- **WHEN** an unsigned user opens the Web sign-in page and Enterprise WeCom login-only mode is enabled with one active WeCom login source
- **THEN** the system redirects the user to the Enterprise WeCom authorization flow

#### Scenario: Password Web sign-in is rejected
- **WHEN** an unsigned user submits local username and password credentials to the Web sign-in endpoint while Enterprise WeCom login-only mode is enabled
- **THEN** the system rejects the request without creating a Web session

#### Scenario: Non-WeCom Web sign-in sources are unavailable
- **WHEN** Enterprise WeCom login-only mode is enabled
- **THEN** the system does not offer local registration, OpenID, Passkey, or non-WeCom OAuth2 Web sign-in as usable Web sign-in methods

### Requirement: WeCom callback identity validation
The system SHALL validate every Enterprise WeCom Web login callback before creating or updating a Gitea Web session.

#### Scenario: Callback with valid state and enterprise member
- **WHEN** the callback contains a valid state and an authorization code that resolves to a member of the configured Enterprise WeCom application
- **THEN** the system continues identity binding for that WeCom user

#### Scenario: Callback with invalid state
- **WHEN** the callback state is missing, expired, or does not match the login attempt
- **THEN** the system denies the Web login attempt and does not create a Web session

#### Scenario: Callback for a non-member or wrong enterprise
- **WHEN** the authorization code does not resolve to a member of the configured Enterprise WeCom enterprise and application boundary
- **THEN** the system denies the Web login attempt and records the denial reason for audit

### Requirement: WeCom userid binding
The system SHALL use the Enterprise WeCom `userid` within the configured enterprise as the external identity key for Web login.

#### Scenario: Existing binding logs in the same Gitea user
- **WHEN** a WeCom `userid` already has an active binding to a Gitea user
- **THEN** a successful WeCom Web login creates a Web session for that bound Gitea user

#### Scenario: First login creates or binds a Gitea user according to configuration
- **WHEN** a valid WeCom member logs in and no binding exists
- **THEN** the system either creates a new Gitea user or binds to an eligible existing Gitea user according to Enterprise WeCom configuration

#### Scenario: Email is not used as the identity key
- **WHEN** the WeCom profile includes an email address
- **THEN** the system does not use that email address as the stable external identity key

### Requirement: Existing Git and token authentication compatibility
Enterprise WeCom Web login SHALL NOT replace or add WeCom-specific checks to existing SSH key, PAT/API token, or Git HTTP token authentication flows.

#### Scenario: SSH key authentication remains on the existing path
- **WHEN** a user authenticates using an existing SSH key
- **THEN** the system evaluates authentication and repository access using the existing Gitea SSH key behavior

#### Scenario: PAT authentication remains on the existing path
- **WHEN** a user authenticates an API request using an existing PAT or API token
- **THEN** the system evaluates authentication and token scope using the existing Gitea token behavior

#### Scenario: Git HTTP token authentication remains on the existing path
- **WHEN** a user authenticates a Git HTTP operation using an existing token-supported mechanism
- **THEN** the system evaluates authentication and repository access using the existing Gitea Git HTTP behavior

### Requirement: Account status compatibility
Enterprise WeCom identity status SHALL affect Web login only as explicitly configured and SHALL NOT define a new token invalidation model.

#### Scenario: WeCom identity is inactive for Web login
- **WHEN** a WeCom identity is marked inactive, left, or out of application-visible scope
- **THEN** the system denies new Web login through Enterprise WeCom for that identity

#### Scenario: Token behavior follows existing Gitea account rules
- **WHEN** a bound Gitea user has SSH keys, PATs, or Git HTTP token access
- **THEN** those credentials continue to follow existing Gitea account status and credential validation rules

### Requirement: Enterprise WeCom audit events
The system SHALL record audit events for Enterprise WeCom Web login decisions and identity binding changes without storing secrets or access tokens in audit metadata.

#### Scenario: Successful WeCom Web login is audited
- **WHEN** a WeCom Web login succeeds
- **THEN** the audit log records the Gitea user, WeCom external identity reference, login source, and outcome

#### Scenario: Denied WeCom Web login is audited
- **WHEN** a WeCom Web login is denied after callback validation or identity status evaluation
- **THEN** the audit log records the denial outcome and reason without exposing WeCom secrets, access tokens, or private user data

#### Scenario: Identity binding change is audited
- **WHEN** a WeCom identity is bound to or updated for a Gitea user
- **THEN** the audit log records the binding change with actor, target user, external identity reference, and outcome

### Requirement: Enterprise WeCom configuration safety
The system SHALL expose Enterprise WeCom configuration in a way that supports secret indirection and safe disabled-by-default rollout.

#### Scenario: Enterprise WeCom is disabled by default
- **WHEN** Enterprise WeCom is not enabled in configuration
- **THEN** the system preserves existing Web sign-in behavior

#### Scenario: Secret values are referenced rather than stored in repository configuration
- **WHEN** Enterprise WeCom requires an application secret
- **THEN** the configuration supports referencing the secret through a secure URI or equivalent indirection rather than requiring committed plaintext

#### Scenario: Disabled integration rejects configured WeCom sources
- **WHEN** Enterprise WeCom is disabled and an active WeCom OAuth2 source remains in the database
- **THEN** the system does not display that source and rejects both login initiation and callback requests for it

#### Scenario: Login-only startup requires the configured source
- **WHEN** Enterprise WeCom login-only mode is enabled and the configured WeCom OAuth2 source is missing, inactive, invalid, or cannot be initialized
- **THEN** startup fails with a non-sensitive configuration error before the Web service accepts requests

### Requirement: Enterprise WeCom errors do not disclose credentials
The system SHALL NOT expose Enterprise WeCom application secrets, access tokens, authorization codes, or sensitive request URLs through logs, audit metadata, or user-visible errors.

#### Scenario: WeCom transport request fails
- **WHEN** a WeCom HTTP request fails and the underlying transport error contains the request URL
- **THEN** the returned error and any resulting log or Web message contain only a safe operation and reason code

#### Scenario: WeCom callback returns an error
- **WHEN** the WeCom callback contains provider error parameters
- **THEN** the user sees a generic localized error and raw callback parameters are not logged or displayed

### Requirement: WeCom directory sync foundation
When directory sync is enabled, the system SHALL synchronize Enterprise WeCom members, departments, and tags within the configured application-visible scope to support identity status and future authorization mapping.

#### Scenario: Directory sync respects application visibility
- **WHEN** directory synchronization runs
- **THEN** the system only records members, departments, and tags visible to the configured Enterprise WeCom application

#### Scenario: Directory sync stores minimum required identity data
- **WHEN** directory synchronization persists WeCom identity data
- **THEN** the system stores only fields needed for identity status, display, audit, and future authorization mapping

#### Scenario: Directory sync runs on the configured schedule
- **WHEN** Enterprise WeCom and its directory sync cron task are enabled
- **THEN** the system runs synchronization on the configured cron schedule and exposes it through the existing administrator cron task controls

#### Scenario: Directory sync is cancelled during shutdown
- **WHEN** the application shutdown context is cancelled during directory synchronization
- **THEN** in-flight WeCom HTTP requests are cancelled and no partial snapshot is committed
