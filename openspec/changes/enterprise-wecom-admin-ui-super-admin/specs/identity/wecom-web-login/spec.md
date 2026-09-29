## ADDED Requirements

### Requirement: Enterprise WeCom administrator authority binding
Enterprise WeCom identity binding and directory synchronization SHALL consume WeCom administrator-authority snapshots from callback/API refresh or the configured Enterprise WeCom `超管` tag source to identify protected local administrator users while keeping Gitea users as the local authorization subject.

#### Scenario: Administrator login establishes protected local user when authority exists
- **WHEN** a WeCom user with active management authority completes Web login and the WeCom `userid` is not yet bound to a Gitea user
- **THEN** the system creates or binds the Gitea user according to Enterprise WeCom login configuration and treats that bound user as protected once the authority snapshot confirms management authority

#### Scenario: Directory sync refreshes administrator protection from authority snapshot
- **WHEN** Enterprise WeCom directory synchronization completes and active administrator-authority snapshot rows resolve to active bound identities
- **THEN** the system refreshes protected local administrators to those bound Gitea users

#### Scenario: Administrator authority source is WeCom API, callback, or configured tag data
- **WHEN** Enterprise WeCom administrator protection is enabled
- **THEN** the system derives protected users from WeCom callback/API-refreshed or configured WeCom tag-refreshed administrator authority and does not use a local Gitea username, local user ID, or manual WeCom `userid` override as the source of truth

#### Scenario: Administrator binding does not change token authentication model
- **WHEN** a Gitea user becomes or stops being protected because of Enterprise WeCom administrator authority refresh
- **THEN** existing SSH key, PAT/API token, Git HTTP token, and repository permission checks continue to follow existing Gitea account and credential behavior
