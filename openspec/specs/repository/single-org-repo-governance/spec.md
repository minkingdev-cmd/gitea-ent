# repository/single-org-repo-governance Specification

## Purpose
Repository governance restricts organization creation to the Enterprise WeCom-derived system super administrator, routes organization repository creation through super-admin approval, permits limited private personal repositories, and restricts repository authorization changes to trusted actors.

## Requirements

### Requirement: Organization creation is super-administrator-only
The system SHALL allow only the Enterprise WeCom-derived system super administrator to create organizations across Web, API, admin API, and service paths.

#### Scenario: Super administrator creates an organization
- **WHEN** the system super administrator creates an organization
- **THEN** the system creates that organization

#### Scenario: Ordinary user cannot create organization
- **WHEN** a non-super-admin user attempts to create an organization
- **THEN** the system rejects the request without creating an organization

#### Scenario: Ordinary site administrator cannot create organization
- **WHEN** a site administrator who is not the system super administrator attempts to create an organization
- **THEN** the system rejects the request without creating an organization

#### Scenario: Super administrator creates organization for another owner through admin API
- **WHEN** the system super administrator creates an organization for an ordinary user through an admin creation path
- **THEN** the system creates the organization and assigns the requested owner according to existing Gitea organization ownership behavior

### Requirement: Ordinary members request organization repositories
The system SHALL let ordinary members request repository creation under an organization and SHALL create the repository only after system super administrator approval.

#### Scenario: Ordinary member submits organization repository request
- **WHEN** an ordinary member submits a valid organization repository request for an organization
- **THEN** the system stores a pending request and does not create the repository yet

#### Scenario: Ordinary member can request before local organization membership exists
- **WHEN** an ordinary signed-in member who is not yet a local Gitea member of the target organization opens or submits the organization repository request flow
- **THEN** the system allows the request to be submitted for the existing organization without granting direct repository creation or organization membership

#### Scenario: Ordinary member can track submitted organization repository requests
- **WHEN** an ordinary member submits an organization repository request
- **THEN** the system redirects to a Gitea-framed user page that lists the member's own organization repository requests and their pending, approved, or rejected status

#### Scenario: Super administrator approves organization repository request
- **WHEN** the system super administrator approves a pending organization repository request
- **THEN** the system creates a Private repository under the requested organization, records the requester as repository creator, grants the requester owner-level repository permission or equivalent existing Gitea authority, links the repository to the request, and audits the approval

#### Scenario: Super administrator rejects organization repository request
- **WHEN** the system super administrator rejects a pending organization repository request with a reason
- **THEN** the system records the request as rejected, creates no repository, and audits the rejection

#### Scenario: Ordinary member cannot directly create organization repository
- **WHEN** an ordinary member attempts to bypass the request workflow and directly create a repository under the organization
- **THEN** the system rejects the request without creating a repository

#### Scenario: Ordinary site administrator cannot approve organization repository request
- **WHEN** a site administrator who is not the system super administrator attempts to approve or reject an organization repository request
- **THEN** the system rejects the request without changing approval state or creating a repository

### Requirement: Personal repositories are private and quota-limited
The system SHALL allow ordinary members to create private repositories under their own user namespace without approval until they reach the personal repository quota.

#### Scenario: Ordinary member creates personal private repository under quota
- **WHEN** an ordinary member with fewer than 10 personal repositories creates a repository in their own namespace
- **THEN** the system creates the repository with Private visibility without requiring administrator approval

#### Scenario: Personal repository quota blocks creation
- **WHEN** an ordinary member already owns 10 or more personal repositories and attempts to create another personal repository
- **THEN** the system rejects the request without creating a repository

#### Scenario: Personal repository creation cannot target another user namespace
- **WHEN** a user attempts to create a personal repository under another user's namespace
- **THEN** the system rejects the request unless an existing higher-priority Gitea safety rule already forbids it earlier

#### Scenario: Organization repositories do not count against personal quota
- **WHEN** the system counts a user's personal repository quota
- **THEN** repositories owned by organizations are not counted against that user's personal repository limit

### Requirement: Repository creation defaults to Private visibility
The system SHALL create repositories with Private visibility by default across personal and organization creation flows governed by this policy.

#### Scenario: Personal repository creation defaults private
- **WHEN** a user opens or submits the personal repository creation flow
- **THEN** Private visibility is selected and persisted for the new repository

#### Scenario: Approved organization repository is private
- **WHEN** a system super administrator approves an organization repository request
- **THEN** the created organization repository has Private visibility

#### Scenario: Non-private creation option is rejected in governed flow
- **WHEN** a governed repository creation request attempts to create a Public or Internal repository
- **THEN** the system rejects or normalizes the request to Private according to the implementation's safest existing Gitea pattern and does not create a non-private repository

### Requirement: Repository authorization changes require creator, owner, or super administrator
The system SHALL restrict repository authorization changes to the repository creator, users with owner-level repository permission, or the system super administrator.

#### Scenario: Repository creator grants access
- **WHEN** the recorded repository creator grants, updates, or revokes another user's repository access
- **THEN** the system permits the authorization change if the target access mode is valid for that repository

#### Scenario: Owner-level user grants access
- **WHEN** a user with owner-level repository permission grants, updates, or revokes another user's or team's repository access
- **THEN** the system permits the authorization change if the target access mode is valid for that repository

#### Scenario: System super administrator grants access
- **WHEN** the system super administrator grants, updates, or revokes another user's or team's repository access
- **THEN** the system permits the authorization change if the target access mode is valid for that repository

#### Scenario: Non-owner administrator cannot grant repository access
- **WHEN** an ordinary site administrator is not the repository creator, lacks owner-level repository permission, and is not the system super administrator
- **THEN** the system rejects the repository authorization change without changing collaborators, teams, or access modes

#### Scenario: Ordinary collaborator cannot grant repository access
- **WHEN** a repository collaborator with read, write, or non-owner administrative permissions but not owner-level permission attempts to grant, update, or revoke repository access
- **THEN** the system rejects the authorization change without changing collaborators, teams, or access modes

### Requirement: Repository governance events are audited safely
The system SHALL audit organization creation decisions, organization repository requests and approvals, personal quota denials, default visibility enforcement, and repository authorization changes without storing sensitive WeCom data.

#### Scenario: Organization repository approval is audited
- **WHEN** an organization repository request is approved or rejected
- **THEN** the audit log records requester, reviewer, outcome, repository when created, and non-sensitive reason metadata

#### Scenario: Personal quota denial is audited
- **WHEN** personal repository creation is denied because the user reached the quota
- **THEN** the audit log records actor, namespace, quota, current count, and outcome

#### Scenario: Repository authorization change is audited
- **WHEN** repository access is granted, changed, revoked, or denied by the governance guard
- **THEN** the audit log records actor, repository, target principal, requested access mode, outcome, and reason code
