## 1. Baseline and integration points

- [x] 1.1 Run `make help` and record the relevant verification targets for Go, templates, swagger, and focused tests.
- [x] 1.2 Inspect existing Web sign-in, OAuth2 source, external login binding, audit, SSH key, PAT, and Git HTTP auth paths to confirm exact hook points.
- [x] 1.3 Confirm current app configuration knobs for password Web sign-in, registration, OpenID, Passkey, Basic auth, OAuth2 auto-registration, and single-provider redirect.

## 2. Configuration and data model

- [x] 2.1 Add `[enterprise.wecom]` settings with disabled-by-default behavior, login-only mode, CorpID, AgentID, secret URI, username template, auto-create-user, and sync options.
- [x] 2.2 Add configuration validation that rejects incomplete WeCom login-only setup when enabled.
- [x] 2.3 Add DB migration and models for WeCom identity binding with `corp_id + userid` uniqueness and Gitea `user_id` linkage.
- [x] 2.4 Add optional directory snapshot models for departments, tags, and memberships if sync is enabled.
- [x] 2.5 Ensure migrations do not mutate existing SSH keys, PATs, Git HTTP token data, or local user credentials.

## 3. WeCom login provider and identity binding

- [x] 3.1 Implement a WeCom API client abstraction for access token retrieval and OAuth code-to-user identity resolution.
- [x] 3.2 Implement the WeCom Web authorization URL builder with state handling, CorpID, AgentID, callback URL, and scope.
- [x] 3.3 Implement callback validation for state, configured enterprise/application boundary, member identity, and provider errors.
- [x] 3.4 Implement identity lookup, first-login creation or binding, username collision handling, and email-as-non-key behavior.
- [x] 3.5 Ensure inactive, left, or out-of-scope WeCom identities are denied new Web login.

## 4. Web login-only enforcement

- [x] 4.1 Filter the Web login page so Enterprise WeCom login-only mode exposes only the WeCom sign-in path.
- [x] 4.2 Reject local Web password sign-in POSTs when Enterprise WeCom login-only mode is enabled.
- [x] 4.3 Disable local registration, OpenID Web sign-in/sign-up, Passkey Web sign-in, and non-WeCom OAuth2 Web sign-in when Enterprise WeCom login-only mode is enabled.
- [x] 4.4 Preserve single-provider auto-redirect behavior for the active WeCom login source.
- [x] 4.5 Keep Basic/token authentication behavior unchanged so Git HTTP token and API token use continue through existing paths.

## 5. Directory sync foundation and audit

- [x] 5.1 Implement minimum WeCom directory sync for visible members, departments, tags, and memberships behind sync settings.
- [x] 5.2 Make directory sync idempotent and scoped to the configured WeCom application-visible range.
- [x] 5.3 Add audit events for WeCom login success, login denial, identity binding, identity update, sync start, and sync finish.
- [x] 5.4 Ensure audit metadata never stores WeCom secrets, access tokens, authorization codes, or sensitive private profile fields.

## 6. Tests

- [x] 6.1 Add unit tests for Enterprise WeCom configuration defaults, validation, and secret URI handling.
- [x] 6.2 Add unit tests for WeCom callback state validation, member identity resolution, and denial cases.
- [x] 6.3 Add model or integration tests for WeCom identity binding uniqueness and first-login create/bind behavior.
- [x] 6.4 Add Web auth tests proving local password Web sign-in is rejected in login-only mode.
- [x] 6.5 Add Web auth tests proving registration, OpenID, Passkey, and non-WeCom OAuth2 Web paths are hidden or rejected in login-only mode.
- [x] 6.6 Add regression tests proving SSH key authentication path is not modified by Enterprise WeCom login-only mode.
- [x] 6.7 Add regression tests proving PAT/API token authentication path is not modified by Enterprise WeCom login-only mode.
- [x] 6.8 Add regression tests proving Git HTTP token authentication path is not modified by Enterprise WeCom login-only mode.
- [x] 6.9 Add audit tests for success, denial, and identity binding events without secret leakage.

## 7. Documentation and verification

- [x] 7.1 Update `custom/conf/app.example.ini` and related configuration documentation for `[enterprise.wecom]` and recommended Web login-only settings.
- [x] 7.2 Update `docs/enterprise-authz/implementation-plan.md` if implementation details diverge from the current plan.
- [x] 7.3 Run `make fmt` after Go edits.
- [x] 7.4 Run targeted Go tests for changed auth, model, and audit packages.
- [x] 7.5 Run template or frontend lint if Web templates or frontend assets are changed. (N/A: no Web templates or frontend assets changed.)
- [x] 7.6 Run `make generate-swagger` and swagger validation only if new or changed API endpoints are added. (N/A: no API endpoints added or changed.)
- [x] 7.7 Run `openspec validate wecom-only-web-login --strict` before applying or marking the change ready for implementation.

## 8. Pre-merge hardening

- [x] 8.1 Replace raw WeCom transport and callback errors with structured errors that cannot expose secrets, tokens, authorization codes, or request URLs.
- [x] 8.2 Add a configured WeCom login source name and enforce `ENABLED` plus exact-source matching in provider listing, login routes, callbacks, and service entry points.
- [x] 8.3 Add startup preflight for login-only mode and prevent runtime deletion, deactivation, renaming, or provider changes of the configured source.
- [x] 8.4 Register directory synchronization with the existing cron service and propagate cancellation into all WeCom HTTP requests.
- [x] 8.5 Cache WeCom access tokens in memory and reconcile directory snapshots transactionally without retaining stale memberships or active status for missing users.
- [x] 8.6 Add focused tests for error redaction, disabled-mode rejection, source preflight, source mutation protection, cron execution, cancellation, token reuse, and snapshot reconciliation.
- [x] 8.7 Update configuration and rollout documentation, run formatting and changed-area lint/tests, and validate the OpenSpec change.
