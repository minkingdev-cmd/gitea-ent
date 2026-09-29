## Why

Enterprise deployments need a single trusted Web identity source so repository ownership, team membership, audit records, and future authorization mapping can be tied to corporate identities. The current Gitea login surface allows local Web password, registration, OpenID, Passkey, and arbitrary OAuth2 paths; that creates inconsistent user identity and weakens enterprise offboarding and auditability.

This change introduces Enterprise WeCom as the only Web sign-in path and as the source of external user identity, while explicitly preserving existing SSH key, PAT, and Git HTTP token authentication behavior.

## What Changes

- Add Enterprise WeCom configuration for CorpID, AgentID, secret reference, login-only mode, auto user creation, and sync options.
- Add a WeCom Web OAuth login flow that resolves a WeCom `userid`, validates the configured enterprise/application boundary, and binds it to a Gitea user.
- Enforce Enterprise WeCom as the only Web login method when enabled:
  - hide or reject local Web password sign-in;
  - disable local registration;
  - disable OpenID Web sign-in/sign-up;
  - disable Passkey Web sign-in;
  - hide or reject non-WeCom OAuth2 Web sign-in sources.
- Keep Gitea's existing SSH key, PAT/API token, and Git HTTP token authentication mechanisms unchanged.
- Add WeCom identity persistence and audit events for login success, login denial, identity binding, and identity updates.
- Add WeCom department/tag/member sync foundations only as needed to support identity status and future authorization mapping; full repo authorization overlay is out of scope for this change.
- Add tests proving Web login is WeCom-only and Git/token authentication paths are not changed.

## Capabilities

### New Capabilities

- `identity/wecom-web-login`: Enterprise WeCom Web login, WeCom `userid` identity binding, Web-only login enforcement, and compatibility boundaries for SSH/PAT/Git HTTP token authentication.

### Modified Capabilities

- None. No existing OpenSpec capabilities are present in this repository yet.

## Impact

- Affected code areas:
  - `modules/setting` for `[enterprise.wecom]` configuration.
  - `models/auth`, `services/auth/source/oauth2`, and Web auth routers/templates for WeCom sign-in and login source filtering.
  - `models/user` or new `models/enterprisewecom` for WeCom identity binding.
  - `services/enterprisewecom` for WeCom API client, callback handling, identity binding, and optional sync foundation.
  - `models/audit` / `services/audit` for WeCom auth audit events.
  - Tests under existing auth, model, and integration test packages.
- Affected external systems:
  - Enterprise WeCom application configuration: CorpID, AgentID, trusted callback domain, and application secret.
  - WeCom APIs for OAuth code-to-user identity and, when sync is enabled, directory data within the application-visible scope.
- API impact:
  - Web callback endpoints for WeCom sign-in.
  - Optional admin/system endpoints for WeCom sync status and manual sync may be added; if added, swagger must be regenerated.
- Data impact:
  - New DB migration for WeCom identity binding and optional sync snapshot state.
- Compatibility:
  - **No breaking change** to SSH key authentication.
  - **No breaking change** to PAT/API token authentication.
  - **No breaking change** to Git HTTP token authentication.
  - Web sign-in behavior changes only when Enterprise WeCom login-only mode is enabled.
