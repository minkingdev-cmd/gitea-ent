## Context

See `proposal.md` for motivation and `specs/identity/wecom-web-login/spec.md` for behavior requirements.

The current Gitea fork already has OAuth2 login source plumbing, external login user binding, service-level login switches, Web login form rendering, and a single-provider OAuth2 auto-redirect path. The design should reuse those extension points where possible instead of replacing the full auth stack.

The central boundary is intentionally narrow: Enterprise WeCom owns Web sign-in and external user identity only. After a successful Web login, the local Gitea `user` remains the runtime subject. SSH key, PAT/API token, and Git HTTP token authentication continue through existing Gitea flows.

## Goals / Non-Goals

**Goals:**

- Add an Enterprise WeCom login source that can complete Web OAuth code login and resolve a WeCom `userid`.
- Persist a stable mapping from configured `corp_id + userid` to a Gitea user.
- Enforce login-only mode for Web sign-in without changing token or Git protocol authentication paths.
- Provide safe configuration defaults and secret indirection.
- Add audit events for WeCom Web login outcomes and identity binding changes.
- Add a minimum directory sync foundation for identity status and future authorization mapping.

**Non-Goals:**

- Do not replace Gitea's internal `user` table as the local subject.
- Do not change SSH key, PAT/API token, or Git HTTP token authentication semantics.
- Do not implement repo action overlay, feature grants, or merge gates in this change.
- Do not require Keycloak, OpenFGA, or an external policy decision point.
- Do not store Enterprise WeCom application secrets, access tokens, or sensitive profile fields in audit metadata.

## Decisions

### Decision 1: Implement a dedicated Enterprise WeCom login source

Use a dedicated WeCom provider/source rather than modeling WeCom as generic OIDC.

Rationale:

- WeCom Web OAuth code flow returns enterprise member identity such as `userid`; it is not guaranteed to behave like a standard OIDC discovery provider.
- Dedicated provider code allows explicit `corp_id`, `agent_id`, callback, and application-visible-scope validation.
- Gitea's existing OAuth2 source and external login binding concepts can still be reused for lifecycle and admin familiarity.

Alternatives considered:

- Generic OIDC source: smaller code change if an enterprise already has an OIDC gateway, but it does not directly express WeCom `userid`, corp boundary, or directory sync.
- Reverse proxy headers: low application code, but weaker audit and identity-binding guarantees unless a separate trusted gateway is fully specified.

### Decision 2: Add `[enterprise.wecom]` for enterprise mode behavior

Introduce explicit Enterprise WeCom settings rather than overloading existing OAuth2 client settings.

Key settings:

```ini
[enterprise.wecom]
ENABLED = false
CORP_ID =
AGENT_ID =
CORP_SECRET_URI =
LOGIN_ONLY = true
LOGIN_SOURCE_NAME = enterprise-wecom
AUTO_CREATE_USER = true
USERNAME_TEMPLATE = {userid}
SYNC_DEPARTMENTS = true
SYNC_TAGS = true
HTTP_TIMEOUT = 15s

[cron.sync_enterprise_wecom_directory]
ENABLED = true
RUN_AT_START = false
SCHEDULE = @every 10m
```

Rationale:

- Existing OAuth2 settings describe generic client behavior; Enterprise WeCom also controls login surface restrictions and optional directory sync.
- `CORP_SECRET_URI` keeps plaintext secret values out of repository configuration.
- Disabled-by-default preserves upstream behavior until the deployment opts in.

### Decision 3: Persist WeCom identity separately from optional directory snapshots

Create a primary WeCom identity binding model and separate optional sync snapshot models.

Core identity fields:

- Gitea `user_id`.
- WeCom `corp_id`.
- WeCom `userid`.
- Derived external ID such as `wecom:{corp_id}:{userid}`.
- status: `active`, `inactive`, `left`, or `out_of_scope`.
- last login and last sync timestamps.

Optional sync snapshots:

- departments;
- tags;
- member-to-department/tag membership.

Rationale:

- Identity binding is required for Web login.
- Directory sync is useful for future authorization mapping but should not be mandatory for a successful login flow.
- Keeping snapshots separate avoids overloading external login records with provider-specific data.

### Decision 4: Enforce Web-only login restrictions at both UI and handler levels

When Enterprise WeCom login-only mode is enabled:

- the login page should auto-redirect when a single WeCom source is active;
- password, registration, OpenID, Passkey, and non-WeCom OAuth2 Web entries should not be offered;
- direct POST or callback attempts for forbidden Web login methods must be rejected server-side.

Rationale:

- UI hiding alone is not sufficient for security.
- Server-side rejection makes direct endpoint access testable and auditable.
- Reusing existing sign-in switches keeps the change shallow, but Enterprise WeCom mode should apply a final guard so misconfiguration does not accidentally re-enable another Web sign-in path.

### Decision 5: Preserve SSH/PAT/Git HTTP token paths by not inserting WeCom checks there

Do not add WeCom OAuth calls or WeCom identity-status checks to SSH key, PAT/API token, or Git HTTP token authentication paths.

Rationale:

- The requested boundary is Web login and user identity only.
- Git/token credentials are operationally important for automation and should keep existing Gitea semantics.
- If a deployment wants stronger offboarding semantics later, that should be a separate policy change against Gitea account/token status, not an implicit side effect of WeCom login.

### Decision 6: Treat inactive WeCom identity as a Web login denial by default

If directory sync or callback validation marks a WeCom identity inactive, left, or out of application scope, deny new Web login for that identity. Do not automatically delete SSH keys, PATs, or Git HTTP tokens.

Rationale:

- This satisfies the Web login identity requirement while preserving token compatibility.
- Existing Gitea user/account status remains the authority for non-Web-login credential validity.

### Decision 7: Audit outcomes, not secrets

Add audit actions for:

- `enterprise:wecom:login:success`;
- `enterprise:wecom:login:deny`;
- `enterprise:wecom:identity:bind`;
- `enterprise:wecom:identity:update`;
- `enterprise:wecom:sync:start`;
- `enterprise:wecom:sync:finish`.

Audit metadata should include actor, target user, external identity reference, source, outcome, and reason. It must not include application secrets, access tokens, raw authorization codes, private profile fields, or sensitive directory data.

### Decision 8: Select one configured WeCom login source

Add `LOGIN_SOURCE_NAME` to `[enterprise.wecom]` and allow Web login only through the active OAuth2 source with that exact name and the `wecom` provider. Provider listing, direct login routes, callbacks, and the Enterprise WeCom service all enforce the same enabled state.

When `ENABLED=true` and `LOGIN_ONLY=true`, OAuth2 startup validates the configured source before the Web server starts accepting requests. Missing, inactive, invalid, or uninitializable sources fail startup. Canary mode (`LOGIN_ONLY=false`) logs the same problem without disabling the other Web login methods.

### Decision 9: Return structured safe errors at the WeCom client boundary

The WeCom HTTP client reports only operation names, HTTP status codes, and WeCom numeric error codes. It does not return or wrap transport errors containing request URLs because those URLs contain CorpSecret, access token, or authorization code query values. WeCom callback errors use fixed reason codes and localized user messages.

### Decision 10: Use the existing cron service for directory sync

Register `sync_enterprise_wecom_directory` with the existing Gitea cron service instead of maintaining an independent ticker. This reuses shutdown context propagation, administrator manual execution, run status, and the existing global task lock. The schedule is configured through `[cron.sync_enterprise_wecom_directory]`; `[enterprise.wecom].SYNC_INTERVAL` is removed to avoid duplicate schedule configuration.

## Risks / Trade-offs

- WeCom API mode differences → Start with internal/self-built application assumptions, isolate WeCom API calls behind a service interface, and document any required changes for third-party or delegated app modes.
- Misconfiguration could lock out Web admins → Keep Enterprise WeCom disabled by default, validate required config on startup, and allow emergency recovery through config rollback or offline CLI/DB operations rather than a Web password backdoor.
- Username collisions on first login → Use deterministic username derivation and conflict handling; never bind a WeCom identity to an existing local user unless the configured linking policy allows it.
- Directory API visibility may be narrower than expected → Treat sync as scoped to the WeCom application-visible range and surface out-of-scope identity status clearly.
- Web-only enforcement can accidentally affect token automation if placed too low in the auth stack → Keep login-only guards in Web sign-in routes/source listing and add regression tests for SSH/PAT/Git HTTP token paths.
- Storing too much WeCom profile data increases privacy exposure → Persist minimum identity and authorization-mapping fields only.

## Migration Plan

1. Add Enterprise WeCom configuration with disabled-by-default behavior.
2. Add DB migration for WeCom identity binding and optional sync snapshot tables.
3. Add WeCom provider/source and callback handling behind the disabled feature flag.
4. Add login-only Web guards and UI filtering.
5. Add audit events.
6. Add directory sync foundation if sync settings are enabled.
7. Add tests for Web login success/denial and unchanged SSH/PAT/Git HTTP token behavior.
8. Update `custom/conf/app.example.ini` and enterprise authorization documentation.

Rollback strategy:

- Disable `[enterprise.wecom].ENABLED` or `LOGIN_ONLY` to restore prior Web sign-in behavior.
- Keep identity tables in place; rollback does not need to delete persisted mappings.
- If callback or source setup fails at startup, fail closed for WeCom login while preserving non-WeCom behavior unless login-only mode was explicitly enabled.

## Implementation Assumptions

- The first implementation targets an internal self-built Enterprise WeCom application. Delegated or third-party application modes require a later compatibility change if deployment evidence demands them.
- First login auto-creates users by default when `AUTO_CREATE_USER=true`; deployments that require pre-created users can disable that setting.
