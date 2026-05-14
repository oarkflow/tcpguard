# TCPGuard Use Cases

TCPGuard is useful when security controls depend on request context, user identity, external state, business intent, and runtime history.

## API Abuse And Rate Limiting

TCPGuard can detect request rate abuse across IP, user, tenant, session, endpoint, IP+user, and tenant+endpoint dimensions. It supports fixed-window, sliding-window, and token-bucket algorithms.

Typical response actions:

- `throttle` for HTTP 429 responses.
- `delay` or `tarpit` for slowing abusive clients.
- `ban_ip` for temporary IP-level blocking.
- `create_incident` for operator visibility.

Example scenario: throttle public API clients after repeated requests from the same IP, while preserving risk evidence for audit.

## Bad IP And Threat Intel Blocking

File intel feeds and datasource lookups can enrich requests with threat intelligence. Rules can block known bad IPs, suspicious CIDR ranges, or glob-style matches.

Typical response actions:

- `block`
- `ban_ip`
- `notify_soc`
- `create_incident`

Example scenario: block a request from an IP listed in `intel/bad_ips.txt` and create an incident with the matched rule and finding evidence.

## Replay And MITM Protection

The built-in replay detector checks nonce reuse, timestamp skew, and HMAC signatures when the relevant headers are present.

Common headers:

- `X-TCPGuard-Nonce`
- `X-TCPGuard-Timestamp`
- `X-TCPGuard-Signature`
- `X-Signature`
- `X-API-Key`

Example scenario: allow the first signed transfer request, then block the second request when the same nonce is reused.

## Tenant Lockdown And Account Status

TCPGuard lookups can read tenant and user state from memory/cache, Redis, CSV, JSON, SQL, or HTTP services. Rules can challenge or block requests when a tenant is locked down, a user account is disabled, or an external risk score is too high.

Typical response actions:

- `mfa_challenge`
- `captcha_challenge`
- `reauthenticate`
- `lock_user`
- `block`

Example scenario: use a JSON tenant datasource to block all traffic for a locked tenant, while using a SQL account lookup to challenge locked users.

## Geo-Restricted Endpoints

`HTTPContextBuilder` can enrich network facts with country, region, city, latitude, and longitude from the client IP. When `TrustedProxyHeaders` is enabled, TCPGuard can derive the public client IP from forwarded headers.

Example scenario: allow `/geo-restricted` only for Nepal (`NP`) IPs and block other countries.

## Admin And Export Protection

Rules can scope to exact paths, wildcards, prefixes, and dynamic route templates. Sensitive routes such as admin APIs, export APIs, and permission-management endpoints can require stronger checks.

Useful context:

- `request.method`
- `request.path`
- `request.params`
- `user.role`
- `user.permissions`
- `tenant.id`
- `business.outside_hours`
- `device.new`

Example scenario: challenge an admin user who attempts a user-management operation after hours from a new device.

## High-Value Business Workflows

Derived triggers and business context let policies react to domain intent rather than only HTTP shape. Applications can extract fields such as business action, amount, entity, workflow, sensitivity, holiday, and outside-hours status.

Typical response actions:

- `mfa_challenge`
- `create_incident`
- `notify_admin`
- `notify_soc`
- `escalate_incident`

Example scenario: block or escalate a high-value payment approval attempted outside business hours.

## Session Drift And Impossible Travel

TCPGuard can evaluate session/device facts such as previous IP, previous country, current country, device changes, user-agent changes, and session age.

Example scenario: challenge a user when the session country changes unexpectedly or a high-risk action comes from a new device.

## Audit And Compliance Evidence

Every evaluation can produce audit records with matched rules, findings, action results, approvals, policy version, config hash, and a deterministic request fingerprint. Stores that implement audit persistence can create tamper-evident envelope chains.

Example scenario: verify that a production enforcement decision came from a specific policy version and that the audit chain was not modified.

## Safe Policy Rollout

Simulation and diff APIs make it possible to evaluate candidate policy changes before enforcing them.

Useful workflow:

- Validate a policy pack with the CLI.
- Simulate representative requests.
- Diff old and new packs against the same request fixtures.
- Publish through `ReloadableGuard`.
- Keep last-known-good behavior when a bad reload fails.
