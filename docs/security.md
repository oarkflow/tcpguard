# TCPGuard Security Hardening

## HMAC Secrets

Provide HMAC secrets through `WithHMACSecretProvider` and load them from a secrets manager or environment-specific secure storage. Rotate secrets by accepting both current and previous secrets during a short transition window in a custom detector or provider wrapper.

Signature version 2 binds the method, host, request URI, timestamp, nonce, and SHA-256 body hash. Clients select it with `X-TCPGuard-Signature-Version: 2`. Use a unique nonce and a short timestamp window. Set `policy_safety { require_signature true }` for deployments where every evaluated request must be signed; guard construction fails if no secret provider is configured.

The nonce store uses atomic `SetNX` when the configured store supports `AtomicSecurityStore`; the built-in memory and Redis stores do. Custom distributed stores should implement that optional interface or replay protection will use a compatibility read/write path that is not safe against concurrent duplicate requests.

## Webhooks And Outbound Actions

For webhook, SIEM, event bus, and notification actions:

- Use HTTPS endpoints.
- Add authentication headers from environment variables or a secret manager.
- Prefer short timeouts and low retry counts.
- Sign webhook payloads when the receiver supports it.
- Avoid sending full request bodies unless required.

## Audit Redaction

Audit records intentionally include decision evidence. Do not map secrets, tokens, raw credentials, or sensitive payload fields into TCPGuard facts unless they are redacted first.

Recommended pattern:

- Store request IDs, user IDs, tenant IDs, rule IDs, and finding IDs.
- Store hashes or classifications for sensitive values.
- Keep raw secrets out of `Context.Extra`, lookup outputs, action fields, and audit evidence.

## Command Actions

Command actions are disabled by default through `policy_safety`. Keep them disabled unless an explicit custom executor enforces:

- exact command allowlists
- argument validation
- bounded timeouts
- no shell interpolation
- full audit of command name and sanitized arguments

## Approvals

Use approvals for destructive actions such as broad bans, user locks, all-session revocation, and tenant-wide controls.

Good approval rules have:

- a narrow scope
- explicit approvers
- strong evidence in the explanation
- clear expiration or follow-up handling outside TCPGuard

## Datasource Credentials

Use `env("NAME")` for DSNs and tokens instead of hard-coding credentials in BCL. Scope credentials to read-only access wherever possible. SQL lookups should remain read-only `SELECT` queries.

## Proxy identity and network boundary

`TrustedProxyHeaders` must only be enabled when the immediate peer is a trusted reverse proxy. Prefer configuring `TrustedProxyCIDRs` as well:

```go
builder := tcpguard.HTTPContextBuilder{
    TrustedProxyHeaders: true,
    TrustedProxyCIDRs: []string{"10.0.0.0/8", "192.0.2.0/24"},
}
```

TCPGuard does not replace edge DDoS protection, TLS termination policy, connection limits, or packet-level spoof filtering.

Configure `MaxHeaderBytes`, `MaxHeaderCount`, `MaxURLBytes`, and `MaxBodyBytes` on `HTTPContextBuilder`. The middleware enforces the body limit before buffering the request; the other limits are emitted as `security.*` facts and can be blocked by policy.
