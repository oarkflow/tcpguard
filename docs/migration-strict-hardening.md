# Migration Guide: Strict Hardening Defaults

This release intentionally tightens defaults and may break previously permissive configurations.

## Management Server

- `ManagementServer` is non-operational without auth configuration.
- Use `NewManagementServer(...)` with:
  - `AuthProvider`
  - `Authorizer`
  - optional `AllowedCIDRs`, body limits, and rate limits.

## Outbound URL Policy

- Private/loopback outbound URLs are blocked by default for:
  - HTTP datasources
  - webhook-like actions
- To allow internal endpoints, set `allow_private_url true` in BCL for the relevant action or datasource.

## Action Status Policy Validation

- `success_codes` and `retry_on_codes` are now validated at guard construction.
- Valid values:
  - exact status codes: `"200"`, `"409"`
  - ranges: `"500-599"`
  - classes: `"2xx"`, `"4xx"`, `"5xx"`
- Invalid tokens now fail guard creation.

## Env/Context/Session Optional Defaults

Supported forms now include optional defaults:

- `env("NAME")` and `env("NAME", "default")`
- `context("path")` and `context("path", "default")`
- `session("path")` and `session("path", "default")`

Malformed calls (empty/too many args) are treated as invalid and rejected by strict validation paths.

## Retention Defaults

- `RedisStore` now resolves partial retention configs against secure defaults.
- If only one retention field is set, remaining fields still use defaults instead of zero/unbounded behavior.
