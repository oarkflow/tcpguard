# TCPGuard Production Hardening and Fully Configurable Policy DSL

## Summary

TCPGuard cannot honestly promise 100% security against every business, application, and security rule. The production target is secure-by-default behavior, defense in depth, fully configurable policies, strong validation, auditability, durable state, and repeatable readiness gates.

Current gaps identified in this repo:

- `go test ./...` failed because `examples/sql-config-example/migrate.go` and `examples/sql-config-example/main.go` both declared `main`; the migration utility must be isolated from normal package builds.
- `ConfigAPI` exposes create, update, and delete routes without built-in authentication, authorization, CSRF protection, rate limiting, or audit logging.
- `DefaultConfigValidator` only validates a small subset of configuration and does not deeply validate detector params, policy conditions, CIDRs, durations, action triggers, thresholds, or rule conflicts.
- The original policy engine supported only flat AND conditions with a small field/operator set and no schema-versioned DSL, nested boolean logic, dry-run mode, shadow mode, conflict detection, or rich explanations.
- Several production controls are examples or optional wiring rather than secure library defaults: auth chain, MFA/device trust, protected metrics and security routes, durable state, secret handling, audit trail, and config change controls.
- Runtime state defaults to in-memory stores, which is not enough for clustered production deployments.

## Phase 1: Production Readiness Baseline

- Keep `go test ./...` green on every change.
- Maintain a production-readiness checklist covering config validation, secure defaults, durable state, protected admin APIs, observability, audit events, and release gates.
- Replace absolute security claims in docs with measurable guarantees: validated configs, bounded scanning, fail-closed sensitive routes, tested policy decisions, and auditable changes.
- Add CI gates for `go test ./...`, targeted race tests, static checks, and example build verification.

## Phase 2: Policy DSL

- Use a schema-versioned declarative DSL for business, application, identity, detector, and response policies.
- Support nested `all`, `any`, and `not` conditions while preserving existing flat `conditions` compatibility.
- Support comparison, set, string, glob, regex, CIDR, existence, numeric range, request field, route tier, risk score, and detector signal matching.
- Return explainable verdicts with matched policy, default decision reason, evaluated condition tree, and policy version.
- Add dry-run and shadow/evaluate-only execution modes so operators can test policies before enforcement.
- Add conflict detection for duplicate policy IDs, impossible conditions, duplicate priorities in the same layer, and contradictory always-on allow/deny policies.

## Phase 3: Secure Runtime Configuration

- Harden `ConfigAPI` before using it in production:
  - require an admin auth middleware or signed admin token,
  - enforce RBAC for read/write/admin operations,
  - rate-limit config mutation endpoints,
  - add CSRF protection for browser-based admin flows,
  - emit audit events for every create, update, delete, and reload,
  - reject unsafe config changes unless validation passes.
- Add optimistic config versioning so concurrent operators cannot overwrite each other silently.
- Add validation-before-commit for file and SQL stores.
- Add safe error responses that do not leak secrets or filesystem paths.

Implemented baseline:

- `ConfigAPI` is deny-by-default unless configured with `WithConfigAPIAuthz`, `WithConfigAPIAdminToken`, `WithConfigAPIAuthorizer`, or the explicit example-only `WithConfigAPIUnsafePublicAccess`.
- `github.com/oarkflow/authz` is integrated for RBAC, ABAC, and ACL decisions through `WithConfigAPIAuthz`.
- Built-in config roles are available through `NewDefaultConfigAPIAuthzEngine`: `config_viewer`, `config_editor`, and `config_admin`.
- Default identity resolution trusts Fiber locals set by upstream middleware; header-based identity is isolated to `HeaderConfigAPIAuthzResolver` for demos and tests.
- Authz management routes are available under `/api/authz` and are protected by the same config authorization guard.
- Audit event details include authz decision metadata such as allow/deny state, reason, matched source, and trace when available.
- File and SQL config stores implement durable config version persistence through `VersionedConfigStore`.

## Phase 4: Durable State and Cluster Safety

- Define production `StateStore` requirements for rate counters, bans, sessions, revoked tokens, detector baselines, audit events, config versions, and policy snapshots.
- Provide or document shared-store adapters suitable for clustered deployments.
- Move detector baselines and action counters behind configurable durable/shared stores where local memory would create inconsistent enforcement.
- Add startup warnings when production-sensitive features run with in-memory state.

## Phase 5: Detector and Rule Config Coverage

- Make anomaly, DDoS, injection, breach, identity, business, and application rules consistently configurable.
- Add per-rule enablement, thresholds, severity, scope, exclusions, actions, telemetry mappings, and fail modes.
- Validate detector-specific params with actionable errors.
- Add migration examples from existing JSON rules to the policy DSL.

## Phase 6: Testing and Verification

- Add table-driven tests for DSL parsing, nested boolean logic, operators, signal lookups, route/user/device fields, and default decisions.
- Add negative config tests for invalid durations, invalid CIDRs, unsafe regex, unknown fields, unknown actions, bad thresholds, duplicate policy IDs, and conflicting rules.
- Add integration tests proving config mutation requires authorization, rejects invalid config, emits audit events, and preserves config versioning.
- Add regression tests for unauthenticated admin/config access, unsafe proxy headers, bypass attempts, malformed payloads, fail-closed sensitive routes, and durable state behavior.
- Run targeted race tests for shared state, detector baselines, policy reload, and action counters.

Implemented coverage:

- RBAC tests prove viewers can read, editors can mutate config rules, and only admins can manage authz routes.
- ACL tests cover explicit deny overriding RBAC allow and resource-specific ACL allow grants.
- ABAC tests cover policy denial from an untrusted source IP.
- Audit tests assert authz decision metadata is emitted.
- File and SQL tests assert config versions persist across new `ConfigAPI` instances.

## Acceptance Gates

- `go test ./...` passes.
- Core policy DSL tests pass.
- Security framework tests pass.
- Race tests pass for core stateful packages before release.
- Production docs avoid absolute “100% secure” claims and describe concrete threat-model boundaries.

## Residual Items

- `go test -race ./examples/security-framework` should be fixed separately. It currently fails because the example pentest subtests use one-second response budgets that time out under `-race`; the run does not report a Go data race.
