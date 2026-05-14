# TCPGuard Enhancements And Gaps

This document separates what TCPGuard already supports from high-value improvements that would make it easier to operate in production.

## Implemented

TCPGuard currently includes:

- Fiber v3 and `net/http` middleware.
- A runnable `examples/tcpguard_http_server` standard-library example.
- BCL policy loading from single files or directories.
- Built-in detectors for headers, sensitive endpoints, replay/HMAC, rate abuse, session drift, and business anomalies.
- Datasources and lookups for memory/cache, Redis, CSV, JSON, SQL, and HTTP-backed data.
- File threat intel, DSL detectors, HTTP detectors, baselines, derived triggers, and threat model decoration.
- Risk scoring, decision effects, action execution, incidents, approvals, audit envelopes, simulation, policy diffing, reload primitives, and CLI commands.
- Custom middleware response rendering.
- Metrics hooks plus an in-memory metrics recorder.
- CLI policy assertion files for effect, allowed, severity, risk range, matched rules, findings, and actions.
- Memory and Redis stores for core runtime state, approvals, incidents, and audit envelopes.
- Tests, benchmarks, and runnable policy-pack examples.

## New Supporting Guides

- [Production Guide](production.md): Redis, proxy headers, GeoIP behavior, reload strategy, policy safety, failure modes, and rollout patterns.
- [Security Hardening](security.md): HMAC secrets, webhook signing, redaction, command action safety, approvals, and credentials.
- [Versioning](versioning.md): BCL syntax, response behavior, stores, policy pack versions, and migration guidance.
- [Policy Authoring](authoring.md): pack layout, rule checklist, assertions, naming, and integration guidance.

## Remaining Enhancements

### OpenTelemetry Exporter

TCPGuard now has metrics hooks. A dedicated OpenTelemetry adapter package would make production wiring even faster by translating `MetricsRecorder` callbacks into instruments and spans.

### More Integration Executors

Webhook-compatible actions now run for notification, SIEM, and event-bus action types when an endpoint is configured. Provider-specific executors for Splunk, Kafka, NATS, SQS, Slack, Teams, and PagerDuty would still be useful.

### SQL And Command Action Packages

The built-in `sql` and `command` action types remain conservative by default. They should be expanded through opt-in executor packages that make datasource selection, parameter binding, command allowlists, and audit redaction explicit.

### Policy Linting

Policy assertions now cover expected decisions. A separate linter should detect unreachable rules, missing action definitions, broad scopes, risky fallbacks, and unused includes before runtime validation.

### Authoring Tools

Add editor snippets, a generated BCL reference, and a larger example rule catalog for common security controls.

### Deployment Templates

Add Docker Compose, Kubernetes, and sidecar-style deployment templates that pair TCPGuard with Redis and observability.

## Suggested Priority

1. Add OpenTelemetry exporter package.
2. Add provider-specific SIEM/event bus/notification executors.
3. Add policy linting.
4. Add authoring snippets and generated BCL reference.
5. Add deployment templates.
