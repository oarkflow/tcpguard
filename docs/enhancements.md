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

### Further Policy Linting

`LintBundle` and `tcpguard lint` detect duplicate IDs, unknown actions and detectors, unknown lookup sources, missing fallbacks, broad scopes, and matching rules with different actions. Further static analysis can improve unreachable-rule and include-glob diagnostics.

### Authoring Tools

Add editor snippets, a generated BCL reference, and a larger example rule catalog for common security controls.

### Large-Pack Performance

`BenchmarkGuardEvaluateDynamicRulesByPackSize` measures dynamic-route packs with 10, 100, and 1,000 matching rules. Expression evaluation creates wrappers only for called functions, and the guard prepares one detached facts snapshot per request for reuse across rule, risk, and severity expressions. Identical dynamic route patterns share one index match and one parameter extraction per evaluation. Evidence deduplication uses a compact open-addressed hash set while retaining output order. Candidate deduplication uses a request-local bitset for policies up to 1,024 rules and a sparse set for larger policies. Synchronous expressions without function calls enforce their time budget with elapsed-time checks rather than allocating a timer context; expressions with function calls and sequence/store work retain deadline contexts. A compile-time recognized fast path evaluates simple conjunctions of `fact.path != ""` directly, avoiding BCL's per-evaluation source parse; its fact paths are pre-split at compile time. All other syntax continues through BCL. Tests compare the fast path to BCL for present, empty, missing, nil, and numeric values. On the Apple M2 Pro, the 1,000-rule case improved from the original 8.7–8.9 ms/op, 6.22 MB/op, and 36,133 allocs/op to 0.386–0.396 ms/op, 506 KB/op, and 1,137 allocs/op after the initial optimization. A subsequent 3-run sample measured 0.351–0.371 ms/op, 440 KB/op, and 1,127 allocs/op after path pre-splitting and evidence-slice preallocation. The 10-rule case measured 14.9–15.2 µs/op and 17.2 KB/op; the 100-rule case measured 46.5–49.4 µs/op and 64.7 KB/op. The benchmark SLO script currently permits up to 20 ms/op and 8 MB/op for 1,000 rules; profile additional workload shapes before tightening cross-machine limits.

### Deployment Templates

Add Docker Compose, Kubernetes, and sidecar-style deployment templates that pair TCPGuard with Redis and observability.

## Suggested Priority

1. Profile and reduce allocations in large rule packs.
2. Add OpenTelemetry exporter package.
3. Add provider-specific SIEM/event bus/notification executors.
4. Add authoring snippets and generated BCL reference.
5. Add deployment templates.

## Implemented enterprise extensibility layer

The project now implements the enterprise roadmap items that were not already present in the original package:

- Detector modules can be registered through `RegisterDetectorFactory` and loaded by BCL `detector` blocks.
- Built-in detector factories cover DSL, HTTP, abuse, rate, replay, header anomaly, sensitive endpoint, session drift, and business anomaly detectors.
- Policy linting is available through `tcpguard.LintBundle` and `tcpguard lint`.
- Decisions include a structured `trace` field with risk contributors and operator recommendations.
- The FH server example contains BCL-configured detector modules and a correlation/sequence rule for account-takeover chains.
- The FH server README documents every curl command, its purpose, expected headers, expected body shape, and response meaning.
