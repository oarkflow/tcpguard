# TCPGuard Versioning And Compatibility

## Policy Pack Versions

Every pack should set a version:

```bcl
pack "payments-security" {
  version "2026.05.13"
  mode enforce
}
```

The version is copied into decisions, audit records, explanations, and management output, which makes production decisions easier to trace.

## BCL Changes

Treat BCL syntax and block semantics as policy-facing API. When changing rules:

- validate the pack
- run policy assertions
- diff representative request fixtures
- deploy through `ReloadableGuard`
- keep old packs available for rollback

## Response Compatibility

Default middleware responses may evolve as decision details improve. APIs that need stable public error contracts should use `WithResponseRenderer` and own their response shape.

In enforce mode, a failed condition/risk/severity or enrichment pipeline now fails closed with a generic evaluation-error finding. This is a security behavior change for deployments that previously allowed requests after an evaluation error. Monitor, shadow, and dry-run modes report the same failure without blocking. Audit persistence errors are reported in the returned decision and do not change its effect.

## Store Compatibility

Store keys are implementation details unless documented as public integration points. If external systems read TCPGuard store keys directly, pin the TCPGuard version and test migrations with copied production-like state.

## Migration Flow

Recommended release flow:

1. Add or update policy assertions for the current behavior.
2. Upgrade TCPGuard in CI.
3. Run `go test ./...`.
4. Run `go run ./cmd/tcpguard validate`.
5. Run `go run ./cmd/tcpguard test -assert` for critical fixtures.
6. Run policy diffs for risky changes.
7. Deploy in monitor or shadow mode when changing high-impact policy.
8. Move to enforce after reviewing metrics and audit output.
