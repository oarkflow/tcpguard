# TCPGuard fh adapter

This optional adapter turns a `*tcpguard.Guard` into `github.com/oarkflow/fh` middleware.

```go
app := fh.New()
app.Use(tcpguardfh.Middleware(guard))
```

For production integrations use `MiddlewareWithConfig`:

```go
app.Use(tcpguardfh.MiddlewareWithConfig(tcpguardfh.Config{
    Guard: guard,
    Skip: func(c *fh.Ctx) bool { return c.OriginalURL() == "/healthz" },
    OnDecision: func(c *fh.Ctx, result tcpguard.HTTPRequestResult) {
        // emit structured logs, metrics, traces, or SOC events
    },
    ResponsePolicy: tcpguard.DefaultResponseMessagePolicy(tcpguard.EnvironmentProduction),
    OnError: func(c *fh.Ctx, err error) error {
        return c.Status(500).JSON(map[string]any{"error": "tcpguard_unavailable"})
    },
}))
```

The middleware converts the fh context into a framework-neutral `http.Request`, evaluates the request through TCPGuard, and either continues the fh chain or returns the TCPGuard decision response.

Response headers added by default:

- `X-TCPGuard-Risk`
- `X-TCPGuard-Decision`
- `X-TCPGuard-Severity`
- `X-TCPGuard-Trace`
- `X-TCPGuard-Message`

Use `examples/tcpguard_fh_server` for a complete anomaly-detection server with global and endpoint-specific rules.


## Environment-aware messages

Use `tcpguard.DefaultResponseMessagePolicy(env)` or configure a `response` block in BCL to control public explanation detail. Production responses keep messages readable while suppressing sensitive values, signatures, tokens, body payloads, datasource values, and rule internals. Development/test responses can include rule IDs and diagnostic fields for local debugging.

## Production-safe responses with detailed logs

Use `WithResponseRenderer` when the application needs a stable public error envelope. The recommended pattern is to wrap `tcpguard.PublicDecisionResponseRenderer(policy)` instead of serializing the raw `Decision`. That keeps production responses minimal, readable, and safe while preserving compatibility with custom API contracts.

Use `Config.OnDecision` for detailed production and development logging. `tcpguard.DecisionLogEntry(sec, decision, policy)` returns a structured SIEM-friendly map with rule IDs, finding/evidence categories, action results, policy version, config hash, request metadata, and audit envelope references. In production, raw sensitive values are redacted or hashed; in development/test, diagnostics can include more values according to `ResponseMessagePolicy`.

```go
policy := tcpguard.DefaultResponseMessagePolicy(tcpguard.EnvironmentProduction)

guard, _ := tcpguard.New(
    tcpguard.WithBundle(bundle),
    tcpguard.WithResponseMessagePolicy(policy),
    tcpguard.WithResponseRenderer(func(sec *tcpguard.Context, d tcpguard.Decision) tcpguard.DecisionResponse {
        return tcpguard.PublicDecisionResponseRenderer(policy)(sec, d)
    }),
)

app.Use(tcpguardfh.MiddlewareWithConfig(tcpguardfh.Config{
    Guard: guard,
    ResponsePolicy: policy,
    OnDecision: func(c *fh.Ctx, result tcpguard.HTTPRequestResult) {
        entry := tcpguard.DecisionLogEntry(result.Context, result.Decision, policy)
        // Send entry to slog, zap, zerolog, SIEM, OpenTelemetry logs, etc.
        _ = entry
    },
}))
```
