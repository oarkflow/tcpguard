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

Use `examples/tcpguard_fh_server` for a complete anomaly-detection server with global and endpoint-specific rules.
