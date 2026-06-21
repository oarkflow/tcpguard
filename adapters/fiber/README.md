# TCPGuard Fiber adapter

This optional module keeps Fiber out of TCPGuard's core dependency graph.

```go
import tcpguardfiber "github.com/oarkflow/tcpguard/adapters/fiber"

app.Use(tcpguardfiber.Middleware(guard))
```

The adapter converts Fiber's request into Go's standard `*http.Request`, calls
`guard.EvaluateHTTPRequest`, and maps an enforced response back to Fiber.
