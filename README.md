# TCPGuard

A comprehensive, production-ready anomaly detection and mitigation system built in Go. TCPGuard provides advanced rule-based protection for web applications with support for global and route-specific rules, real-time metrics collection, IP geolocation, session tracking, and automated threat response.

## Features

- **🔧 Modular Architecture**: Interface-first design with pluggable components
- **📊 Real-time Metrics**: Comprehensive observability with Prometheus-style metrics and /metrics endpoint
- **🌍 IP Geolocation**: Built-in IP geolocation with caching and fallback support
- **🔄 Hot Config Reload**: Automatic configuration updates without restart
- **🛡️ Multi-layer Protection**: Global, endpoint-specific, and session-based rules
- **⚡ High Performance**: Optimized with caching and concurrent processing
- **🔍 Health Monitoring**: Built-in health checks for all components
- **📝 Structured Logging**: Comprehensive logging with console and file support
- **🧪 Comprehensive Testing**: Full test coverage with unit and integration tests
- **📧 Notification System**: Multi-channel notifications (webhook, Slack, email, log)
- **🔍 Enhanced MITM Detection**: Advanced indicators for man-in-the-middle attack detection

## Supported Rule Types

### Global Rules
- **DDoS Detection**: Rate-based attack detection with configurable thresholds
- **MITM Detection**: Man-in-the-middle attack detection with indicator-based analysis
- **Business Hours**: Time-based access control with timezone support
- **Business Region**: Geographic access control with IP geolocation

### Route-Specific Rules
- **Protected Routes**: Authentication-based route protection
- **Session Hijacking**: Multi-session monitoring and anomaly detection
- **Rate Limiting**: Endpoint-specific rate limiting

## Supported Actions

- **⚠️ Warning**: Log security events with configurable messages
- **⏱️ Rate Limit**: Apply rate limiting with burst control
- **🚫 Temporary Ban**: Time-based IP bans with automatic cleanup
- **🚫 Permanent Ban**: Permanent IP bans for severe violations
- **🔒 Restrict Access**: Conditional access restrictions

## Installation

```bash
go get github.com/oarkflow/tcpguard
```

## Quick Start

### 1. Basic Usage

```go
package main

import (
    "log"
    "time"

    "github.com/gofiber/fiber/v2"
    "github.com/oarkflow/tcpguard"
)

func main() {
    // Initialize components
    store := tcpguard.NewInMemoryCounterStore()
    rateLimiter := tcpguard.NewTokenBucketRateLimiter(100, time.Minute)
    metrics := tcpguard.NewInMemoryMetricsCollector()
    actionRegistry := tcpguard.NewActionHandlerRegistry()

    // Register pipeline functions
    pipelineReg := tcpguard.NewInMemoryPipelineFunctionRegistry()
    // ... register pipeline functions ...

    // Create rule engine
    ruleEngine, err := tcpguard.NewRuleEngine(
        "./configs",
        store,
        rateLimiter,
        actionRegistry,
        pipelineReg,
        metrics,
        tcpguard.NewDefaultConfigValidator(),
    )
    if err != nil {
        log.Fatal(err)
    }

    // Create Fiber app
    app := fiber.New()

    // Add anomaly detection middleware
    app.Use(ruleEngine.AnomalyDetectionMiddleware())

    // Your routes here
    app.Get("/api/protected", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{"message": "Protected endpoint"})
    })

    log.Fatal(app.Listen(":3000"))
}
```

### 2. Configuration Structure

Create the following directory structure:

```
configs/
├── global/
│   ├── ddos.json
│   └── mitm.json
├── rules/
│   ├── businessHours.json
│   ├── businessRegion.json
│   ├── protectedRoute.json
│   └── sessionHijacking.json
└── endpoints/
    ├── login.json
    ├── data-export.json
    └── status.json
```

#### Example Global Rule (ddos.json)

```json
{
    "name": "ddosDetection",
    "type": "ddos",
    "enabled": true,
    "priority": 100,
    "params": {
        "requestsPerMinute": 50
    },
    "actions": [
        {
            "type": "temporary_ban",
            "priority": 10,
            "duration": "10m",
            "trigger": {
                "threshold": 10,
                "within": "1m",
                "scope": "client",
                "key": "ddos_violations"
            },
            "response": {
                "status": 403,
                "message": "Temporary ban due to suspected DDoS activity."
            }
        }
    ]
}
```

#### Example Route Rule (protectedRoute.json)

```json
{
    "name": "protectedRouteCheck",
    "type": "protected_route",
    "enabled": true,
    "priority": 50,
    "params": {
        "endpoint": "/api/protected",
        "protectedRoutes": ["/api/admin", "/api/delete"],
        "loginCheckHeader": "Authorization"
    },
    "actions": [
        {
            "type": "restrict",
            "priority": 5,
            "response": {
                "status": 401,
                "message": "Authentication required for protected routes."
            }
        }
    ]
}
```

## Architecture

### Core Components

- **RuleEngine**: Central orchestration component
- **CounterStore**: Pluggable storage for counters and bans
- **RateLimiter**: Token bucket rate limiting implementation
- **MetricsCollector**: Real-time metrics collection
- **PipelineFunctionRegistry**: Extensible function registry for rule evaluation
- **ActionHandlerRegistry**: Pluggable action handlers

### Key Interfaces

```go
type CounterStore interface {
    IncrementGlobal(ip string) (count int, lastReset time.Time, err error)
    GetBan(ip string) (*BanInfo, error)
    SetBan(ip string, ban *BanInfo) error
    HealthCheck() error
}

type RateLimiter interface {
    Allow(key string) (allowed bool, remaining int, reset time.Time, err error)
    HealthCheck() error
}

type MetricsCollector interface {
    IncrementCounter(name string, labels map[string]string)
    ObserveHistogram(name string, value float64, labels map[string]string)
    SetGauge(name string, value float64, labels map[string]string)
    HealthCheck() error
}
```

## Health Monitoring

TCPGuard includes comprehensive health monitoring:

```bash
curl http://localhost:3000/health
```

Response:
```json
{
  "status": "ok",
  "timestamp": "2025-09-18T19:51:48+05:45",
  "services": {
    "store": {"status": "ok"},
    "metrics": {"status": "ok"},
    "rate_limiter": {"status": "ok"},
    "rule_engine": {"status": "ok"}
  }
}
```

## Hot Config Reload

TCPGuard automatically reloads configuration when files change:

```go
// Configuration is automatically watched and reloaded
// No manual intervention required
ruleEngine, err := tcpguard.NewRuleEngine("./configs", ...)
```

## Metrics Collection

Access real-time metrics:

```go
// Get counter value
count := metrics.GetCounterValue("anomaly_detected", map[string]string{
    "rule_type": "ddos",
})

// Get gauge value
value := metrics.GetGaugeValue("active_connections", 0, map[string]string{})
```

## Prometheus Metrics Export

Access Prometheus-compatible metrics:

```bash
curl http://localhost:3000/metrics
```

## Rule Management API

Inspect and reload rules dynamically:

```bash
# Get current rules
curl http://localhost:3000/api/rules

# Reload configuration
curl -X POST http://localhost:3000/api/rules/reload
```

## Persistent Storage

Use file-based storage for persistence:

```go
store, err := tcpguard.NewFileCounterStore("./data/store.json")
```

## IP Geolocation

Built-in IP geolocation with caching:

```go
country := ruleEngine.GetCountryFromIP("192.168.1.1", "US")
```

## Session Tracking

Advanced session monitoring:

```go
// Sessions are automatically tracked and validated
// Hijacking attempts are detected based on:
- User-Agent changes
- Concurrent session limits
- Session timeout validation
```

## Running the Example

```bash
cd examples
go run main.go
```

Test endpoints:

```bash
# Health check
curl http://localhost:3000/health

# Metrics (Prometheus format)
curl http://localhost:3000/metrics

# Protected endpoint (requires auth)
curl http://localhost:3000/api/protected

# Login endpoint
curl -X POST http://localhost:3000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"password"}'
```

## Recent Enhancements

- **Geolocation Caching**: IP to country lookups are now cached to improve performance and reduce external API calls
- **Enhanced MITM Detection**: Added checks for unexpected headers and anomalous request sizes
- **File Logging**: Logger now supports writing to files in addition to console output
- **Prometheus Metrics Export**: Added /metrics endpoint for Prometheus-compatible metrics collection
- **Separated Business Rules**: Business hours and business region rules are now distinct and independently configurable
- **Improved Email Notifications**: Enhanced email notification formatting and logging
- **Additional Pipeline Functions**: Added checkRequestMethod and other utility functions for advanced rule creation
- **Persistent Storage**: Added FileCounterStore for file-based persistence of counters and bans
- **Rule Management API**: Added /api/rules and /api/rules/reload endpoints for dynamic rule inspection and reloading

## Testing

Run the comprehensive test suite:

```bash
go test ./...
```

## Performance Features

- **Concurrent Processing**: Thread-safe operations with proper locking
- **Rule Caching**: Pre-sorted rules for optimal performance
- **Connection Pooling**: Efficient resource management
- **Memory Optimization**: TTL-based cleanup for expired data

## Security Features

- **Input Validation**: Comprehensive input sanitization
- **Rate Limiting**: Multi-layer rate limiting protection
- **IP Ban Management**: Automatic cleanup of expired bans and escalation to permanent bans on repeated offenses
- **Session Security**: Hijacking detection and prevention
- **Config Security**: File permission validation
- **Access Control Lists**: Global allow/deny CIDR lists with single-IP support
- **Proxy Trust Policy**: Optional trust of X-Forwarded-For when the immediate peer is within trusted proxy CIDRs

### Access Control and Proxy Trust

Add a global access control file at configs/global/access.json:

```json
{
  "rules": {},
  "allowCIDRs": ["127.0.0.1/32", "::1/128", "192.168.0.0/16"],
  "denyCIDRs": ["203.0.113.0/24"],
  "trustProxy": true,
  "trustedProxyCIDRs": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
  "banEscalation": { "tempThreshold": 3, "window": "24h" }
}
```

Behavior:
- If denyCIDRs matches client IP, request is rejected with 403 deny_list.
- If allowCIDRs is non-empty and client is not in it, request is rejected with 403 allow_list.
- If trustProxy is true and the immediate peer IP is within trustedProxyCIDRs, the first IP in X-Forwarded-For is used as the client IP.
- Temporary bans will escalate to permanent if tempThreshold bans occur within window.

## Extending TCPGuard

### Custom Pipeline Function

```go
pipelineReg.Register("customCheck", func(ctx *tcpguard.PipelineContext) any {
    // Your custom logic here
    return result
})
```

### Custom Action Handler

```go
type CustomAction struct{}

func (a *CustomAction) Handle(ctx context.Context, c *fiber.Ctx, action Action, meta ActionMeta, store CounterStore) error {
    // Your action logic here
    return nil
}
```

## Production Deployment

### Environment Variables

```bash
export PORT=8080
export CONFIG_DIR=./configs
export LOG_LEVEL=info
```

### Docker Deployment

```dockerfile
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o tcpguard ./examples

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/tcpguard .
COPY --from=builder /app/examples/configs ./configs
CMD ["./tcpguard"]
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 📖 [Documentation](docs/)
- 🐛 [Issue Tracker](https://github.com/oarkflow/tcpguard/issues)
- 💬 [Discussions](https://github.com/oarkflow/tcpguard/discussions)

---

**TCPGuard** - Advanced anomaly detection for modern web applications.
