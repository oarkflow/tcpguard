# TCPGuard

A robust, interface-first anomaly detection system built in Go. TCPGuard provides configurable rules-based anomaly detection for system metrics, application logs, and HTTP routes with predefined actions including warnings, rate limiting, and account bans.

## Features

- **Interface-First Design**: Clean, extensible architecture using Go interfaces
- **JSON Configuration**: Easy-to-configure rules and actions via JSON
- **Multiple Anomaly Types**: Support for system, application, and HTTP route anomalies
- **Jitter-Based Actions**: Randomized delays to prevent synchronized attacks
- **Hot Config Reloading**: Automatic configuration updates without restart
- **Thread-Safe**: Concurrent-safe processing with proper locking

## Supported Actions

- **Warning**: Log warnings with configurable jitter
- **Rate Limit**: Apply rate limiting with jitter
- **Restrict**: Restrict user access
- **Temporary Ban**: Time-based account bans with jitter
- **Permanent Ban**: Permanent account bans

## Supported Rules

- **Threshold Rules**: Numeric value comparisons (>, <, >=, <=, ==)
- **Pattern Rules**: Regex pattern matching on string fields

## Installation

```bash
go get github.com/example/tcpguard
```

## Quick Start

### 1. Create Configuration

Create a `config.json` file:

```json
{
  "rules": [
    {
      "type": "threshold",
      "name": "high_goroutines_rule",
      "config": {
        "field": "goroutines",
        "threshold": 80,
        "operator": ">"
      }
    },
    {
      "type": "pattern",
      "name": "suspicious_path_rule",
      "config": {
        "field": "path",
        "pattern": "^/admin"
      }
    }
  ],
  "actions": [
    {
      "type": "warning",
      "name": "high_goroutines",
      "config": {
        "base_delay": 1,
        "jitter_range": 500
      }
    },
    {
      "type": "rate_limit",
      "name": "suspicious_path",
      "config": {
        "base_delay": 5,
        "jitter_range": 2000
      }
    }
  ]
}
```

### 2. Basic Usage

```go
package main

import (
    "context"
    "log"
    "time"

    "github.com/example/tcpguard"
)

func main() {
    // Create guard instance
    guard, err := tcpguard.NewGuard("config.json")
    if err != nil {
        log.Fatal(err)
    }

    // Start config watcher for hot reloading
    ctx := context.Background()
    err = guard.StartConfigWatcher(ctx)
    if err != nil {
        log.Fatal(err)
    }

    // Process HTTP data
    httpData := tcpguard.HTTPData{
        Method:       "POST",
        Path:         "/admin/delete",
        UserID:       "user123",
        StatusCode:   403,
        ResponseTime: 6 * time.Second,
    }

    err = guard.Process(ctx, httpData)
    if err != nil {
        log.Printf("Processing error: %v", err)
    }
}
```

## Configuration

### Rules Configuration

#### Threshold Rule
```json
{
  "type": "threshold",
  "name": "cpu_usage_high",
  "config": {
    "field": "cpu_percent",
    "threshold": 90.0,
    "operator": ">"
  }
}
```

#### Pattern Rule
```json
{
  "type": "pattern",
  "name": "suspicious_user_agent",
  "config": {
    "field": "user_agent",
    "pattern": ".*bot.*"
  }
}
```

### Actions Configuration

#### Warning Action
```json
{
  "type": "warning",
  "name": "log_warning",
  "config": {
    "base_delay": 1,
    "jitter_range": 500
  }
}
```

#### Rate Limit Action
```json
{
  "type": "rate_limit",
  "name": "apply_rate_limit",
  "config": {
    "base_delay": 5,
    "jitter_range": 2000
  }
}
```

#### Temporary Ban Action
```json
{
  "type": "temp_ban",
  "name": "temp_ban_user",
  "config": {
    "base_duration": 10,
    "jitter_range": 2
  }
}
```

## Architecture

### Core Interfaces

- `AnomalyDetector`: Detects anomalies from input data
- `Rule`: Evaluates whether an anomaly matches criteria
- `Action`: Performs response actions on anomalies
- `Config`: JSON configuration structure

### Built-in Detectors

- **SystemDetector**: Monitors system-level metrics
- **HTTPDetector**: Analyzes HTTP request patterns

### Extending the System

#### Custom Detector
```go
type CustomDetector struct{}

func (d *CustomDetector) Name() string {
    return "custom"
}

func (d *CustomDetector) Detect(data interface{}) []tcpguard.Anomaly {
    // Your detection logic here
    return anomalies
}
```

#### Custom Rule
```go
type CustomRule struct {
    name string
}

func (r *CustomRule) Name() string {
    return r.name
}

func (r *CustomRule) Match(anomaly tcpguard.Anomaly) bool {
    // Your matching logic here
    return matches
}
```

#### Custom Action
```go
type CustomAction struct {
    name string
}

func (a *CustomAction) Name() string {
    return a.name
}

func (a *CustomAction) Execute(ctx context.Context, anomaly tcpguard.Anomaly) error {
    // Your action logic here
    return nil
}
```

## HTTP Data Structure

```go
type HTTPData struct {
    Method       string
    Path         string
    UserID       string
    StatusCode   int
    ResponseTime time.Duration
    UserAgent    string
    IPAddress    string
}
```

## Anomaly Structure

```go
type Anomaly struct {
    Type      string                 `json:"type"`
    Source    string                 `json:"source"`
    Severity  string                 `json:"severity"`
    Data      map[string]interface{} `json:"data"`
    Timestamp time.Time              `json:"timestamp"`
    UserID    string                 `json:"user_id,omitempty"`
}
```

## Running the Example

```bash
# Build the example
go build -o guard cmd/main.go

# Run with config
./guard
```

## Examples: try the rules locally

Start the HTTP guard (from the repo root):

```bash
go run ./cmd/main.go
```

HTTP examples (use separate terminals as needed):

# 1) Test route rate limit /api/
curl -i http://localhost:8080/api/
curl -i http://localhost:8080/api/
curl -i http://localhost:8080/api/   # repeated quickly should trigger rate limit rule

# 2) Test admin route header requirement (will be restricted without header)
curl -i http://localhost:8080/api/admin/
curl -i -H "X-Admin-Token: secret-token" http://localhost:8080/api/admin/

# 3) Test MITM detection heuristic for secure path (non-TLS request)
curl -i http://localhost:8080/secure/path

TCP examples (requires nc or telnet):

# Start a TCP client and connect repeatedly to trigger conn_rate
nc localhost 9000
# Open multiple concurrent connections: in several terminals run the above to exceed concurrent_conn threshold

Notes:
- The example `config.json` includes sample rules for global and route scopes, plus TCP rules under `tcp_rules`.
- Adjust thresholds in `config.json` to see actions trigger faster during testing.


## Testing

```bash
go test ./...
```

## License

MIT License

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request
