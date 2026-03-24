# Security Detectors

tcpguard provides three production-ready security detection engines that run as pipeline functions. Each can be configured via JSON rules and integrated into your Fiber v3 middleware pipeline.

## Table of Contents

- [Injection Detection](#injection-detection)
- [Breach Detection](#breach-detection)
- [Anomaly Detection](#anomaly-detection)
- [Configuration](#configuration)
- [Architecture](#architecture)

---

## Injection Detection

Scans incoming requests for injection attacks across 8 categories with 192+ built-in patterns.

### Attack Types

| Type | Patterns | Default Severity | Description |
|------|----------|-----------------|-------------|
| `sql_injection` | 46 | critical | SQL injection via query params, body, headers |
| `xss` | 37 | high | Cross-site scripting via `<script>`, event handlers, etc. |
| `command_injection` | 28 | critical | OS command injection via `;`, `|`, backticks |
| `path_traversal` | 19 | high | Directory traversal via `../`, encoded variants |
| `ldap_injection` | 11 | high | LDAP filter injection via `*`, `)(`, etc. |
| `nosql_injection` | 21 | high | MongoDB/NoSQL operator injection (`$ne`, `$gt`, etc.) |
| `template_injection` | 18 | high | Server-side template injection (`{{`, `${`, `<%`) |
| `header_injection` | 12 | medium | HTTP header injection via CRLF, `Set-Cookie` injection |

### Input Normalization

All inputs are automatically:
- Double URL-decoded (catches `%252e%252e%252f` -> `../`)
- HTML entity decoded (`&amp;` -> `&`)
- Whitespace-collapsed (multiple spaces -> single space)
- Lowercased for pattern matching

### Scan Targets

Configurable via `scanTargets`:
- `query` - URL query parameters
- `body` - Request body (up to `maxBodyScan` bytes)
- `headers` - HTTP headers (excluding standard safe headers)
- `path` - URL path
- `cookies` - Cookie header values

### Configuration

```json
{
    "name": "injectionDetection",
    "type": "pipeline",
    "enabled": true,
    "priority": 95,
    "pipeline": {
        "nodes": [{
            "id": "detect_injection",
            "type": "condition",
            "function": "injection",
            "params": {
                "scanTargets": ["query", "body", "headers", "path", "cookies"],
                "maxBodyScan": 65536,
                "allowlist": ["/api/health", "/api/docs/*"],
                "types": {
                    "sql_injection": { "enabled": true, "severity": "critical" },
                    "xss": { "enabled": true, "severity": "high" },
                    "command_injection": { "enabled": true, "severity": "critical" },
                    "path_traversal": { "enabled": true, "severity": "high" },
                    "ldap_injection": { "enabled": true },
                    "nosql_injection": { "enabled": true },
                    "template_injection": { "enabled": true },
                    "header_injection": { "enabled": true, "severity": "medium" }
                },
                "customRules": [
                    {
                        "name": "custom_pattern",
                        "pattern": "evil_keyword",
                        "type": "custom",
                        "severity": "high",
                        "location": "body"
                    }
                ]
            }
        }],
        "edges": []
    },
    "actions": [{
        "type": "temporary_ban",
        "duration": "15m",
        "response": { "status": 403, "message": "Injection attack detected." }
    }]
}
```

### Parameters Reference

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scanTargets` | `[]string` | `["query","body","headers","path","cookies"]` | Which parts of the request to scan |
| `maxBodyScan` | `int` | `65536` | Maximum body bytes to scan |
| `allowlist` | `[]string` | `[]` | Paths to skip (supports `*` wildcard suffix) |
| `types` | `map` | all enabled | Per-type config (enable/disable, severity, extra patterns) |
| `customRules` | `[]object` | `[]` | User-defined patterns with name, pattern, type, severity, location |

---

## Breach Detection

Detects ongoing security breaches and compromise indicators across 6 categories with stateful tracking.

### Detection Categories

| Type | Description |
|------|-------------|
| `data_exfiltration` | Large data transfers, bulk endpoint access, unusual download volumes |
| `credential_stuffing` | High-volume failed logins, username spraying, automated login attempts |
| `account_takeover` | Failed login bursts per account, impossible geo-velocity, post-failure access |
| `lateral_movement` | Multiple accounts from same IP, single user from many IPs in short window |
| `privilege_escalation` | Access to sensitive endpoints after repeated 403s, permission probing |
| `insider_threat` | Off-hours access, bulk data operations, access to scope-sensitive endpoints |

### State Tracking

The breach detector maintains per-`RuleEngine` state:
- **Response tracker**: Cumulative bytes, request counts, endpoint lists per IP
- **Login tracker**: Success/failure counts, unique usernames, timestamps per IP
- **User-IP mapping**: Bidirectional user-to-IP associations with timestamps
- **Access patterns**: Per-user endpoint access history with status codes

State is automatically cleaned up via background goroutines.

### Configuration

```json
{
    "name": "breachDetection",
    "type": "pipeline",
    "enabled": true,
    "priority": 90,
    "pipeline": {
        "nodes": [{
            "id": "detect_breach",
            "type": "condition",
            "function": "breach",
            "params": {
                "detectors": {
                    "data_exfiltration": { "enabled": true, "severity": "critical" },
                    "credential_stuffing": { "enabled": true, "severity": "critical" },
                    "account_takeover": { "enabled": true, "severity": "critical" },
                    "lateral_movement": { "enabled": true, "severity": "high" },
                    "privilege_escalation": { "enabled": true, "severity": "critical" },
                    "insider_threat": { "enabled": true, "severity": "high" }
                },
                "dataExfiltration": {
                    "maxResponseBytes": 52428800,
                    "window": "10m",
                    "bulkAccessThreshold": 30
                },
                "credentialStuffing": {
                    "window": "5m",
                    "maxFailedLogins": 20,
                    "uniqueUsernameRatio": 0.8,
                    "minAttempts": 5
                },
                "accountTakeover": {
                    "failureThreshold": 5,
                    "geoVelocityKmh": 500,
                    "mfaRequired": false,
                    "window": "15m"
                },
                "lateralMovement": {
                    "maxAccountsPerIP": 3,
                    "maxIPsPerUser": 5,
                    "window": "30m"
                },
                "privilegeEscalation": {
                    "sensitiveEndpoints": ["/admin", "/api/admin/*"],
                    "escalationWindow": "10m",
                    "max403Before200": 5
                },
                "insiderThreat": {
                    "normalHoursStart": 8,
                    "normalHoursEnd": 20,
                    "bulkThreshold": 100,
                    "scopePatterns": ["/api/export/*", "/api/bulk/*"],
                    "window": "1h"
                }
            }
        }],
        "edges": []
    },
    "actions": [{
        "type": "temporary_ban",
        "duration": "30m",
        "response": { "status": 403, "message": "Suspicious activity detected." }
    }]
}
```

### Parameters Reference

**Data Exfiltration**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `maxResponseBytes` | `int64` | `52428800` (50MB) | Cumulative response size threshold |
| `window` | `string` | `"10m"` | Time window for tracking |
| `bulkAccessThreshold` | `int` | `30` | Distinct endpoints in window before alert |

**Credential Stuffing**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `maxFailedLogins` | `int` | `20` | Failed login threshold |
| `uniqueUsernameRatio` | `float64` | `0.8` | Ratio of unique usernames (spray detection) |
| `minAttempts` | `int` | `5` | Minimum attempts before evaluating |
| `window` | `string` | `"5m"` | Time window |

**Account Takeover**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `failureThreshold` | `int` | `5` | Failed login count per account |
| `geoVelocityKmh` | `int` | `500` | Impossible travel speed threshold |
| `mfaRequired` | `bool` | `false` | Whether to flag missing MFA |
| `window` | `string` | `"15m"` | Time window |

**Lateral Movement**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `maxAccountsPerIP` | `int` | `3` | Max accounts from one IP |
| `maxIPsPerUser` | `int` | `5` | Max IPs for one user |
| `window` | `string` | `"30m"` | Time window |

**Privilege Escalation**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `sensitiveEndpoints` | `[]string` | `["/admin","/api/admin/*"...]` | Endpoints to monitor |
| `escalationWindow` | `string` | `"10m"` | Evaluation window |
| `max403Before200` | `int` | `5` | 403 responses before a 200 triggers alert |

**Insider Threat**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `normalHoursStart` | `int` | `8` | Start of normal hours (0-23) |
| `normalHoursEnd` | `int` | `20` | End of normal hours (0-23) |
| `bulkThreshold` | `int` | `100` | Bulk operation count threshold |
| `scopePatterns` | `[]string` | `["/api/export/*"...]` | Sensitive scope patterns |
| `window` | `string` | `"1h"` | Time window |

### Risk Scoring Integration

The breach detector provides 3 signal providers for the RiskScorer:
- `BreachExfiltrationSignal` - data exfiltration risk score
- `BreachCredentialStuffingSignal` - credential stuffing risk score
- `BreachAccountTakeoverSignal` - account takeover risk score

---

## Anomaly Detection

ML-inspired behavioral anomaly detection using statistical baselines. Learns normal behavior per IP and flags deviations.

### Detection Types

| Type | Description |
|------|-------------|
| `rate_anomaly` | Request rate deviates significantly from baseline |
| `payload_entropy` | Request body entropy is abnormally high (encrypted/compressed) or low |
| `geo_anomaly` | Client appears from multiple countries in short window |
| `temporal_anomaly` | Requests during unusual hours for this client |
| `behavioral_drift` | Path/method/user-agent patterns diverge from established baseline |
| `error_rate_anomaly` | Client error rate (4xx/5xx) deviates from baseline |
| `response_anomaly` | Response sizes deviate significantly from baseline |

### How It Works

1. **Baseline Learning**: For each client IP, the detector builds a statistical baseline using `RollingStats` (Welford's online algorithm for mean/variance).
2. **Z-Score Detection**: New observations are compared against the baseline. Values exceeding the z-score threshold (adjusted by sensitivity) are flagged.
3. **Shannon Entropy**: Payload entropy is calculated to detect encrypted/obfuscated payloads.
4. **Jaccard Similarity**: Behavioral drift is measured by comparing current path/method/UA sets against historical sets.

### Sensitivity Levels

| Level | Multiplier | Effect |
|-------|-----------|--------|
| `low` | 1.5x | Wider thresholds, fewer false positives |
| `medium` | 1.0x | Balanced (default) |
| `high` | 0.6x | Tighter thresholds, more sensitive |

### Configuration

```json
{
    "name": "anomalyDetection",
    "type": "pipeline",
    "enabled": true,
    "priority": 85,
    "pipeline": {
        "nodes": [{
            "id": "detect_anomaly",
            "type": "condition",
            "function": "anomaly",
            "params": {
                "baselineWindow": "1h",
                "sensitivityLevel": "medium",
                "minSamples": 10,
                "detectors": {
                    "rate_anomaly": {
                        "enabled": true,
                        "severity": "medium",
                        "thresholds": { "zScoreThreshold": 3.0 }
                    },
                    "payload_entropy": {
                        "enabled": true,
                        "thresholds": { "maxEntropy": 7.5, "minEntropy": 0.5 }
                    },
                    "geo_anomaly": {
                        "enabled": true,
                        "severity": "high",
                        "thresholds": { "maxCountriesPerHour": 3 }
                    },
                    "temporal_anomaly": {
                        "enabled": true,
                        "thresholds": { "hourDeviationThreshold": 3.0 }
                    },
                    "behavioral_drift": {
                        "enabled": true,
                        "thresholds": { "minSimilarity": 0.3 }
                    },
                    "error_rate_anomaly": {
                        "enabled": true,
                        "thresholds": { "zScoreThreshold": 3.0 }
                    },
                    "response_anomaly": {
                        "enabled": true,
                        "thresholds": { "zScoreThreshold": 3.0 }
                    }
                }
            }
        }],
        "edges": []
    },
    "actions": [{
        "type": "rate_limit",
        "limit": "30 rpm",
        "response": { "status": 429, "message": "Anomalous traffic pattern detected." }
    }]
}
```

### Parameters Reference

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `baselineWindow` | `string` | `"1h"` | Time window for baseline data retention |
| `sensitivityLevel` | `string` | `"medium"` | `low`, `medium`, or `high` |
| `minSamples` | `int` | `10` | Minimum observations before anomaly detection activates |
| `detectors` | `map` | all enabled | Per-detector config (enable/disable, severity, thresholds) |

### Risk Scoring Integration

The anomaly detector provides `AnomalyScoreSignalProvider` for the RiskScorer, which returns the aggregate anomaly score as a risk signal.

---

## Configuration

### Standalone Rule Files

Place individual rule configs in the config directory:

```
configs/
  global/
    ddos.json        # DDoS detection
    mitm.json        # MITM detection
    injection.json   # Injection detection
    breach.json      # Breach detection
    anomaly.json     # Anomaly detection
  rules/
    sessionHijacking.json
    businessHours.json
    ...
  endpoints/
    login.json
    ...
```

Load with:

```go
engine := tcpguard.New(tcpguard.Config{
    ConfigDir: "./configs",
})
```

### Unified Config

Or include all rules in a single `config.json`:

```go
engine := tcpguard.New(tcpguard.Config{
    ConfigPath: "./config.json",
})
```

See `examples/config.json` for the full unified configuration.

### Hot Reload

Config changes are automatically picked up via filesystem watcher (fsnotify). No restart required.

---

## Architecture

### Pipeline Integration

All three detectors register as pipeline functions:

```
"injection" -> InjectionDetectionCondition(ctx *Context) any
"breach"    -> BreachDetectionCondition(ctx *Context) any
"anomaly"   -> AnomalyDetectionCondition(ctx *Context) any
```

They are registered in `builtin_pipeline.go` alongside existing functions like `ddos`, `mitm`, `checkSessionHijacking`, etc.

### Verdict Flow

Each detector returns a verdict struct that is stored in `ctx.Results`:

- `InjectionDetectionVerdict` - `.Triggered`, `.Findings[]`
- `BreachDetectionVerdict` - `.Triggered`, `.Findings[]`
- `AnomalyDetectionVerdict` - `.Triggered`, `.Findings[]`, `.AnomalyScore`

When `.Triggered` is `true`, the pipeline marks the context as triggered and configured actions execute.

### Event Emission

High/critical findings are automatically emitted as `SecurityEvent` through the `EventEmitter`, enabling:
- Real-time monitoring
- Correlation with other security events
- Incident response automation via the `CorrelationEngine`

### Priority Ordering

Recommended priority ordering (higher = evaluated first):

| Priority | Detector |
|----------|----------|
| 100 | DDoS Detection |
| 95 | Injection Detection |
| 90 | Breach Detection |
| 85 | Anomaly Detection |
| 80 | Session Hijacking / Custom Rules |

### Disabling Specific Detectors

To disable a specific sub-detector without disabling the whole engine:

```json
{
    "types": {
        "ldap_injection": { "enabled": false }
    }
}
```

```json
{
    "detectors": {
        "insider_threat": { "enabled": false }
    }
}
```

### Adding Custom Injection Patterns

```json
{
    "customRules": [
        {
            "name": "internal_api_probe",
            "pattern": "/internal/",
            "type": "custom",
            "severity": "high",
            "location": "path"
        }
    ]
}
```

Or extend built-in types with extra patterns:

```json
{
    "types": {
        "sql_injection": {
            "patterns": ["custom_sql_keyword", "proprietary_function("]
        }
    }
}
```
