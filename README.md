# TCPGuard

TCPGuard is an HTTP application-security and abuse-prevention policy engine for Go services. It sits in front of Fiber v3 or `net/http` handlers, builds a security context for each request, evaluates BCL policies, scores risk, runs detectors, executes response actions, and records audit evidence. It protects application traffic from spam, credential abuse, replay, API-key theft, session anomalies, probing, and authorization misuse.

TCPGuard is not a packet firewall or volumetric DDoS system. Put a CDN/WAF, DDoS provider, load balancer, or API gateway in front of it for SYN floods, connection exhaustion, TLS attacks, and network-layer filtering; use TCPGuard for identity-, tenant-, endpoint-, and business-aware enforcement.

Use it when application security logic has outgrown scattered middleware and hard-coded `if` statements. TCPGuard lets teams describe controls such as rate abuse, bad IP blocking, replay protection, tenant lockdowns, sensitive endpoint rules, approval gates, and high-value business workflows as policy packs that can be validated, simulated, reloaded, and audited.

## What It Does

- **Inline enforcement for Go apps** through Fiber v3 middleware or `net/http` middleware.
- **BCL policy packs** with `pack`, `guard`, `rule`, `trigger`, `action`, `datasource`, `lookup`, `detector`, `intel`, `baseline`, `threat_model`, and `policy_safety` blocks.
- **Rich request context** covering request, network, user, tenant, session, device, business, runtime, security, rate, and custom facts.
- **Built-in detectors** for header anomalies, sensitive endpoints, nonce/signature replay checks, rate abuse, session drift, and business anomalies.
- **Modern request hardening** with atomic distributed nonce consumption, trusted-proxy CIDR boundaries, and versioned HMAC request signing.
- **Risk-based decisions** including allow, monitor, challenge, throttle, block, revoke, and escalate.
- **Action orchestration** for blocking, throttling, challenges, bans, locks, incidents, notifications, webhooks, and custom executors.
- **Action reliability controls** with explicit success status policies, retry-on-status behavior, jittered backoff, and idempotency headers.
- **External data access** through memory/cache, Redis, CSV, JSON, SQL, and HTTP datasources.
- **Cached file datasources** with indexed CSV/JSON lookup snapshots and checksum-based refresh.
- **Threat intel and enrichment** from file feeds, lookup enrichers, baselines, and threat model decoration.
- **Approval workflows** that can hold destructive actions until an authorized reviewer approves them.
- **Tamper-evident audit** with deterministic request fingerprints and verifiable audit envelope chains.
- **Environment-aware enforcement responses** with readable allow/deny/challenge reasons, safe production redaction, request IDs, public details, and pluggable status codes, headers, and JSON bodies.
- **Metrics hooks** for decisions, detectors, actions, and reloads, including an in-memory recorder for local use.
- **Simulation and reloads** through APIs, a hardened management server, and the `cmd/tcpguard` CLI.
- **Secure management plane** via `NewManagementServer(...)` with auth chain, route RBAC, CIDR allowlists, body limits, and request timeouts.
- **Local and distributed stores** with `MemoryStore` for local/test use and `RedisStore` for distributed runtime state, approvals, incidents, and audit envelopes, with retention and capped indexes.

See [Decision Engine Contracts](docs/decision-engine.md) for rule ordering, effect selection, and evaluation failure behavior.

For production, use `RedisStore`, configure `TrustedProxyCIDRs` when forwarded headers are accepted, require signatures for machine-to-machine endpoints, and integrate real CAPTCHA/MFA/mTLS providers through custom executors or the edge gateway.

## Quick Start

Install/import the module:

```sh
go get github.com/oarkflow/tcpguard
```

Load a policy pack and attach TCPGuard to a Fiber v3 app:

```go
package main

import (
    "context"
    "log"

    "github.com/gofiber/fiber/v3"
    "github.com/oarkflow/tcpguard"
    tcpguardfiber "github.com/oarkflow/tcpguard/adapters/fiber"
)

func main() {
    ctx := context.Background()

    bundle, err := tcpguard.LoadTCPGuardBundleDir(ctx, "./policy")
    if err != nil {
        log.Fatal(err)
    }

    guard, err := tcpguard.New(
        tcpguard.WithBundle(bundle),
        tcpguard.WithMode(tcpguard.Enforce),
    )
    if err != nil {
        log.Fatal(err)
    }

    app := fiber.New()
    app.Use(tcpguardfiber.Middleware(guard))
    log.Fatal(app.Listen(":8080"))
}
```

For `net/http`, wrap an existing handler:

```go
protected := guard.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.WriteHeader(http.StatusOK)
    _, _ = w.Write([]byte("ok"))
}))

log.Fatal(http.ListenAndServe(":8080", protected))
```

For frameworks that expose a `*http.Request` (including Echo), use
`guard.EvaluateHTTPRequest(r)` when a native `http.Handler` wrapper is not the
right fit. The result contains the security context, decision, enforcement
state, and the framework-neutral response to write when enforcement applies.

## AuthZ policies, roles, ACLs, and memberships

TCPGuard can enforce a complete `oarkflow/authz` DSL file for every HTTP
request. Reference it from the guard configuration and enable route
enforcement:

```bcl
guard "tcpguard-main" {
  mode enforce
  authz {
    file "./access.authz"
    enforce_http true
    timeout 25ms
    error_policy deny
  }
}
```

The referenced `.authz` file supports AuthZ's native block and compact syntax,
including `tenant`, `policy`, `role`, `acl`, `members`, role inheritance,
owner conditions, tenant hierarchy, and `engine` settings. Subject IDs are
passed to AuthZ exactly as extracted, so a membership for `user:alice` should
use `user:alice` as the TCPGuard identity ID.

TCPGuard builds route resources as `route:<METHOD>:<path>`. Configure identity
and tenant extraction with `HTTPContextBuilder`, then use the normal `net/http`
or optional Fiber middleware. `OarkflowAuthzProvider.Engine()` exposes the
configured engine when runtime updates through AuthZ's Engine API are needed.

## Minimal Policy

TCPGuard policies are written in BCL. A small policy can block a sensitive endpoint when the request comes from a missing or suspicious user agent:

```bcl
pack "example-security-pack" {
  version "1.0.0"
  mode enforce
}

guard "tcpguard-main" {
  mode enforce
  version "2026.05.13"
}

rule "protect-admin" {
  scope {
    methods ["GET", "POST"]
    paths ["/admin/*"]
  }

  trigger {
    on request.received
  }

  when {
    any {
      request.user_agent equals ""
      request.user_agent contains "sqlmap"
    }
  }

  risk {
    base 90
  }

  actions {
    critical {
      run block
      run create_incident
    }
  }
}
```

Policies can be kept in one file or split across a directory with `include` globs:

```bcl
guard "tcpguard-main" {
  include "./actions/*.bcl"
  include "./triggers/*.bcl"
  include "./intel/*.bcl"
  include "./rules/*/*.bcl"
}
```

## Abuse Detection

TCPGuard includes an opt-in abuse detector for application, API, auth, function, admin, export, and payment abuse patterns. In BCL, this block:

```bcl
detector "abuse" {
  type abuse
  window 10m
  auth_ip_failure_threshold 3
  auth_user_failure_threshold 3
  password_spray_user_threshold 3
  api_key_ip_threshold 2
  api_key_user_threshold 2
  scan_path_threshold 4
  export_threshold 2
  function_invoke_threshold 3
  user_agent_rotation_threshold 3
  tenant_user_threshold 4
  account_enumeration_threshold 3
  large_body_threshold 1048576
  payment_user_amount_threshold 200000
  payment_tenant_amount_threshold 500000
  profile_risk_threshold 70
}
```

means: instantiate the built-in Go `tcpguard.AbuseDetector` for this policy pack. It is not a magic external service; `type abuse` is mapped by `WithBundle(...)` to `NewAbuseDetector(store)` and the fields above configure that detector. The detector uses the configured `SecurityStore` to keep short-window counters and distinct sets. Use Redis in multi-instance production so every process sees the same abuse state.

The same detector can be registered directly in Go:

```go
store := tcpguard.NewMemoryStore()
abuse := tcpguard.NewAbuseDetector(store)
abuse.Window = 10 * time.Minute
abuse.AuthIPFailureThreshold = 20

guard, err := tcpguard.New(
    tcpguard.WithStore(store),
    tcpguard.WithDetector(abuse),
)
```

### Abuse Parameters

| BCL parameter | Go field | Default | What it controls |
| --- | --- | ---: | --- |
| `window` | `Window` | `10m` | TTL/window for abuse counters, distinct sets, and amount totals. |
| `auth_ip_failure_threshold` | `AuthIPFailureThreshold` | `20` | Failed auth attempts from one IP before `credential_stuffing`. |
| `auth_user_failure_threshold` | `AuthUserFailureThreshold` | `8` | Failed auth attempts for one user before `credential_stuffing`. |
| `password_spray_user_threshold` | `PasswordSprayUserThreshold` | `10` | Distinct users failed from one IP before `password_spray`. |
| `account_enumeration_threshold` | `AccountEnumerationThreshold` | `10` | Distinct failed login/reset-style users from one IP before `account_enumeration`. |
| `api_key_ip_threshold` | `APIKeyIPThreshold` | `5` | Distinct IPs using one API key before `api_key_ip_spread`. |
| `api_key_user_threshold` | `APIKeyUserThreshold` | `5` | Distinct users using one API key before `api_key_user_spread`. |
| `scan_path_threshold` | `ScanPathThreshold` | `40` | Distinct request paths by IP/user before `endpoint_scanning`. |
| `user_agent_rotation_threshold` | `UserAgentRotationThreshold` | `8` | Distinct user agents from one IP before `user_agent_rotation`. |
| `tenant_user_threshold` | `TenantUserThreshold` | `50` | Distinct active users in one tenant before `tenant_user_fanout`. |
| `export_threshold` | `ExportThreshold` | `10` | Export/download attempts by user/IP/tenant before `export_velocity`. |
| `large_body_threshold` | `LargeBodyThreshold` | `10485760` | Export response/request body size before `large_export_body`. |
| `function_invoke_threshold` | `FunctionInvokeThreshold` | `120` | Invocations of one function by user/IP before `function_invocation_velocity`. |
| `payment_user_amount_threshold` | `PaymentUserAmountThreshold` | `100000` | User payment/transfer amount total before `payment_velocity`. |
| `payment_tenant_amount_threshold` | `PaymentTenantAmountThreshold` | `500000` | Tenant payment/transfer amount total before `tenant_payment_velocity`. |
| `profile_risk_threshold` | `ProfileRiskThreshold` | `75` | Prior entity profile risk that contributes to `account_takeover_risk`. |

Set low thresholds in demos and tests so behavior is easy to see. Use higher thresholds in production and tune them from audit/metrics data.

### Facts, Findings, And Rules

Detectors produce two things:

- **Facts** are stable values under paths such as `abuse.auth.ip_failures`, `abuse.api_key.distinct_ips`, `abuse.scan.distinct_paths`, `abuse.fn.invocations`, or `abuse.application.injection_probe`. Rules read facts in `when` conditions.
- **Findings** are named security signals such as `credential_stuffing`, `api_key_user_spread`, `function_invocation_velocity`, or `injection_probe`. Findings appear in decisions, audit records, evidence, explanations, metrics, and threat model categories.

A finding alone records evidence, but enforcement still comes from a matching rule. A typical rule watches facts emitted by the detector:

```bcl
rule "function-invocation-abuse" {
  trigger {
    on request.received
    on function.invoked
  }

  when {
    any {
      abuse.fn.invocations greater_or_equal 3
      abuse.fn.errors greater_or_equal 3
    }
  }

  risk {
    base 72
    max 90
  }

  actions {
    medium {
      run throttle
    }
    high {
      run mfa_challenge
      run notify_soc
    }
  }
}
```

The current abuse detector emits these commonly used facts:

- `abuse.auth.ip_failures`, `abuse.auth.user_failures`, `abuse.auth.distinct_users`
- `abuse.enumeration.distinct_users`
- `abuse.signals.new_device`, `abuse.signals.country_changed`, `abuse.signals.user_agent_changed`, `abuse.signals.profile_risk`, `abuse.signals.account_takeover_score`
- `abuse.api_key.distinct_ips`, `abuse.api_key.distinct_users`
- `abuse.scan.distinct_paths`, `abuse.scan.ip_distinct_paths`, `abuse.scan.user_distinct_paths`
- `abuse.client.distinct_user_agents`
- `abuse.tenant.distinct_users`
- `abuse.data_export.count`, `abuse.data_export.large_body`
- `abuse.payment.user_amount`, `abuse.payment.tenant_amount`
- `abuse.fn.name`, `abuse.fn.invocations`, `abuse.fn.errors`
- `abuse.application.path_traversal`, `abuse.application.injection_probe`, `abuse.application.xss_probe`, `abuse.application.ssrf_probe`
- `abuse.admin.destructive`

### Threat Models

`threat_model` does not detect or block anything by itself. It decorates findings with categories so the decision/audit output can answer "what kind of threat was this?".

```bcl
threat_model "abuse-default" {
  category account_takeover {
    findings ["account_takeover_risk", "session_country_changed"]
  }
  category api_abuse {
    findings ["api_key_ip_spread", "api_key_user_spread", "endpoint_scanning"]
  }
  category application_abuse {
    findings ["path_traversal_probe", "injection_probe", "xss_probe", "ssrf_probe"]
  }
}
```

When a detector returns a finding whose `id` appears in a category, TCPGuard adds that category under `finding.threat_categories`. Models whose ID starts with `mitre` also populate `finding.mitre`; models whose ID starts with `stride` populate `finding.stride`. Other model names, such as `abuse-default`, stay in `threat_categories`.

### Adding New Abuse Parameters

To tune existing abuse behavior, add or change fields in the BCL `detector "abuse"` block and then write rules against the emitted facts.

To add a new abuse signal in code:

1. Add a field to `AbuseDetector` and a default in `NewAbuseDetector`.
2. Add BCL parsing/mapping for the field in `bcl/tcpguard.go` and `bundle.go`.
3. Add detector logic that sets a stable fact with `setContextFact(sec, "abuse.some.path", value)`.
4. Return a stable finding ID with `finding("some_abuse_id", risk, "message")`.
5. Add the finding ID to `DefaultAbuseThreatModel()` and any BCL `threat_model` blocks.
6. Add rules that read the fact path and choose actions.
7. Add tests for the fact, finding, BCL parsing, and an example policy assertion.

### How Abuse Detection Flows

Abuse detection is a pipeline. The detector observes behavior, rules decide whether to enforce, actions perform the response, and threat models label the findings for audit/SOC context.

1. A request or event enters TCPGuard.

   Fiber and `net/http` middleware send normal HTTP traffic as `request.received`:

   ```go
   app.Use(tcpguardfiber.Middleware(guard))
   ```

   You can also evaluate domain events directly:

   ```go
   decision := guard.Evaluate(ctx, tcpguard.Event{Type: "auth.login_failed"}, sec)
   ```

2. TCPGuard builds a security context.

   The context contains request, network, user, tenant, session, device, business, runtime, security, rate, and custom facts:

   ```text
   request.path
   request.method
   request.headers
   network.ip
   user.id
   tenant.id
   session.id
   session.device.new
   business.action
   business.amount
   ```

   For HTTP middleware, `HTTPContextBuilder` extracts this from the request. Applications can provide custom identity and business extractors.

3. The BCL `detector "abuse"` block enables the built-in abuse detector.

   ```bcl
   detector "abuse" {
     type abuse
     window 10m
     auth_ip_failure_threshold 3
     api_key_ip_threshold 2
     function_invoke_threshold 3
   }
   ```

   `type abuse` maps to the Go `tcpguard.AbuseDetector`. The BCL loader creates it from the policy pack and attaches it to the guard.

4. Abuse parameters control the detector’s counters and thresholds.

   For example:

   ```bcl
   auth_ip_failure_threshold 3
   ```

   means three failed auth events from the same IP within `window` can produce `credential_stuffing`.

   ```bcl
   api_key_ip_threshold 2
   ```

   means one API key used from two distinct IPs within `window` can produce `api_key_ip_spread`.

   TCPGuard stores these counters and distinct sets in the configured `SecurityStore`. Use `MemoryStore` for tests/local demos and Redis for multi-instance production.

5. Detectors run before rules.

   During evaluation, TCPGuard runs all matching detectors. The abuse detector updates stable `abuse.*` facts such as:

   ```text
   abuse.auth.ip_failures
   abuse.auth.distinct_users
   abuse.api_key.distinct_ips
   abuse.scan.distinct_paths
   abuse.fn.invocations
   abuse.payment.user_amount
   abuse.application.injection_probe
   ```

   Facts are machine-readable values. Rules use them in `when` conditions.

6. The abuse detector emits findings.

   When a threshold or probe condition is met, the detector returns a finding:

   ```json
   {
     "id": "credential_stuffing",
     "risk": 80,
     "severity": "high",
     "confidence": 0.8,
     "message": "authentication failure velocity indicates credential stuffing"
   }
   ```

   Findings are evidence. They appear in decisions, audit records, explanations, metrics, and threat model categories. A finding alone records what happened; a rule decides whether to block, throttle, challenge, or only monitor.

7. Rule triggers decide which rules are considered.

   ```bcl
   trigger {
     on auth.login_failed
   }
   ```

   This rule only evaluates for `auth.login_failed` events.

   Common event types include:

   ```text
   request.received
   auth.login_failed
   auth.login_success
   function.invoked
   business.high_value_payment
   ```

8. Rule conditions read abuse facts.

   ```bcl
   rule "auth-abuse-velocity" {
     trigger {
       on auth.login_failed
     }

     when {
       any {
         abuse.auth.ip_failures greater_or_equal 3
         abuse.auth.distinct_users greater_or_equal 3
       }
     }

     risk {
       base 92
       max 100
     }

     actions {
       critical {
         run block
         run create_incident
         run notify_soc
       }
     }
   }
   ```

   The flow for that rule is:

   ```text
   auth.login_failed event
   -> abuse detector increments auth counters
   -> abuse.auth.ip_failures reaches 3
   -> rule condition matches
   -> risk becomes 92
   -> severity becomes critical
   -> critical actions run
   ```

9. Risk and severity are calculated.

   A rule sets risk:

   ```bcl
   risk {
     base 92
     max 100
   }
   ```

   Findings can also carry risk. TCPGuard uses the highest relevant risk and caps it with the rule’s `max`.

   Severity follows risk unless overridden:

   ```text
   0-24    info
   25-49   low
   50-74   medium
   75-89   high
   90-100  critical
   ```

   You can make severity explicit:

   ```bcl
   severity {
     high when risk.score greater_or_equal 75
     critical when risk.score greater_or_equal 90
   }
   ```

10. Actions run from the resolved severity.

    ```bcl
    actions {
      critical {
        run block
        run create_incident
        run notify_soc
      }
    }
    ```

    Example actions include:

    ```text
    block
    throttle
    mfa_challenge
    create_incident
    notify_soc
    revoke_session
    lock_user
    ban_ip
    ```

    In `enforce` mode, the default effect by severity is:

    ```text
    critical -> block
    high     -> challenge
    medium   -> throttle
    low/info -> monitor or allow
    ```

11. Threat models categorize findings.

    `threat_model` does not detect or block anything by itself. It labels findings after detectors emit them.

    ```bcl
    threat_model "abuse-default" {
      category bot_abuse {
        findings ["credential_stuffing", "password_spray"]
      }

      category api_abuse {
        findings ["api_key_ip_spread", "endpoint_scanning"]
      }
    }
    ```

    If the detector emits `credential_stuffing`, TCPGuard decorates the finding:

    ```json
    {
      "id": "credential_stuffing",
      "threat_categories": {
        "abuse-default": ["bot_abuse"]
      }
    }
    ```

    Models whose IDs start with `mitre` also populate `finding.mitre`. Models whose IDs start with `stride` populate `finding.stride`. Other models, such as `abuse-default`, populate `finding.threat_categories`.

12. TCPGuard returns and audits the final decision.

    A blocked abuse decision looks like:

    ```json
    {
      "effect": "block",
      "allowed": false,
      "risk": {
        "score": 92,
        "confidence": 0.8
      },
      "severity": "critical",
      "findings": [
        {
          "id": "credential_stuffing",
          "threat_categories": {
            "abuse-default": ["bot_abuse"]
          }
        }
      ],
      "matched_rules": ["auth-abuse-velocity"],
      "actions": [
        {"id": "block", "status": "ok"},
        {"id": "create_incident", "status": "ok"}
      ],
      "evidence": [
        {"type": "matched_rule", "id": "auth-abuse-velocity"},
        {"type": "finding", "id": "credential_stuffing"}
      ]
    }
    ```

The shortest mental model is:

```text
request/event
-> context builder extracts request/user/session/business data
-> abuse detector updates abuse.* facts
-> abuse detector emits findings
-> threat model decorates findings
-> rule trigger selects candidate rules
-> rule when condition reads abuse.* facts
-> risk and severity are calculated
-> actions run
-> decision, evidence, audit, incidents, and profiles are saved/returned
```

### Complete Abuse Sink Example

This example shows the whole path for credential stuffing: failed login events enter TCPGuard, the abuse detector counts them, a rule matches, actions run, and the decision is sent to response/audit/incident/SOC sinks.

#### 1. Configure The Action Sink

An action sink is where TCPGuard sends the result of a matched rule. A sink can be an inline response action such as `block`, an internal sink such as `create_incident`, or an external sink such as `notify_soc`, `webhook`, `siem`, or `event_bus`.

```bcl
action "notify_soc" {
  type event_bus
  provider nats
  subject "security.tcpguard.alert"
  success_codes ["2xx"]
  retry_on_codes ["429", "5xx"]

  retry {
    attempts 2
    backoff linear
    jitter true
  }

  idempotency {
    header "Idempotency-Key"
    key concat(request.id, "-notify-soc")
  }

  request {
    body {
      request context("request.id", "unknown-request")
      ip context("network.ip", "unknown-ip")
      user context("user.id", "anonymous")
      tenant context("tenant.id", "public")
      risk "{{risk.score}}"
      severity "{{severity}}"
      include matched_rules
      include findings
      field source "tcpguard"
    }
  }
}
```

What this does:

- `type event_bus` chooses the action executor type.
- `subject` is the event topic/channel.
- `retry` and `retry_on_codes` make delivery more resilient.
- `idempotency` prevents duplicate SOC notifications for retried action delivery.
- `request.body` maps TCPGuard facts and decision values into the outbound sink payload.

In the local examples, if no real endpoint/provider executor is configured, `notify_soc` is safely marked `skipped`. The rule still blocks, audits, and creates incidents.

#### 2. Enable The Abuse Detector

```bcl
detector "abuse" {
  type abuse
  window 10m
  auth_ip_failure_threshold 3
  password_spray_user_threshold 3
}
```

What this does:

- `type abuse` enables `tcpguard.AbuseDetector`.
- `window 10m` means counters expire after 10 minutes.
- `auth_ip_failure_threshold 3` means 3 failed logins from one IP can become `credential_stuffing`.
- `password_spray_user_threshold 3` means 3 distinct users failed from one IP can become `password_spray`.

#### 3. Categorize Findings With A Threat Model

```bcl
threat_model "abuse-default" {
  category bot_abuse {
    findings ["credential_stuffing", "password_spray"]
  }

  category account_takeover {
    findings ["account_takeover_risk"]
  }
}
```

What this does:

- It does not detect anything.
- It does not block anything.
- It decorates matching findings with `threat_categories`.

If the detector emits `credential_stuffing`, the finding is decorated like:

```json
{
  "id": "credential_stuffing",
  "threat_categories": {
    "abuse-default": ["bot_abuse"]
  }
}
```

#### 4. Add The Abuse Rule

```bcl
rule "auth-abuse-velocity" {
  name "Block credential stuffing and password spray"
  status active
  priority 930

  trigger {
    on auth.login_failed
  }

  when {
    any {
      abuse.auth.ip_failures greater_or_equal 3
      abuse.auth.distinct_users greater_or_equal 3
    }
  }

  risk {
    base 92
    max 100
  }

  severity {
    critical when risk.score greater_or_equal 90
  }

  actions {
    critical {
      run block
      run create_incident
      run notify_soc
    }
  }
}
```

What this does:

- `trigger` makes the rule run only for `auth.login_failed`.
- `when` reads facts emitted by the abuse detector.
- `risk` gives the matched rule a high score.
- `severity` turns score `92` into `critical`.
- `actions` sends the final decision to three sinks:
  - `block`: reject the request/event.
  - `create_incident`: store an incident record.
  - `notify_soc`: send an external SOC/event-bus notification if configured.

#### 5. Send Failed Auth Events From The App

HTTP middleware automatically emits `request.received`, but failed login is an application/domain event. Emit it when your login handler rejects credentials:

```go
func loginFailedHandler(w http.ResponseWriter, r *http.Request) {
    sec := &tcpguard.Context{
        Request: tcpguard.RequestContext{
            ID:      r.Header.Get("X-Request-ID"),
            Method:  r.Method,
            Path:    r.URL.Path,
            Headers: map[string]string{},
        },
        Network: tcpguard.NetworkContext{
            IP: r.Header.Get("X-Forwarded-For"),
        },
        Identity: tcpguard.IdentityContext{
            ID: r.Header.Get("X-User-ID"),
        },
        Tenant: tcpguard.TenantContext{
            ID: r.Header.Get("X-Tenant-ID"),
        },
        Security: map[string]any{},
        Rate:     map[string]any{},
    }

    decision := guard.Evaluate(
        r.Context(),
        tcpguard.Event{Type: "auth.login_failed", Source: "login"},
        sec,
    )

    if !decision.Allowed {
        w.WriteHeader(http.StatusForbidden)
        _ = json.NewEncoder(w).Encode(decision)
        return
    }

    w.WriteHeader(http.StatusUnauthorized)
    _ = json.NewEncoder(w).Encode(map[string]any{"error": "invalid_credentials"})
}
```

What this does:

- The application knows the login failed, so it emits `auth.login_failed`.
- TCPGuard evaluates the event with the user/IP/tenant context.
- The first failures may only update counters.
- Once thresholds are crossed, the rule blocks and sends to sinks.

The Fiber demo includes this same idea at:

```text
POST /_demo/auth/fail
```

#### 6. Test The Flow

Run the Fiber demo:

```sh
GOCACHE=/tmp/tcpguard-go-build go run ./examples/tcpguard_fiber_server
```

Then send three failed logins from the same IP:

```sh
for user in a b c; do
  curl -i -X POST http://127.0.0.1:18181/_demo/auth/fail \
    -H 'User-Agent: demo' \
    -H "X-User-ID: $user" \
    -H 'X-Tenant-ID: bank' \
    -H 'X-Forwarded-For: 198.51.100.77'
done
```

What happens:

1. First request:
   - event is `auth.login_failed`
   - `abuse.auth.ip_failures` becomes `1`
   - `abuse.auth.distinct_users` becomes `1`
   - rule does not match yet
   - decision is allowed/monitored

2. Second request:
   - `abuse.auth.ip_failures` becomes `2`
   - `abuse.auth.distinct_users` becomes `2`
   - rule still does not match
   - decision is allowed/monitored

3. Third request:
   - `abuse.auth.ip_failures` becomes `3`
   - `abuse.auth.distinct_users` becomes `3`
   - detector emits `credential_stuffing`
   - detector emits `password_spray`
   - threat model labels both as `bot_abuse`
   - rule `auth-abuse-velocity` matches
   - risk becomes `92`
   - severity becomes `critical`
   - `block`, `create_incident`, and `notify_soc` actions run

#### 7. Final Decision Shape

The third response looks like this, shortened for readability:

```json
{
  "effect": "block",
  "allowed": false,
  "risk": {
    "score": 92,
    "confidence": 0.8
  },
  "severity": "critical",
  "findings": [
    {
      "id": "credential_stuffing",
      "risk": 80,
      "severity": "high",
      "threat_categories": {
        "abuse-default": ["bot_abuse"]
      }
    },
    {
      "id": "password_spray",
      "risk": 78,
      "severity": "high",
      "threat_categories": {
        "abuse-default": ["bot_abuse"]
      }
    }
  ],
  "matched_rules": ["auth-abuse-velocity"],
  "actions": [
    {
      "id": "block",
      "type": "block",
      "status": "ok"
    },
    {
      "id": "incident_req_123_456",
      "type": "create_incident",
      "status": "ok"
    },
    {
      "id": "notify_soc",
      "type": "event_bus",
      "status": "ok"
    }
  ],
  "evidence": [
    {
      "type": "matched_rule",
      "id": "auth-abuse-velocity"
    },
    {
      "type": "finding",
      "id": "credential_stuffing"
    },
    {
      "type": "finding",
      "id": "password_spray"
    }
  ]
}
```

#### 8. Where Each Piece Lands

| Step | TCPGuard object | Example | Purpose |
| --- | --- | --- | --- |
| Input | `Event` | `auth.login_failed` | Says what happened. |
| Input | `Context` | `network.ip`, `user.id` | Supplies the data used for detection. |
| Detection | `detector "abuse"` | `type abuse` | Enables abuse counters and probes. |
| State | `SecurityStore` | `MemoryStore`, `RedisStore` | Stores counters, distinct sets, nonces, profiles, incidents, audits. |
| Facts | `abuse.*` | `abuse.auth.ip_failures` | Values that rules evaluate. |
| Findings | `Finding` | `credential_stuffing` | Evidence emitted by detectors. |
| Categorization | `threat_model` | `bot_abuse` | Labels findings for audit/SOC reporting. |
| Rule selection | `trigger` | `on auth.login_failed` | Decides whether a rule runs for this event. |
| Rule match | `when` | `abuse.auth.ip_failures >= 3` | Decides whether the rule matched. |
| Scoring | `risk`/`severity` | `base 92`, `critical` | Decides seriousness. |
| Sink | `actions` | `block`, `create_incident`, `notify_soc` | Performs response and notification. |
| Output | `Decision` | `effect`, `findings`, `actions` | Returned to middleware/app and saved in audit. |

## Configuration-Driven Detection

TCPGuard's built-in detectors can evaluate HTTP requests and application events. For business events, the host application must pass facts it already knows—such as the authenticated identity, transaction ID, amount, approval count, and event type—to `Guard.Evaluate`. TCPGuard does not infer those values from an opaque request body. HTTP abuse probes scan paths, query values, event fields, and text, JSON, XML, or form request bodies up to 1 MiB; binary bodies are skipped, and the request stream is restored for the application.

Policies and detector paths can read `context.user.id`, `request.path`, `request.query.payment_id`, `request.params.order_id`, and headers through `header.x-api-key`, `request.header.x-api-key`, or `request.headers.x-api-key`. Header lookups are case-insensitive. Query and route parameter maps are traversable facts.

### Business and Cross-Service Controls

Configure temporal and domain thresholds in a `business_anomaly` detector:

```bcl
detector "business-controls" {
  type business_anomaly
  window 15m
  authz_failure_threshold 5
  body_size_threshold 10485760
  duration_threshold_ms 30000
  high_value_threshold 1000000
  approval_amount_threshold 100000
  refund_amount_threshold 50000
  payout_amount_threshold 250000
  sensitive_record_threshold 100
  service_allowlist ["billing-worker", "payments-api"]
  privileged_roles ["admin", "owner", "super_admin"]
}
```

The detector reports authorization failure velocity, oversized or slow requests, role elevation, cross-user permission changes, unknown service identities, approval gaps, duplicate transactions, large refunds or payouts, and refund/payout velocity. `service_allowlist` checks `identity.id` when `identity.type` is `service` or `workload`.

It also detects bulk access to sensitive records and high record-access velocity for an actor or tenant. Emit an event such as `security.data_access` after the application has authorized and completed a read, and include `sensitive: true` (or `sensitivity: "high"`) and `records_count`. The default threshold is 100 records per operation or configured window; set `sensitive_record_threshold` to tune it. The application should report the number of records returned because TCPGuard does not inspect response bodies. This works with any adapter that passes the event to `Guard.Evaluate`.

For event-based checks, send a typed `Event` with fields such as:

- `authz.denied`: `status` or a denial event type, plus actor identity in the context.
- `security.privilege_changed`: `old_role`, `new_role`, or `privilege_escalation`; cross-user permission changes can include `actor_user_id` and `target_user_id`.
- `business.approval`: `approval_required`, `approval_count`, plus `business.approval_level` in context.
- Payment-like events: `transaction_id` (or `payment_id`) and a `business.action`, workflow, or entity containing `payment`, `transfer`, `payout`, or `refund`.
- Resource checks: `duration_ms` in event fields and request body size in context.

### Breach and Compromise Events

The built-in security breach detector converts confirmed incident events such as `security.data_breach`, `security.credential_exposure`, and `security.server_compromise` into critical findings. A suspected event such as `security.breach_suspected` produces a separate high-risk finding. Send these events from the application, SIEM, cloud security service, or another trusted telemetry source; TCPGuard cannot confirm a breach from an opaque request alone. The detector records only the event type and classification, so do not put exposed secrets or raw sensitive values in event fields.

Use ordinary BCL rules to choose the response for emitted findings: challenge, block, throttle, open an incident, or notify an operator. Detector findings provide signals; policy determines enforcement.

### Tenant-Specific Behavioral Baselines

Define a baseline per entity and observation event. The configured entity can be `tenant.id`, `user.id`, or another fact path; fields map aliases to numeric facts. TCPGuard learns per-entity means and variance and reports deviations after `min_samples` observations. Baseline updates are atomic when the configured store implements `AtomicUpdater` (the built-in memory, Redis, and SQLite stores do).

```bcl
baseline "tenant-payment-amount" {
  entity tenant.id
  observe business.payment
  window 30d
  min_samples 30
  fields {
    amount business.amount
  }
}
```

Applications must supply consistent facts and event names across requests. Configure a shared store such as Redis for multi-instance deployments so counters and baselines cover the fleet. See the [standalone Configuration-Driven Detection guide](docs/detection-configuration.md) for the same material in a focused reference.

### Complete Built-In Anomaly Examples And Results

The detector emits **findings**; a matching rule and the configured mode determine the final decision. Finding risk below is the finding's own risk value, not necessarily the final decision risk. Stateful examples need a shared `SecurityStore` in multi-instance deployments. Use a fresh `Context` for each request/event.

#### Enable The Built-In Detectors

The default detector set includes header anomalies, sensitive endpoints, replay, rate abuse, session drift, security breach events, business anomalies, and abuse detection. When you disable defaults, configure the factory-backed types in BCL and add `SecurityBreachDetector` directly because it has no BCL factory:

```bcl
detector "request-boundary" {
  type header_anomaly
}

detector "sensitive-routes" {
  type sensitive_endpoint
  patterns ["/admin/*", "/api/payments/export"]
}

detector "request-rate" {
  type rate
  algorithm sliding_window
  window 1m
  ip_limit 120
  user_limit 300
  endpoint_limit 60
}

detector "request-replay" {
  type replay
  clock_skew 1m
  nonce_ttl 10m
}

detector "session-change" {
  type session_drift
}

detector "business-controls" {
  type business_anomaly
  window 15m
  high_value_threshold 1000000
  authz_failure_threshold 5
  body_size_threshold 10485760
  duration_threshold_ms 30000
  refund_amount_threshold 50000
  payout_amount_threshold 250000
  approval_amount_threshold 100000
  sensitive_record_threshold 100
  service_allowlist ["billing-worker", "payments-api"]
  privileged_roles ["admin", "owner", "super_admin"]
  transaction_id_path "request.query.payment_id"
  service_id_header "X-Service-ID"
}

detector "abuse-controls" {
  type abuse
  window 10m
  auth_ip_failure_threshold 3
  auth_user_failure_threshold 3
  password_spray_user_threshold 3
  api_key_ip_threshold 2
  api_key_user_threshold 2
  scan_path_threshold 4
  export_threshold 2
  function_invoke_threshold 3
  user_agent_rotation_threshold 3
  tenant_user_threshold 4
  account_enumeration_threshold 3
  large_body_threshold 1048576
  payment_user_amount_threshold 200000
  payment_tenant_amount_threshold 500000
  profile_risk_threshold 70
}
```

For the runnable HTTP implementation, use the FH adapter and the existing [FH anomaly server](examples/tcpguard_fh_server/README.md). Its BCL configuration loads the detectors, and its HTTP middleware evaluates real requests. The breach detector is part of the default set; if you disable default detectors, register it explicitly because it has no BCL factory.

```go
// This route is implemented in examples/tcpguard_fh_server/main.go.
// Its guard is built from the FH example's loaded policy bundle.
app.Post("/_demo/business-payment", func(c fh.Ctx) error {
    // The request extractor is the FH example's contextFromFH helper.
    // Map application-owned, already validated values into TCPGuard facts.
    amount, err := strconv.ParseFloat(c.Get("X-Business-Amount"), 64)
    if err != nil {
        return c.Status(http.StatusBadRequest).JSON(map[string]string{"error": "invalid_amount"})
    }
    approvalRequired, _ := strconv.ParseBool(c.Get("X-Approval-Required"))
    sec := contextFromFH(c)
    sec.Business.Action = "payment.transfer"
    sec.Business.Amount = amount
    event := tcpguard.Event{
        Type:   "business.payment",
        Fields: map[string]any{
            "transaction_id":    c.Get("X-Transaction-ID"),
            "approval_required": approvalRequired,
        },
    }
    decision := guard.Evaluate(c.Context(), event, sec)
    return respondWithDecision(c, sec, decision)
})
```

The route above is a domain-event handler inside an FH server; regular HTTP request anomalies continue through `tcpguardfh.Middleware`. This rule is included in the FH example policy and turns the detected high-value transfer into an enforcement decision:

```bcl
rule "business-event-high-value-payment" {
  trigger {
    on business.payment
  }
  when {
    business.amount greater_or_equal 1000000
  }
  risk {
    base 92
    max 100
  }
  severity {
    critical when risk.score greater_or_equal 90
  }
  actions {
    critical {
      run block
      run create_incident
    }
  }
}
```

Call the FH route with application facts:

```sh
curl -i -X POST http://127.0.0.1:18184/_demo/business-payment \
  -H 'X-User-ID: payer-1' \
  -H 'X-Tenant-ID: tenant-4' \
  -H 'X-Business-Amount: 1250000' \
  -H 'X-Approval-Required: true' \
  -H 'X-Transaction-ID: txn-884'
```

The FH example includes this route and rule. At the sample amount, its configured counters also emit `payment_velocity` and `tenant_payment_velocity`; the business detector emits `high_value_action` and `approval_level_missing`. The matching rule blocks and runs `create_incident`. Without a matching rule, TCPGuard still reports findings, but the policy's default effect controls enforcement.

#### Request And HTTP Boundary Findings

These are emitted by `header_anomaly`. Configure matching limits and trusted proxy handling in `HTTPContextBuilder`; the marked facts are supplied by that builder. Avoid trusting forwarded identity headers from arbitrary peers.

| Input or condition | Finding (risk) |
| --- | --- |
| Host is empty | `missing_host_header` (30) |
| POST content type is neither JSON nor form | `content_type_unusual` (20) |
| User agent is empty or contains `sqlmap` | `suspicious_user_agent` (35) |
| Origin and Referer differ by origin | `origin_referer_mismatch` (25) |
| Forwarding headers exist and the peer is untrusted | `untrusted_forwarded_headers` (75) |
| Both Content-Length and Transfer-Encoding are present | `ambiguous_request_framing` (90) |
| Method override header is present | `method_override_header` (55) |
| Method is TRACE or CONNECT | `dangerous_http_method` (65) |
| Escaped path has encoded slash, backslash, or NUL, or path contains `;` | `path_canonicalization_ambiguity` (70) |
| Content-Length contains comma-separated values | `duplicate_content_length` (90) |
| Transfer-Encoding is set to something other than `chunked` | `invalid_transfer_encoding` (85) |
| Range has at least three ranges | `range_request_abuse` (55) |
| Content-Encoding is neither identity nor gzip | `unsupported_content_encoding` (60) |
| Builder marks CSRF missing / idempotency missing / CORS origin disallowed | `csrf_token_missing` (85) / `idempotency_key_missing` (65) / `cors_origin_not_allowed` (80) |
| `limit`, `page_size`, or `pagesize` exceeds 1000; `offset` exceeds 100000 | `pagination_abuse` (55) |
| JSON body is malformed / has duplicate object key / nesting exceeds 50 | `malformed_json` (60) / `duplicate_json_key` (75) / `json_complexity_abuse` (70) |
| Builder marks HTTPS required, host/method disallowed, header bytes/count, URL, or body over limit | `https_required` (85), `host_not_allowed` (85), `method_not_allowed` (75), `headers_oversized` (75), `header_count_exceeded` (75), `url_oversized` (75), or `body_oversized` (75) |

HTTP abuse probes also scan request paths, query values, event fields, and supported text/JSON/XML/form bodies up to 1 MiB. For example, a request path containing `../` emits `path_traversal_probe` (76); a body containing ` UNION SELECT ` emits `injection_probe` (78); `<script` emits `xss_probe` (66); a target containing `169.254.169.254` emits `ssrf_probe` (80). Binary bodies are skipped.

#### Stateful And Event-Based Findings

| Detector | Example input | Finding(s) (finding risk) |
| --- | --- | --- |
| `sensitive_endpoint` | Request path matches configured pattern (defaults include `/admin/*`, `/api/v1/reports/export`, `/api/v1/users/*/permissions`) | `sensitive_endpoint_access` (30); fact `endpoint.sensitive=true` |
| `rate` | Same IP, user, tenant, session, endpoint, IP+user, or tenant+endpoint exceeds its configured count in the window | `rate_limit_abuse`, `user_rate_limit_abuse`, `tenant_rate_limit_abuse`, `session_rate_limit_abuse`, `endpoint_rate_limit_abuse`, `ip_user_rate_limit_abuse`, or `tenant_endpoint_rate_limit_abuse` (70). Counts flag when they are **greater than** the limit. |
| `session_drift` | Previous country differs from current; session UA differs from request UA; or login succeeds on a new device | `session_country_changed` (65), `session_user_agent_changed` (45), `new_device_login` (45) |
| Built-in `SecurityBreachDetector` | `Event{Type:"security.data_breach"}` / `security.breach_suspected` / `security.credential_exposure` / `security.server_compromise` | `confirmed_data_breach` (100) / `suspected_security_breach` (78) / `credential_exposure_detected` (100) / `server_compromise_detected` (100). This records trusted telemetry; it does not infer that a breach occurred. |
| `business_anomaly` | Privileged role and outside-hours/holiday activity; high-sensitivity export; high-value amount; approval or resource event | `after_hours_admin_access` (50), `sensitive_export` (55), `high_value_action` (60), `approval_level_missing` (65), `request_body_anomaly` (68), `resource_exhaustion_signal` (70) |
| `business_anomaly` | `security.data_access` with sensitivity and records count; repeated sensitive reads in window | `bulk_sensitive_data_access` (82) for a single operation at threshold; `sensitive_data_access_velocity` (86) when actor or tenant rolling count reaches threshold |
| `business_anomaly` | `authz.denied` repeated for one actor; `security.privilege_changed` from member to admin; service identity absent or not allowed | `authorization_failure_velocity` (78), `privilege_elevation` (88), `missing_service_identity` (76), `unknown_service_identity` (82) |
| `business_anomaly` | Refund/payout amount or rolling total exceeds configured thresholds; same transaction ID repeats within window | `unusual_refund_amount` (82), `refund_velocity` (86), `unusual_payout_amount` (84), `payout_velocity` (88), `duplicate_transaction` (95) |
| `baseline` | Numeric observed value is at least 3 standard deviations from a per-entity baseline after `min_samples` | `baseline_<field-alias>_anomaly` (45), for example `baseline_amount_anomaly` |

For `business_anomaly`, use `Event{Type:"business.payment", Fields:map[string]any{"transaction_id":"txn-884","approval_required":true}}` with `Business.Action="payment.transfer"` and `Business.Amount` set by the application. A repeated transaction ID within the configured window produces `duplicate_transaction`; a transfer at or above `high_value_threshold` produces `high_value_action`. `security.data_access` should be emitted after authorization and completion and include `sensitive:true` and `records_count`; TCPGuard cannot infer response record counts.

#### Abuse Detector Finding Catalog

`type abuse` uses `SecurityStore` counters and distinct sets. These are the finding IDs and the input that produces them; configure thresholds on the detector block shown above.

| Finding (risk) | Example that crosses its threshold |
| --- | --- |
| `credential_stuffing` (80) | Failed auth events reach `auth_ip_failure_threshold` for one IP or `auth_user_failure_threshold` for one user. |
| `password_spray` (78) | Failed auth events from one IP span `password_spray_user_threshold` distinct users. |
| `account_enumeration` (74) | Login/reset/signup-style failures for nonexistent users span `account_enumeration_threshold` users. |
| `account_takeover_risk` (82) | At least two signals among new device, country change, user-agent change, anonymous network, and prior profile risk at threshold. |
| `api_key_ip_spread` (72) / `api_key_user_spread` (74) | One API key is seen from enough distinct IPs / users. |
| `endpoint_scanning` (70) | One IP or user reaches `scan_path_threshold` distinct method+path pairs. |
| `user_agent_rotation` (62) | One IP uses `user_agent_rotation_threshold` distinct user agents. |
| `tenant_user_fanout` (68) | A tenant has activity from `tenant_user_threshold` distinct users. |
| `export_velocity` (76) / `large_export_body` (70) | Export/download count reaches `export_threshold`, or its body reaches `large_body_threshold`. |
| `payment_velocity` (84) / `tenant_payment_velocity` (82) | Payment/transfer running amount reaches the configured per-user / per-tenant amount. |
| `function_invocation_velocity` (72) / `function_error_abuse` (64) | One actor repeatedly invokes the same named function, or gets at least three errors for it. |
| `path_traversal_probe` (76) / `injection_probe` (78) / `xss_probe` (66) / `ssrf_probe` (80) | Request surface contains traversal, SQL injection, XSS, or internal metadata/localhost target indicators. |
| `destructive_admin_action` (60) / `destructive_admin_abuse` (86) | A privileged actor performs delete/disable/lock/ban/revoke/permission/role/sudo action; outside-hours, new-device, or country-change signal raises it to abuse. |

#### Replay Findings

`replay` uses a nonce store and optionally a request signing secret. In production, use a store with atomic `SetNX`, configure a secret provider, and set `RequireSignature`/`RequireIdempotency` in Go as required by your threat model.

| Input | Finding (risk) |
| --- | --- |
| Reused `X-TCPGuard-Nonce` | `nonce_reused` (85) |
| Malformed `X-TCPGuard-Timestamp` / timestamp outside `clock_skew` | `invalid_timestamp` (75) / `timestamp_skew` (65) |
| Required signature has no secret / signature header is missing / request lacks original HTTP request | `signature_secret_unavailable` (95) / `missing_signature` (90) / `signature_unverifiable` (90) |
| Signature fails HMAC validation | `invalid_signature` (90) |
| Mutation reuses `Idempotency-Key` with same fingerprint / different fingerprint | `idempotency_reused` (75) / `idempotency_conflict` (90) |

#### Custom DSL And HTTP Detector Results

`dsl` findings and outputs are policy-defined: when a configured finding condition matches, the exact configured finding ID, risk, message, and fields are returned. `http` sends data to an external detector; a positive numeric `risk_score` produces the configured detector ID (or `http_detector`) with that score. With `fallback "allow"`, transport errors do not fail evaluation; other fallback policies determine the configured failure behavior. These cannot have one universal finding list because the policy or remote response defines it.

#### Actual End-To-End Result

Run the FH server and issue the application-reported business event:

```sh
cd examples/tcpguard_fh_server
go run .
```

In another terminal:

```sh
curl -i -X POST \
  -H 'X-User-ID: payer-1' \
  -H 'X-Tenant-ID: tenant-4' \
  -H 'X-Business-Amount: 1250000' \
  -H 'X-Approval-Required: true' \
  -H 'X-Transaction-ID: txn-884' \
  http://127.0.0.1:18184/_demo/business-payment
```

I ran this request against the FH server. It returned `403 Forbidden` with `X-TCPGuard-Decision: block` and `X-TCPGuard-Severity: critical`. The structured decision log showed risk 92, matched rule `business-event-high-value-payment`, findings `payment_velocity`, `tenant_payment_velocity`, `high_value_action`, and `approval_level_missing`, plus successful `block` and `create_incident` actions. The public production response stays redacted. For the complete request/result catalog—including credential stuffing, account takeover, endpoint scanning, exports, function abuse, replay, and dynamic-route ownership—see [the FH server scenarios](examples/tcpguard_fh_server/README.md#curl-scenarios).

## Operator CLI

The repository includes a CLI for validation, simulation, explanation, policy diffing, smoke tests, and reload checks:

```sh
go run ./cmd/tcpguard validate -dir ./examples/tcpguard_multi_file_policy_pack
go run ./cmd/tcpguard simulate -dir ./examples/tcpguard_multi_file_policy_pack -request ./examples/tcpguard_multi_file_policy_pack/request.json
go run ./cmd/tcpguard explain -dir ./examples/tcpguard_multi_file_policy_pack -request ./examples/tcpguard_multi_file_policy_pack/request.json
go run ./cmd/tcpguard test -dir ./examples/tcpguard_multi_file_policy_pack -request ./examples/tcpguard_multi_file_policy_pack/request.json
go run ./cmd/tcpguard diff -before-dir ./policy-old -after-dir ./policy-new -request ./request.json
```

## Hardened Management Server (v2)

Use `NewManagementServer(...)` for production management endpoints. It supports:

- chained authentication providers (`mTLS`, `Bearer JWT`, static API keys)
- route-level RBAC authorization
- CIDR allowlists
- max request body size
- short per-request read timeouts
- optional per-IP rate limits

```go
management := tcpguard.NewManagementServer(reloadable, tcpguard.ManagementServerConfig{
    AuthProvider: tcpguard.ChainAuthProvider{
        tcpguard.MTLSAuth{RequireVerified: true},
        tcpguard.JWTAuth{Secret: []byte(os.Getenv("TCPGUARD_MGMT_JWT_SECRET"))},
        tcpguard.StaticAPIKeyAuth{
            Keys: map[string]tcpguard.ManagementPrincipal{
                os.Getenv("TCPGUARD_MGMT_API_KEY"): {Subject: "ops", Roles: []string{"admin"}},
            },
        },
    },
    Authorizer: tcpguard.RoleBasedAuthorizer{
        RolesByRoute: map[tcpguard.ManagementRoute][]string{
            tcpguard.ManagementRouteReload:      {"admin"},
            tcpguard.ManagementRouteSimulate:    {"admin", "analyst"},
            tcpguard.ManagementRouteExplain:     {"admin", "analyst"},
            tcpguard.ManagementRouteAudit:       {"admin", "auditor"},
            tcpguard.ManagementRouteApprovals:   {"admin", "approver"},
        },
    },
    AllowedCIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"},
    MaxBodyBytes: 1 << 20,
    ReadTimeout:  2 * time.Second,
})
```

Management list endpoints now support pagination/filtering query params:

- `limit`
- `cursor`
- `after` (unix seconds or RFC3339)
- `before` (unix seconds or RFC3339)

## Examples

- [Fiber server example](examples/tcpguard_fiber_server/README.md): end-to-end Fiber v3 app with policy packs, datasources, GeoIP, approvals, incidents, and audit.
- [net/http server example](examples/tcpguard_http_server/README.md): standard library middleware with custom responses, metrics, management endpoints, and policy assertions.
- [Multi-file policy pack](examples/tcpguard_multi_file_policy_pack/README.md): directory-based policy layout with shared actions, intel, triggers, and endpoint/business/session rules.
- [FH anomaly-detection server](examples/tcpguard_fh_server/README.md): runnable `oarkflow/fh` implementation with request and event examples, expected responses, and CLI policy checks.
- [Single-file banking pack](examples/tcpguard_banking_protection_pack/tcpguard.bcl): compact policy pack in one BCL file.

## Documentation

- [Usage Guide](docs/usage.md): installation, middleware setup, policy loading, CLI usage, management endpoints, performance options, stores, and reloads.
- [Use Cases](docs/use-cases.md): practical security scenarios TCPGuard handles today.
- [Enhancements](docs/enhancements.md): candid roadmap of missing or high-value improvements.
- [Production Guide](docs/production.md): Redis, proxy headers, reloads, GeoIP, safety settings, and failure modes.
- [Security Hardening](docs/security.md): secrets, webhooks, command actions, audit redaction, and approvals.
- [Configuration-Driven Detection](docs/detection-configuration.md): configure business anomaly detection, breach events, behavioral baselines, request facts, and cross-service controls.
- [Versioning](docs/versioning.md): policy pack compatibility and migration guidance.
- [Policy Authoring](docs/authoring.md): pack structure, rule checklist, assertions, naming, and integration guidance.
- [Release Checklist](docs/release-checklist.md): pre-production hardening and rollout checks.
- [Strict Hardening Migration](docs/migration-strict-hardening.md): upgrade notes for breaking secure-by-default changes.

## CI and Performance Gates

This repo includes CI checks for:

- `go test ./...`
- `go test -race ./...`
- benchmark SLO checks via [`scripts/check_bench_slo.sh`](scripts/check_bench_slo.sh)
- `govulncheck`
- `gosec`

## Current Status

TCPGuard includes runtime enforcement, policy loading, detectors, lookup datasources, approvals, audit envelopes, simulation, reload primitives, response customization, metrics hooks, Redis-backed state, retention controls, hardened management APIs, tests, benchmarks, and runnable examples.

## Enterprise anomaly-detection additions

TCPGuard now includes enterprise extensibility and governance primitives:

- **Detector factory registry**: detector modules can be registered once and enabled from BCL using `detector` blocks. Built-in registry-backed detector types include `dsl`, `http`, `abuse`, `rate`, `replay`, `header_anomaly`, `sensitive_endpoint`, `session_drift`, and `business_anomaly`.
- **BCL-configurable runtime detectors**: rate limits, replay windows, clock skew, and abuse thresholds can be policy-managed instead of hard-coded in Go.
- **Correlation/sequence rules**: rule triggers can model multi-step attacks such as failed-logins followed by a successful login.
- **Policy linter**: `tcpguard lint` validates rule quality, missing actions, missing authz policies, unknown detectors, unused actions, lookup/datasource mismatches, unsafe webhook definitions, and broad-scoped rules.
- **Structured decision trace**: decisions now include a `trace` object with risk contributors, policy identity, and recommended operator actions.
- **FH enterprise example**: `examples/tcpguard_fh_server` contains a complete server with global and endpoint rules, correlation flows, datasource lookups, HMAC/replay protection, authz, metrics, audit verification, incidents, approvals, and detailed curl documentation.

Example CLI usage:

```bash
go run ./cmd/tcpguard validate -dir ./examples/tcpguard_fh_server
go run ./cmd/tcpguard lint -dir ./examples/tcpguard_fh_server
go run ./cmd/tcpguard lint -strict -dir ./examples/tcpguard_fh_server
```

## Production responses and decision logs

TCPGuard separates public response safety from operator diagnostics. Use `ResponseMessagePolicy` and `PublicDecisionResponseRenderer` for minimal, understandable client responses. Keep `WithResponseRenderer` when your API needs a stable envelope, but wrap the public renderer/body builder rather than exposing raw `Decision` values.

For production debugging, use `DecisionLogEntry(sec, decision, policy)` from middleware hooks such as the FH adapter `OnDecision`. Production logs are compact by default: triggered rules, top reason, deduplicated findings, compact action summary, request ID, method/path, safe entity references, policy version, incident reference, and audit ID. They avoid dumping full request/business/trace/audit internals into every application log line. Development/test or `DecisionLogFull` can include fuller redacted diagnostics when needed.
