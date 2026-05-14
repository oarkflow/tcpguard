# TCPGuard

TCPGuard is a runtime security policy engine for Go services. It sits in front of Fiber v3 or `net/http` handlers, builds a security context for each request, evaluates BCL policies, scores risk, runs detectors, executes response actions, and records audit evidence.

Use it when application security logic has outgrown scattered middleware and hard-coded `if` statements. TCPGuard lets teams describe controls such as rate abuse, bad IP blocking, replay protection, tenant lockdowns, sensitive endpoint rules, approval gates, and high-value business workflows as policy packs that can be validated, simulated, reloaded, and audited.

## What It Does

- **Inline enforcement for Go apps** through Fiber v3 middleware or `net/http` middleware.
- **BCL policy packs** with `pack`, `guard`, `rule`, `trigger`, `action`, `datasource`, `lookup`, `detector`, `intel`, `baseline`, `threat_model`, and `policy_safety` blocks.
- **Rich request context** covering request, network, user, tenant, session, device, business, runtime, security, rate, and custom facts.
- **Built-in detectors** for header anomalies, sensitive endpoints, nonce/signature replay checks, rate abuse, session drift, and business anomalies.
- **Risk-based decisions** including allow, monitor, challenge, throttle, block, revoke, and escalate.
- **Action orchestration** for blocking, throttling, challenges, bans, locks, incidents, notifications, webhooks, and custom executors.
- **External data access** through memory/cache, Redis, CSV, JSON, SQL, and HTTP datasources.
- **Threat intel and enrichment** from file feeds, lookup enrichers, baselines, and threat model decoration.
- **Approval workflows** that can hold destructive actions until an authorized reviewer approves them.
- **Tamper-evident audit** with deterministic request fingerprints and verifiable audit envelope chains.
- **Custom enforcement responses** with pluggable status codes, headers, and JSON bodies.
- **Metrics hooks** for decisions, detectors, actions, and reloads, including an in-memory recorder for local use.
- **Simulation and reloads** through APIs, a management server, and the `cmd/tcpguard` CLI.
- **Local and distributed stores** with `MemoryStore` for local/test use and `RedisStore` for distributed runtime state, approvals, incidents, and audit envelopes.

## Quick Start

Install/import the module:

```sh
go get github.com/oarkflow/condition/tcpguard
```

Load a policy pack and attach TCPGuard to a Fiber v3 app:

```go
package main

import (
    "context"
    "log"

    "github.com/gofiber/fiber/v3"
    "github.com/oarkflow/condition/tcpguard"
    "github.com/oarkflow/condition/tcpguard/bcl"
)

func main() {
    ctx := context.Background()

    bundle, err := bcl.LoadTCPGuardBundleDir(ctx, "./policy")
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
    app.Use(guard.Middleware())
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

## Operator CLI

The repository includes a CLI for validation, simulation, explanation, policy diffing, smoke tests, and reload checks:

```sh
go run ./cmd/tcpguard validate -dir ./examples/tcpguard_multi_file_policy_pack
go run ./cmd/tcpguard simulate -dir ./examples/tcpguard_multi_file_policy_pack -request ./examples/tcpguard_multi_file_policy_pack/request.json
go run ./cmd/tcpguard explain -dir ./examples/tcpguard_multi_file_policy_pack -request ./examples/tcpguard_multi_file_policy_pack/request.json
go run ./cmd/tcpguard test -dir ./examples/tcpguard_multi_file_policy_pack -request ./examples/tcpguard_multi_file_policy_pack/request.json
go run ./cmd/tcpguard diff -before-dir ./policy-old -after-dir ./policy-new -request ./request.json
```

## Examples

- [Fiber server example](examples/tcpguard_fiber_server/README.md): end-to-end Fiber v3 app with policy packs, datasources, GeoIP, approvals, incidents, and audit.
- [net/http server example](examples/tcpguard_http_server/README.md): standard library middleware with custom responses, metrics, management endpoints, and policy assertions.
- [Multi-file policy pack](examples/tcpguard_multi_file_policy_pack/README.md): directory-based policy layout with shared actions, intel, triggers, and endpoint/business/session rules.
- [Single-file banking pack](examples/tcpguard_banking_protection_pack/tcpguard.bcl): compact policy pack in one BCL file.

## Documentation

- [Usage Guide](docs/usage.md): installation, middleware setup, policy loading, CLI usage, management endpoints, performance options, stores, and reloads.
- [Use Cases](docs/use-cases.md): practical security scenarios TCPGuard handles today.
- [Enhancements](docs/enhancements.md): candid roadmap of missing or high-value improvements.
- [Production Guide](docs/production.md): Redis, proxy headers, reloads, GeoIP, safety settings, and failure modes.
- [Security Hardening](docs/security.md): secrets, webhooks, command actions, audit redaction, and approvals.
- [Versioning](docs/versioning.md): policy pack compatibility and migration guidance.
- [Policy Authoring](docs/authoring.md): pack structure, rule checklist, assertions, naming, and integration guidance.

## Current Status

TCPGuard already includes runtime enforcement, policy loading, detectors, datasource lookups, approvals, audit envelopes, simulation, reload primitives, response customization, metrics hooks, CLI assertions, Redis-backed audit/incidents, tests, benchmarks, and runnable examples. The most important next improvements are broader integration-specific executors, richer policy linting, and more production deployment templates.
