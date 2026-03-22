# TCPGuard Security Framework Example

A hardened, production-ready security framework demonstrating all TCPGuard components wired together: risk scoring, identity risk assessment, policy engine, correlation, playbooks, and investigation API.

## Security Features

| Feature | Implementation |
|---------|---------------|
| Password storage | bcrypt-hashed (constant-time comparison) |
| JWT tokens | HMAC-SHA256 signed with expiry claims |
| MFA | HMAC-based time codes (30s steps, clock-skew tolerant) |
| Session management | 24h absolute TTL, 30min idle timeout, auto-cleanup |
| Device trust | New devices start unverified; separate enrollment required |
| Rate limiting | Token bucket with LRU eviction (max 100K buckets) |
| Bot detection | Policy-based denial on sensitive routes |
| Request validation | Body size limit (16KB), request ID format validation |
| Security headers | CSP, HSTS, X-Frame-Options, X-Content-Type-Options |
| Error handling | Generic messages to clients, detailed server-side logging |

## Route Tiers

| Tier | Routes | Requirements |
|------|--------|-------------|
| 0 | `/api/public`, `/api/public/status` | None |
| 1 | `/api/user/profile`, `/api/user/settings` | Authenticated session |
| 2 | `/api/billing/export`, `/api/billing/invoices` | Session + verified device |
| 3 | `/admin/export`, `/admin/users`, `/admin/config` | Session + MFA + verified device |
| - | `/health` | None (minimal info) |
| - | `/metrics`, `/security/*`, `/investigate/*` | Authenticated session |

## Quick Start

### 1. Run the Server

```bash
# From the tcpguard project root
go run ./examples/security-framework

# Or with a custom port
PORT=8080 go run ./examples/security-framework

# With a persistent JWT signing key (recommended for production)
JWT_SIGNING_KEY=your-secret-key-here go run ./examples/security-framework
```

### 2. Run the Pentest Suite

```bash
go test ./examples/security-framework/ -v -count=1
```

## Usage Walkthrough

### Public Access (Tier 0)

No authentication required:

```bash
# Public content
curl http://localhost:4000/api/public

# Health check
curl http://localhost:4000/health
```

### Login (Get a Session)

```bash
# Login with credentials
curl -s -X POST http://localhost:4000/auth/login \
  -H 'Content-Type: application/json' \
  -H 'X-Device-ID: my-laptop' \
  -H 'User-Agent: Mozilla/5.0 Chrome/120' \
  -d '{"username":"alice","password":"correct"}'
```

Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "session_id": "6ff0a669-9798-412f-9189-a8c9657946d8",
  "user": "alice",
  "message": "login successful",
  "risk": 0
}
```

Save the `session_id` for subsequent requests.

### Authenticated Routes (Tier 1)

Pass your session ID in the `X-Session-ID` header:

```bash
curl http://localhost:4000/api/user/profile \
  -H 'X-User-ID: alice' \
  -H 'X-Session-ID: <your-session-id>'
```

### MFA Verification (Required for Tier 3)

MFA codes are HMAC-SHA256 time-based (30-second steps). Generate a code using the user's MFA secret:

```python
import hmac, hashlib, time

# Demo MFA secrets (from source):
#   alice: ALICE_MFA_SECRET_2024
#   bob:   BOB_MFA_SECRET_2024
#   admin: ADMIN_MFA_SECRET_2024

secret = "ADMIN_MFA_SECRET_2024"
step = int(time.time()) // 30
code = hmac.new(secret.encode(), str(step).encode(), hashlib.sha256).hexdigest()[:6]
print(code)
```

Then verify it:

```bash
curl -s -X POST http://localhost:4000/auth/mfa/verify \
  -H 'Content-Type: application/json' \
  -H 'X-User-ID: admin' \
  -H 'X-Session-ID: <your-session-id>' \
  -d '{"code":"<mfa-code>","session_id":"<your-session-id>"}'
```

### Billing Routes (Tier 2) — Requires Verified Device

New devices start as **unverified** on first login. To access Tier 2 routes, the device must be enrolled and verified through a separate process (in production, this would be email confirmation or admin approval).

```bash
curl http://localhost:4000/api/billing/export \
  -H 'X-User-ID: alice' \
  -H 'X-Session-ID: <your-session-id>' \
  -H 'X-Device-ID: <your-device-id>'
```

### Admin Routes (Tier 3) — Requires Session + MFA + Verified Device

```bash
curl http://localhost:4000/admin/export \
  -H 'X-User-ID: admin' \
  -H 'X-Session-ID: <your-session-id>' \
  -H 'X-Device-ID: <your-device-id>'
```

### Token Refresh

Tokens expire after 1 hour. Refresh before expiry:

```bash
curl -s -X POST http://localhost:4000/auth/token/refresh \
  -H 'Content-Type: application/json' \
  -H 'X-User-ID: alice' \
  -H 'X-Session-ID: <your-session-id>' \
  -d '{"token":"<your-current-token>"}'
```

The old token is revoked immediately. Replaying a used token returns `"token revoked"`.

### Logout

```bash
curl -s -X POST http://localhost:4000/auth/logout \
  -H 'X-User-ID: alice' \
  -H 'X-Session-ID: <your-session-id>'
```

### Security Dashboard (Authenticated)

```bash
# Dashboard summary
curl http://localhost:4000/security/dashboard \
  -H 'X-User-ID: admin' \
  -H 'X-Session-ID: <your-session-id>'

# Query security events
curl "http://localhost:4000/security/events?type=auth_failure" \
  -H 'X-User-ID: admin' \
  -H 'X-Session-ID: <your-session-id>'

# Prometheus metrics
curl http://localhost:4000/metrics \
  -H 'X-User-ID: admin' \
  -H 'X-Session-ID: <your-session-id>'
```

## Demo Users

| Username | Password | MFA Secret |
|----------|----------|------------|
| `alice` | `correct` | `ALICE_MFA_SECRET_2024` |
| `bob` | `correct` | `BOB_MFA_SECRET_2024` |
| `admin` | `correct` | `ADMIN_MFA_SECRET_2024` |

## How the Security Layers Work

```
Request
  │
  ├─ Security Headers (CSP, HSTS, X-Frame-Options, etc.)
  ├─ Request ID Validation (UUID format, max 64 chars)
  │
  ├─ /health ─────────────────────────── Public (minimal info)
  │
  ├─ Risk Scoring Middleware ──────────── Evaluates 6 signals:
  │   │                                    brute force, new device,
  │   │                                    IP reputation, privileged route,
  │   │                                    automation (bot), identity risk
  │   │
  │   ├─ Policy Engine (7 policies) ──── Emergency, behavioral,
  │   │                                    context-aware, static rules
  │   │
  │   ├─ Score < 0.30 ── Allow
  │   ├─ Score 0.30-0.55 ── Challenge (429)
  │   ├─ Score 0.55-0.80 ── Contain (monitor)
  │   └─ Score > 0.80 ── Deny (403)
  │
  ├─ requireAuth ──── Validates session from state store
  │                    (24h absolute TTL, 30min idle timeout)
  │
  ├─ requireDeviceTrust ── Checks device verification status
  │
  └─ requireMFA ── Checks MFA verification on session
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `4000` | Server listen port |
| `JWT_SIGNING_KEY` | Random (generated at startup) | HMAC-SHA256 signing key for tokens. Set a persistent value in production. |

## Pentest Coverage

The test suite (`pentest_test.go`) covers 31 tests across 12 attack categories:

1. **Brute Force** — Login blocking, rotating usernames, recovery
2. **Credential Stuffing** — High-volume distinct credentials, mixed valid/invalid
3. **Privilege Escalation** — Unauthenticated admin, tier escalation without MFA/device
4. **Bot/Automation Detection** — curl/wget/python UAs blocked on sensitive routes
5. **Rate Limiting & DoS** — Rapid fire, slowloris, burst patterns
6. **Session & Token Attacks** — Token replay, session fixation, logout invalidation
7. **Input Injection** — SQL injection, XSS, path traversal, command injection
8. **Information Leakage** — No stack traces, no framework disclosure, security headers
9. **Policy Bypass** — Fail-closed behavior, emergency policy activation
10. **Correlation & Forensics** — Attack path creation, timeline recording
11. **Identity Risk** — New device detection, impossible travel, account lockout
12. **Playbook Execution** — Automated response triggers, cooldown enforcement
