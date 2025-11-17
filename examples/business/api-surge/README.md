# API Surge Protection

Guards the `/api/data/export` endpoint against sudden scraping bursts and runaway integrations.

- The pipeline ties `checkEndpoint` to the advanced `ddos` function but scopes metrics to API-specific telemetry.
- Endpoint config layers stricter rate limits and jitter responses so customer-facing systems degrade gracefully.

## Run

```bash
PORT=3005 go run ./examples/business/api-surge
```

Generate a burst of `GET /api/data/export` calls (or feed synthetic telemetry) to watch the surge guard kick in.
