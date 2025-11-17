# Login Hours Enforcement

This scenario shows how to block suspicious login attempts that happen outside of the retail bank's help-desk hours.

## Files

- `configs/global/access.json` – trust corporate CIDRs and apply escalation rules.
- `configs/rules/businessHours.json` – pipeline that checks `/api/login` requests against 08:00-20:00 ET.
- `configs/endpoints/login.json` – rate limits login traffic and adds a ban action when a client keeps probing after hours.

## Run locally

```bash
PORT=3001 go run ./examples/business/login-hours
```

Send a POST request to `/api/login` before 08:00 ET or after 20:00 ET to see the temporary ban message. During allowed hours, normal login throttling applies.
