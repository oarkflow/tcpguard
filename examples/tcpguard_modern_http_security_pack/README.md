# TCPGuard Modern HTTP Security Pack

This reusable policy pack provides a conservative baseline for public HTTP APIs.
It detects protocol/header anomalies, replay attempts, application probes,
sensitive endpoint access, session drift, and multi-dimensional request abuse.

The runtime also supports atomic distributed nonce consumption, trusted-proxy
CIDR restrictions, and version-2 HMAC signatures that bind request metadata and
the body hash. This is application-layer protection, not volumetric DDoS or
packet filtering: deploy it behind a CDN/WAF or API gateway and provide real
CAPTCHA, MFA, mTLS, and bot-management integrations through application-specific
executors.

Use it in `enforce` mode only after observing findings in `monitor` or `shadow`
mode and tuning thresholds for the application.
