# Detector Reference

The `detectors/` quick reference helps you understand which telemetry keys drive each attack definition. Combine this with the playbooks under `../playbooks/` to enable fine-grained protection.

| Category | Detector | Key Telemetry Inputs |
| --- | --- | --- |
| Network | `icmp_flood` | `telemetry.icmp_rate`, `telemetry.icmp_bandwidth` |
| Network | `ip_fragmentation` | `telemetry.fragment_failure_ratio`, `telemetry.fragment_overlap` |
| Network | `smurf_attack` | `telemetry.smurf_response_count`, `telemetry.smurf_amplification` |
| Transport | `syn_flood` | `telemetry.syn_rate`, `telemetry.half_open`, `telemetry.syn_completion_ratio` |
| Transport | `ack_flood` | `telemetry.ack_rate`, `telemetry.ack_ratio`, `telemetry.no_session` |
| Transport | `udp_flood` | `telemetry.udp_rate`, `telemetry.udp_bandwidth`, `telemetry.unique_ports` |
| Application | `http_flood` | Request profiler RPM, `telemetry.request_rate`, `telemetry.path_diversity` |
| Application | `slowloris` | `telemetry.slowloris_duration`, `telemetry.slowloris_connection_count` |
| Application | `xml_json_bomb` | `telemetry.payload_size`, `telemetry.payload_depth`, `telemetry.payload_expansion` |
| Protocol | `tls_renegotiation` | `telemetry.tls_renegotiation_rate`, `telemetry.tls_handshake_time` |
| Protocol | `http2_rapid_reset` | `telemetry.http2_stream_rate`, `telemetry.http2_reset_ratio` |
| Amplification | `dns_amplification` | `telemetry.dns_query_rate`, `telemetry.dns_amplification_ratio` |
| Amplification | `memcached_amplification` | `telemetry.memcached_udp_requests`, `telemetry.memcached_amp_factor` |
| Volumetric | `bandwidth_saturation` | `telemetry.total_bandwidth`, `telemetry.per_ip_bandwidth` |
| State | `connection_table_exhaustion` | `telemetry.conn_table_usage`, `telemetry.syn_recv_ratio` |
| Advanced | `redos_attack` | `telemetry.regex_exec_time`, `telemetry.regex_complexity` |
| Advanced | `graphql_complexity` | `telemetry.graphql_depth`, `telemetry.graphql_complexity` |
| Bot | `web_scraping` | `telemetry.crawl_rate`, `telemetry.pattern_score` |
| Bot | `credential_stuffing` | `telemetry.login_attempt_rate`, `telemetry.failed_login_ratio` |
| Misc | `email_bomb` | `telemetry.email_send_rate`, `telemetry.email_recipient_count`, `telemetry.email_size` |

> **Tip:** You can feed these telemetry keys via `fiber.Ctx.Locals("tcpguard.telemetry", map[string]any{...})` or persist them globally with `RuleEngine.IngestTelemetry`. The detectors automatically merge profiler data, locals, and stored telemetry into the evaluation snapshot.
