package tcpguard

import (
	"fmt"
	"math"
	"strings"
)

type attackDefinition struct {
	Layer             string
	DefaultSeverity   string
	DefaultThresholds map[string]float64
	Detector          func(detectionContext, attackConfig) detectionOutcome
}

var attackDefinitions = map[string]attackDefinition{
	"icmp_flood": {
		Layer:           "network",
		DefaultSeverity: "critical",
		DefaultThresholds: map[string]float64{
			"rate":      100,
			"bandwidth": 10 * 1024 * 1024,
		},
		Detector: detectICMPFlood,
	},
	"ip_fragmentation": {
		Layer:           "network",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"failure_ratio": 0.3,
			"overlap":       1,
		},
		Detector: detectFragmentationAttack,
	},
	"smurf_attack": {
		Layer:           "network",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"responses":     1000,
			"amplification": 100,
		},
		Detector: detectSmurfAttack,
	},
	"syn_flood": {
		Layer:           "transport",
		DefaultSeverity: "critical",
		DefaultThresholds: map[string]float64{
			"rate":             100,
			"completion_ratio": 0.1,
			"half_open":        50,
		},
		Detector: detectSYNFlood,
	},
	"ack_flood": {
		Layer:           "transport",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"rate":       500,
			"ack_ratio":  0.8,
			"no_session": 50,
		},
		Detector: detectACKFlood,
	},
	"rst_fin_flood": {
		Layer:           "transport",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"rst_rate":     100,
			"rst_ratio":    0.5,
			"state_breach": 2,
		},
		Detector: detectRSTFlood,
	},
	"udp_flood": {
		Layer:           "transport",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"rate":         1000,
			"bandwidth":    10 * 1024 * 1024,
			"unique_ports": 100,
		},
		Detector: detectUDPFlood,
	},
	"tcp_connection_flood": {
		Layer:           "transport",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"active":       100,
			"rate":         50,
			"avg_duration": 1,
		},
		Detector: detectConnectionFlood,
	},
	"http_flood": {
		Layer:           "application",
		DefaultSeverity: "critical",
		DefaultThresholds: map[string]float64{
			"request_rate":   100,
			"path_diversity": 0.1,
			"ua_diversity":   2,
		},
		Detector: detectHTTPFlood,
	},
	"slowloris": {
		Layer:           "application",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"duration":         60,
			"data_rate":        10,
			"connection_count": 10,
			"gap":              10,
		},
		Detector: detectSlowloris,
	},
	"slow_post": {
		Layer:           "application",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"transfer_rate": 100,
			"gap":           30,
			"duration":      300,
		},
		Detector: detectSlowPOST,
	},
	"http_header_flood": {
		Layer:           "application",
		DefaultSeverity: "medium",
		DefaultThresholds: map[string]float64{
			"header_size":  32 * 1024,
			"header_count": 100,
		},
		Detector: detectHTTPHeaderFlood,
	},
	"cache_bypass": {
		Layer:           "application",
		DefaultSeverity: "medium",
		DefaultThresholds: map[string]float64{
			"randomness": 0.5,
		},
		Detector: detectCacheBypass,
	},
	"xml_json_bomb": {
		Layer:           "application",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"payload_size": 10 * 1024 * 1024,
			"depth":        20,
			"expansion":    1000,
		},
		Detector: detectXMLBomb,
	},
	"api_abuse": {
		Layer:           "application",
		DefaultSeverity: "medium",
		DefaultThresholds: map[string]float64{
			"call_rate":     100,
			"exec_time":     10,
			"endpoint_span": 50,
		},
		Detector: detectAPIAbuse,
	},
	"tls_renegotiation": {
		Layer:           "protocol",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"renegotiations": 10,
			"handshake_time": 2,
		},
		Detector: detectTLSRenegotiation,
	},
	"tls_handshake_flood": {
		Layer:           "protocol",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"client_hello":     50,
			"completion_ratio": 0.2,
			"timeouts":         20,
		},
		Detector: detectTLSHandshakeFlood,
	},
	"http2_rapid_reset": {
		Layer:           "protocol",
		DefaultSeverity: "critical",
		DefaultThresholds: map[string]float64{
			"stream_rate": 100,
			"reset_ratio": 0.8,
			"lifetime_ms": 100,
		},
		Detector: detectHTTP2RapidReset,
	},
	"websocket_flood": {
		Layer:           "protocol",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"connections":  50,
			"message_rate": 1000,
			"upgrade_rate": 10,
			"bandwidth":    10 * 1024 * 1024,
		},
		Detector: detectWebSocketFlood,
	},
	"dns_amplification": {
		Layer:           "amplification",
		DefaultSeverity: "critical",
		DefaultThresholds: map[string]float64{
			"query_rate":    100,
			"amplification": 50,
		},
		Detector: detectDNSAmplification,
	},
	"ntp_amplification": {
		Layer:           "amplification",
		DefaultSeverity: "critical",
		DefaultThresholds: map[string]float64{
			"monlist":       10,
			"response_size": 1000,
		},
		Detector: detectNTPAmplification,
	},
	"snmp_amplification": {
		Layer:           "amplification",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"getbulk":       50,
			"response_size": 1024 * 1024,
		},
		Detector: detectSNMPAmplification,
	},
	"memcached_amplification": {
		Layer:           "amplification",
		DefaultSeverity: "critical",
		DefaultThresholds: map[string]float64{
			"udp_requests": 10,
			"amp_factor":   10000,
		},
		Detector: detectMemcachedAmplification,
	},
	"bandwidth_saturation": {
		Layer:           "volumetric",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"total_bandwidth": 0.8,
			"per_ip_share":    0.5,
		},
		Detector: detectBandwidthSaturation,
	},
	"pps_attack": {
		Layer:           "volumetric",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"total_pps":  0.8,
			"per_ip_pps": 10000,
		},
		Detector: detectPPSAttack,
	},
	"connection_table_exhaustion": {
		Layer:           "state",
		DefaultSeverity: "critical",
		DefaultThresholds: map[string]float64{
			"usage":     0.9,
			"syn_recv":  0.25,
			"conn_rate": 1000,
		},
		Detector: detectConnectionTableExhaustion,
	},
	"memory_exhaustion": {
		Layer:           "state",
		DefaultSeverity: "critical",
		DefaultThresholds: map[string]float64{
			"usage":       0.9,
			"growth_rate": 100,
			"per_conn":    100 * 1024 * 1024,
		},
		Detector: detectMemoryExhaustion,
	},
	"cpu_exhaustion": {
		Layer:           "state",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"cpu_usage": 90,
			"exec_time": 10,
			"heavy_ops": 5,
		},
		Detector: detectCPUExhaustion,
	},
	"fd_exhaustion": {
		Layer:           "state",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"usage":       0.9,
			"growth_rate": 100,
			"per_ip":      1000,
		},
		Detector: detectFDExhaustion,
	},
	"redos_attack": {
		Layer:           "advanced",
		DefaultSeverity: "medium",
		DefaultThresholds: map[string]float64{
			"exec_time":  5,
			"complexity": 100,
		},
		Detector: detectReDoS,
	},
	"graphql_complexity": {
		Layer:           "advanced",
		DefaultSeverity: "medium",
		DefaultThresholds: map[string]float64{
			"depth":      10,
			"complexity": 1000,
			"fields":     100,
		},
		Detector: detectGraphQLComplexity,
	},
	"sql_dos": {
		Layer:           "advanced",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"exec_time":     30,
			"expensive_ops": 1,
			"db_cpu":        90,
		},
		Detector: detectSQLDoS,
	},
	"range_request_attack": {
		Layer:           "advanced",
		DefaultSeverity: "medium",
		DefaultThresholds: map[string]float64{
			"range_count":  100,
			"micro_ranges": 50,
		},
		Detector: detectRangeRequestAttack,
	},
	"compression_bomb": {
		Layer:           "advanced",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"ratio":        1000,
			"uncompressed": 1024 * 1024 * 1024,
		},
		Detector: detectCompressionBomb,
	},
	"web_scraping": {
		Layer:           "bot",
		DefaultSeverity: "medium",
		DefaultThresholds: map[string]float64{
			"crawl_rate":    30,
			"pattern_score": 0.5,
		},
		Detector: detectWebScraping,
	},
	"credential_stuffing": {
		Layer:           "bot",
		DefaultSeverity: "high",
		DefaultThresholds: map[string]float64{
			"login_rate":    50,
			"failure_ratio": 0.9,
			"accounts":      20,
		},
		Detector: detectCredentialStuffing,
	},
	"account_enumeration": {
		Layer:           "bot",
		DefaultSeverity: "medium",
		DefaultThresholds: map[string]float64{
			"lookup_rate":   20,
			"pattern_score": 0.5,
		},
		Detector: detectAccountEnumeration,
	},
	"session_exhaustion": {
		Layer:           "misc",
		DefaultSeverity: "medium",
		DefaultThresholds: map[string]float64{
			"session_rate": 100,
			"usage":        0.9,
		},
		Detector: detectSessionExhaustion,
	},
	"resource_locking": {
		Layer:           "misc",
		DefaultSeverity: "medium",
		DefaultThresholds: map[string]float64{
			"lock_rate": 50,
			"hold_time": 30,
			"deadlocks": 5,
		},
		Detector: detectResourceLocking,
	},
	"email_bomb": {
		Layer:           "misc",
		DefaultSeverity: "medium",
		DefaultThresholds: map[string]float64{
			"send_rate":  100,
			"recipients": 1000,
			"size":       25 * 1024 * 1024,
		},
		Detector: detectEmailBomb,
	},
}

func (def attackDefinition) buildConfig(name string, params *ddosRuleParams) attackConfig {
	cfg := attackConfig{
		enabled:    true,
		severity:   def.DefaultSeverity,
		thresholds: make(map[string]float64),
	}
	for k, v := range def.DefaultThresholds {
		cfg.thresholds[k] = v
	}
	if params != nil && params.Attacks != nil {
		if override, ok := params.Attacks[name]; ok {
			if override.Enabled != nil {
				cfg.enabled = *override.Enabled
			}
			if override.Severity != "" {
				cfg.severity = override.Severity
			}
			for k, v := range override.Thresholds {
				cfg.thresholds[k] = v
			}
		}
	}
	return cfg
}

func (cfg attackConfig) threshold(key string, fallback float64) float64 {
	if cfg.thresholds == nil {
		return fallback
	}
	if val, ok := cfg.thresholds[key]; ok {
		return val
	}
	return fallback
}

func detectICMPFlood(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.Metric("icmp_rate", math.NaN())
	threshold := cfg.threshold("rate", 100)
	if !math.IsNaN(rate) && rate >= threshold {
		metrics := map[string]float64{"icmp_rate": rate}
		if bw := dc.snapshot.Metric("icmp_bandwidth", math.NaN()); !math.IsNaN(bw) {
			metrics["icmp_bandwidth"] = bw
		}
		reason := fmt.Sprintf("ICMP rate %.2fpps exceeds %.2fpps", rate, threshold)
		return detectionOutcome{triggered: true, reason: reason, metrics: metrics}
	}
	return detectionOutcome{}
}

func detectFragmentationAttack(dc detectionContext, cfg attackConfig) detectionOutcome {
	ratio := dc.snapshot.Metric("fragment_failure_ratio", math.NaN())
	threshold := cfg.threshold("failure_ratio", 0.3)
	if !math.IsNaN(ratio) && ratio >= threshold {
		reason := fmt.Sprintf("Fragment reassembly failures %.2f exceed %.2f", ratio, threshold)
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"fragment_failure_ratio": ratio}}
	}
	overlap := dc.snapshot.Metric("fragment_overlap", math.NaN())
	if !math.IsNaN(overlap) && overlap >= cfg.threshold("overlap", 1) {
		reason := fmt.Sprintf("Overlapping fragments detected: %.0f", overlap)
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"fragment_overlap": overlap}}
	}
	return detectionOutcome{}
}

func detectSmurfAttack(dc detectionContext, cfg attackConfig) detectionOutcome {
	responses := dc.snapshot.Metric("smurf_response_count", math.NaN())
	if !math.IsNaN(responses) && responses >= cfg.threshold("responses", 1000) {
		reason := fmt.Sprintf("ICMP amplification responses %.0f exceed limit", responses)
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"smurf_response_count": responses}}
	}
	ratio := dc.snapshot.Metric("smurf_amplification", math.NaN())
	if !math.IsNaN(ratio) && ratio >= cfg.threshold("amplification", 100) {
		reason := fmt.Sprintf("Smurf amplification %.2fx above limit", ratio)
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"smurf_amplification": ratio}}
	}
	return detectionOutcome{}
}

func detectSYNFlood(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.Metric("syn_rate", math.NaN())
	if !math.IsNaN(rate) && rate >= cfg.threshold("rate", 100) {
		reason := fmt.Sprintf("SYN rate %.0f exceeds %.0f", rate, cfg.threshold("rate", 100))
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"syn_rate": rate}}
	}
	completion := dc.snapshot.Metric("syn_completion_ratio", math.NaN())
	if !math.IsNaN(completion) && completion <= cfg.threshold("completion_ratio", 0.1) {
		reason := fmt.Sprintf("SYN completion ratio %.2f below %.2f", completion, cfg.threshold("completion_ratio", 0.1))
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"syn_completion_ratio": completion}}
	}
	halfOpen := dc.snapshot.Metric("half_open", math.NaN())
	if !math.IsNaN(halfOpen) && halfOpen >= cfg.threshold("half_open", 50) {
		reason := fmt.Sprintf("Half-open connections %.0f exceed limit", halfOpen)
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"half_open": halfOpen}}
	}
	return detectionOutcome{}
}

func detectACKFlood(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.Metric("ack_rate", math.NaN())
	if !math.IsNaN(rate) && rate >= cfg.threshold("rate", 500) {
		reason := fmt.Sprintf("ACK rate %.0f exceeds %.0f", rate, cfg.threshold("rate", 500))
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"ack_rate": rate}}
	}
	ratio := dc.snapshot.Metric("ack_ratio", math.NaN())
	if !math.IsNaN(ratio) && ratio >= cfg.threshold("ack_ratio", 0.8) {
		reason := fmt.Sprintf("ACK ratio %.2f above %.2f", ratio, cfg.threshold("ack_ratio", 0.8))
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"ack_ratio": ratio}}
	}
	stray := dc.snapshot.Metric("ack_without_conn", math.NaN())
	if !math.IsNaN(stray) && stray >= cfg.threshold("no_session", 50) {
		reason := "ACK packets without session detected"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"ack_without_conn": stray}}
	}
	return detectionOutcome{}
}

func detectRSTFlood(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.Metric("rst_rate", math.NaN())
	if !math.IsNaN(rate) && rate >= cfg.threshold("rst_rate", 100) {
		reason := fmt.Sprintf("RST rate %.0f exceeds %.0f", rate, cfg.threshold("rst_rate", 100))
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"rst_rate": rate}}
	}
	ratio := dc.snapshot.Metric("rst_ratio", math.NaN())
	if !math.IsNaN(ratio) && ratio >= cfg.threshold("rst_ratio", 0.5) {
		reason := fmt.Sprintf("RST ratio %.2f above %.2f", ratio, cfg.threshold("rst_ratio", 0.5))
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"rst_ratio": ratio}}
	}
	breach := dc.snapshot.Metric("rst_without_state", math.NaN())
	if !math.IsNaN(breach) && breach >= cfg.threshold("state_breach", 2) {
		reason := "RST packets without active connections"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"rst_without_state": breach}}
	}
	return detectionOutcome{}
}

func detectUDPFlood(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.Metric("udp_rate", math.NaN())
	if !math.IsNaN(rate) && rate >= cfg.threshold("rate", 1000) {
		reason := fmt.Sprintf("UDP rate %.0f exceeds %.0f", rate, cfg.threshold("rate", 1000))
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"udp_rate": rate}}
	}
	bw := dc.snapshot.Metric("udp_bandwidth", math.NaN())
	if !math.IsNaN(bw) && bw >= cfg.threshold("bandwidth", 10*1024*1024) {
		reason := "UDP bandwidth consumption too high"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"udp_bandwidth": bw}}
	}
	ports := dc.snapshot.Metric("udp_unique_ports", math.NaN())
	if !math.IsNaN(ports) && ports >= cfg.threshold("unique_ports", 100) {
		reason := "UDP flood targeting multiple ports"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"udp_unique_ports": ports}}
	}
	return detectionOutcome{}
}

func detectConnectionFlood(dc detectionContext, cfg attackConfig) detectionOutcome {
	active := dc.snapshot.Metric("tcp_active_connections", math.NaN())
	if !math.IsNaN(active) && active >= cfg.threshold("active", 100) {
		reason := fmt.Sprintf("Active TCP connections %.0f exceed limit", active)
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"tcp_active_connections": active}}
	}
	rate := dc.snapshot.Metric("tcp_connection_rate", math.NaN())
	if !math.IsNaN(rate) && rate >= cfg.threshold("rate", 50) {
		reason := "TCP connection rate unusually high"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"tcp_connection_rate": rate}}
	}
	duration := dc.snapshot.Metric("tcp_avg_duration", math.NaN())
	if !math.IsNaN(duration) && duration <= cfg.threshold("avg_duration", 1) {
		reason := "Connections churn too quickly"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"tcp_avg_duration": duration}}
	}
	return detectionOutcome{}
}

func detectHTTPFlood(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.RequestPerSecond
	if rate >= cfg.threshold("request_rate", 100) {
		reason := fmt.Sprintf("HTTP rate %.2f req/s exceeds %.2f", rate, cfg.threshold("request_rate", 100))
		metrics := map[string]float64{"request_rate": rate, "path_diversity": dc.snapshot.PathDiversity}
		return detectionOutcome{triggered: true, reason: reason, metrics: metrics}
	}
	if dc.snapshot.PathDiversity > 0 && dc.snapshot.PathDiversity <= cfg.threshold("path_diversity", 0.1) && dc.snapshot.RequestPerMinute > 30 {
		reason := "Low path diversity with repetitive requests"
		metrics := map[string]float64{"path_diversity": dc.snapshot.PathDiversity, "request_rate": dc.snapshot.RequestPerMinute}
		return detectionOutcome{triggered: true, reason: reason, metrics: metrics}
	}
	if dc.snapshot.UserAgentDiversity != 0 && float64(dc.snapshot.UserAgentDiversity) <= cfg.threshold("ua_diversity", 2) && dc.snapshot.RequestPerMinute > 50 {
		reason := "Single user-agent driving high volume"
		metrics := map[string]float64{"user_agent_diversity": float64(dc.snapshot.UserAgentDiversity)}
		return detectionOutcome{triggered: true, reason: reason, metrics: metrics}
	}
	if dc.snapshot.UserAgent == "" && dc.snapshot.RequestPerMinute > 10 {
		reason := "Missing User-Agent with high request volume"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"request_rate": dc.snapshot.RequestPerMinute}}
	}
	return detectionOutcome{}
}

func detectSlowloris(dc detectionContext, cfg attackConfig) detectionOutcome {
	duration := dc.snapshot.Metric("slowloris_duration", math.NaN())
	if !math.IsNaN(duration) && duration >= cfg.threshold("duration", 60) {
		reason := "Slowloris connection duration exceeded"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"slowloris_duration": duration}}
	}
	dataRate := dc.snapshot.Metric("slowloris_data_rate", math.NaN())
	if !math.IsNaN(dataRate) && dataRate <= cfg.threshold("data_rate", 10) {
		reason := "Slowloris data rate too low"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"slowloris_data_rate": dataRate}}
	}
	conn := dc.snapshot.Metric("slowloris_connection_count", math.NaN())
	if !math.IsNaN(conn) && conn >= cfg.threshold("connection_count", 10) {
		reason := "Too many slowloris connections"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"slowloris_connection_count": conn}}
	}
	gap := dc.snapshot.Metric("slowloris_gap", math.NaN())
	if !math.IsNaN(gap) && gap >= cfg.threshold("gap", 10) {
		reason := "Large gaps between slowloris bytes"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"slowloris_gap": gap}}
	}
	return detectionOutcome{}
}

func detectSlowPOST(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.Metric("slow_post_rate", math.NaN())
	if !math.IsNaN(rate) && rate <= cfg.threshold("transfer_rate", 100) {
		reason := "Slow POST transfer rate"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"slow_post_rate": rate}}
	}
	gap := dc.snapshot.Metric("slow_post_gap", math.NaN())
	if !math.IsNaN(gap) && gap >= cfg.threshold("gap", 30) {
		reason := "Large gaps between POST chunks"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"slow_post_gap": gap}}
	}
	duration := dc.snapshot.Metric("slow_post_duration", math.NaN())
	if !math.IsNaN(duration) && duration >= cfg.threshold("duration", 300) {
		reason := "Slow POST duration exceeded"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"slow_post_duration": duration}}
	}
	return detectionOutcome{}
}

func detectHTTPHeaderFlood(dc detectionContext, cfg attackConfig) detectionOutcome {
	if dc.snapshot.HeaderSize >= int(cfg.threshold("header_size", 32*1024)) {
		reason := "HTTP headers too large"
		metrics := map[string]float64{"header_size": float64(dc.snapshot.HeaderSize)}
		return detectionOutcome{triggered: true, reason: reason, metrics: metrics}
	}
	if dc.snapshot.HeaderCount >= int(cfg.threshold("header_count", 100)) {
		reason := "HTTP header count too high"
		metrics := map[string]float64{"header_count": float64(dc.snapshot.HeaderCount)}
		return detectionOutcome{triggered: true, reason: reason, metrics: metrics}
	}
	return detectionOutcome{}
}

func detectCacheBypass(dc detectionContext, cfg attackConfig) detectionOutcome {
	randomness := dc.snapshot.QueryRandomness
	if randomness >= cfg.threshold("randomness", 0.5) {
		reason := "Cache-bypass query patterns detected"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"query_randomness": randomness}}
	}
	if strings.Contains(strings.ToLower(dc.snapshot.CacheControl), "no-cache") {
		reason := "Cache-Control header forcing bypass"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{}}
	}
	return detectionOutcome{}
}

func detectXMLBomb(dc detectionContext, cfg attackConfig) detectionOutcome {
	if dc.snapshot.BodySize >= int(cfg.threshold("payload_size", 10*1024*1024)) {
		reason := "Payload size exceeds XML/JSON bomb limit"
		metrics := map[string]float64{"payload_size": float64(dc.snapshot.BodySize)}
		return detectionOutcome{triggered: true, reason: reason, metrics: metrics}
	}
	if depth := dc.snapshot.Metric("payload_depth", math.NaN()); !math.IsNaN(depth) && depth >= cfg.threshold("depth", 20) {
		reason := "Payload nesting depth too high"
		metrics := map[string]float64{"payload_depth": depth}
		return detectionOutcome{triggered: true, reason: reason, metrics: metrics}
	}
	if expand := dc.snapshot.Metric("payload_expansion", math.NaN()); !math.IsNaN(expand) && expand >= cfg.threshold("expansion", 1000) {
		reason := "Entity expansion ratio too large"
		metrics := map[string]float64{"payload_expansion": expand}
		return detectionOutcome{triggered: true, reason: reason, metrics: metrics}
	}
	return detectionOutcome{}
}

func detectAPIAbuse(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.Metric("api_call_frequency", math.NaN())
	if !math.IsNaN(rate) && rate >= cfg.threshold("call_rate", 100) {
		reason := "API call frequency too high"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"api_call_frequency": rate}}
	}
	exec := dc.snapshot.Metric("api_exec_time", math.NaN())
	if !math.IsNaN(exec) && exec >= cfg.threshold("exec_time", 10) {
		reason := "API execution time abused"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"api_exec_time": exec}}
	}
	span := dc.snapshot.Metric("api_endpoint_span", math.NaN())
	if !math.IsNaN(span) && span >= cfg.threshold("endpoint_span", 50) {
		reason := "API enumeration across endpoints"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"api_endpoint_span": span}}
	}
	return detectionOutcome{}
}

func detectTLSRenegotiation(dc detectionContext, cfg attackConfig) detectionOutcome {
	reneg := dc.snapshot.Metric("tls_renegotiation_rate", math.NaN())
	if !math.IsNaN(reneg) && reneg >= cfg.threshold("renegotiations", 10) {
		reason := "TLS renegotiation flood detected"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"tls_renegotiation_rate": reneg}}
	}
	timeSpent := dc.snapshot.Metric("tls_handshake_time", math.NaN())
	if !math.IsNaN(timeSpent) && timeSpent >= cfg.threshold("handshake_time", 2) {
		reason := "TLS handshake time unusually high"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"tls_handshake_time": timeSpent}}
	}
	return detectionOutcome{}
}

func detectTLSHandshakeFlood(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.Metric("tls_client_hello_rate", math.NaN())
	if !math.IsNaN(rate) && rate >= cfg.threshold("client_hello", 50) {
		reason := "TLS ClientHello rate too high"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"tls_client_hello_rate": rate}}
	}
	completion := dc.snapshot.Metric("tls_completion_ratio", math.NaN())
	if !math.IsNaN(completion) && completion <= cfg.threshold("completion_ratio", 0.2) {
		reason := "TLS handshake completion ratio too low"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"tls_completion_ratio": completion}}
	}
	timeouts := dc.snapshot.Metric("tls_timeouts", math.NaN())
	if !math.IsNaN(timeouts) && timeouts >= cfg.threshold("timeouts", 20) {
		reason := "TLS handshake timeouts exceeded"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"tls_timeouts": timeouts}}
	}
	return detectionOutcome{}
}

func detectHTTP2RapidReset(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.Metric("http2_stream_rate", math.NaN())
	if !math.IsNaN(rate) && rate >= cfg.threshold("stream_rate", 100) {
		reason := "HTTP/2 stream creation flood"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"http2_stream_rate": rate}}
	}
	ratio := dc.snapshot.Metric("http2_reset_ratio", math.NaN())
	if !math.IsNaN(ratio) && ratio >= cfg.threshold("reset_ratio", 0.8) {
		reason := "HTTP/2 reset ratio too high"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"http2_reset_ratio": ratio}}
	}
	lifetime := dc.snapshot.Metric("http2_stream_lifetime_ms", math.NaN())
	if !math.IsNaN(lifetime) && lifetime <= cfg.threshold("lifetime_ms", 100) {
		reason := "HTTP/2 streams close too quickly"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"http2_stream_lifetime_ms": lifetime}}
	}
	return detectionOutcome{}
}

func detectWebSocketFlood(dc detectionContext, cfg attackConfig) detectionOutcome {
	connections := dc.snapshot.Metric("ws_connections", math.NaN())
	if !math.IsNaN(connections) && connections >= cfg.threshold("connections", 50) {
		reason := "WebSocket connections exceed limits"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"ws_connections": connections}}
	}
	messageRate := dc.snapshot.Metric("ws_message_rate", math.NaN())
	if !math.IsNaN(messageRate) && messageRate >= cfg.threshold("message_rate", 1000) {
		reason := "WebSocket message flood"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"ws_message_rate": messageRate}}
	}
	upgrades := dc.snapshot.Metric("ws_upgrade_rate", math.NaN())
	if !math.IsNaN(upgrades) && upgrades >= cfg.threshold("upgrade_rate", 10) {
		reason := "WebSocket upgrade abuse"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"ws_upgrade_rate": upgrades}}
	}
	bandwidth := dc.snapshot.Metric("ws_bandwidth", math.NaN())
	if !math.IsNaN(bandwidth) && bandwidth >= cfg.threshold("bandwidth", 10*1024*1024) {
		reason := "WebSocket bandwidth saturation"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"ws_bandwidth": bandwidth}}
	}
	return detectionOutcome{}
}

func detectDNSAmplification(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.Metric("dns_query_rate", math.NaN())
	if !math.IsNaN(rate) && rate >= cfg.threshold("query_rate", 100) {
		reason := "DNS query rate suspicious"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"dns_query_rate": rate}}
	}
	amp := dc.snapshot.Metric("dns_amplification_ratio", math.NaN())
	if !math.IsNaN(amp) && amp >= cfg.threshold("amplification", 50) {
		reason := fmt.Sprintf("DNS amplification %.2fx above threshold", amp)
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"dns_amplification_ratio": amp}}
	}
	return detectionOutcome{}
}

func detectNTPAmplification(dc detectionContext, cfg attackConfig) detectionOutcome {
	monlist := dc.snapshot.Metric("ntp_monlist", math.NaN())
	if !math.IsNaN(monlist) && monlist >= cfg.threshold("monlist", 10) {
		reason := "NTP MONLIST abuse detected"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"ntp_monlist": monlist}}
	}
	size := dc.snapshot.Metric("ntp_response_size", math.NaN())
	if !math.IsNaN(size) && size >= cfg.threshold("response_size", 1000) {
		reason := "Large NTP responses observed"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"ntp_response_size": size}}
	}
	return detectionOutcome{}
}

func detectSNMPAmplification(dc detectionContext, cfg attackConfig) detectionOutcome {
	getbulk := dc.snapshot.Metric("snmp_getbulk", math.NaN())
	if !math.IsNaN(getbulk) && getbulk >= cfg.threshold("getbulk", 50) {
		reason := "SNMP GetBulk flood"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"snmp_getbulk": getbulk}}
	}
	size := dc.snapshot.Metric("snmp_response_size", math.NaN())
	if !math.IsNaN(size) && size >= cfg.threshold("response_size", 1024*1024) {
		reason := "Large SNMP responses detected"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"snmp_response_size": size}}
	}
	return detectionOutcome{}
}

func detectMemcachedAmplification(dc detectionContext, cfg attackConfig) detectionOutcome {
	requests := dc.snapshot.Metric("memcached_udp_requests", math.NaN())
	if !math.IsNaN(requests) && requests >= cfg.threshold("udp_requests", 10) {
		reason := "Memcached UDP requests spike"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"memcached_udp_requests": requests}}
	}
	amp := dc.snapshot.Metric("memcached_amp_factor", math.NaN())
	if !math.IsNaN(amp) && amp >= cfg.threshold("amp_factor", 10000) {
		reason := fmt.Sprintf("Memcached amplification %.0fx", amp)
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"memcached_amp_factor": amp}}
	}
	return detectionOutcome{}
}

func detectBandwidthSaturation(dc detectionContext, cfg attackConfig) detectionOutcome {
	total := dc.snapshot.Metric("total_bandwidth", math.NaN())
	if !math.IsNaN(total) && total >= cfg.threshold("total_bandwidth", 0.8) {
		reason := "Total bandwidth exceeds capacity"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"total_bandwidth": total}}
	}
	perIP := dc.snapshot.Metric("per_ip_bandwidth", math.NaN())
	if !math.IsNaN(perIP) && perIP >= cfg.threshold("per_ip_share", 0.5) {
		reason := "Single IP consuming majority bandwidth"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"per_ip_bandwidth": perIP}}
	}
	return detectionOutcome{}
}

func detectPPSAttack(dc detectionContext, cfg attackConfig) detectionOutcome {
	total := dc.snapshot.Metric("total_pps", math.NaN())
	if !math.IsNaN(total) && total >= cfg.threshold("total_pps", 0.8) {
		reason := "Packets per second exceeding NIC capacity"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"total_pps": total}}
	}
	perIP := dc.snapshot.Metric("pps_per_ip", math.NaN())
	if !math.IsNaN(perIP) && perIP >= cfg.threshold("per_ip_pps", 10000) {
		reason := "Single IP PPS too high"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"pps_per_ip": perIP}}
	}
	return detectionOutcome{}
}

func detectConnectionTableExhaustion(dc detectionContext, cfg attackConfig) detectionOutcome {
	usage := dc.snapshot.Metric("conn_table_usage", math.NaN())
	if !math.IsNaN(usage) && usage >= cfg.threshold("usage", 0.9) {
		reason := "Connection table usage critical"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"conn_table_usage": usage}}
	}
	synRecv := dc.snapshot.Metric("syn_recv_ratio", math.NaN())
	if !math.IsNaN(synRecv) && synRecv >= cfg.threshold("syn_recv", 0.25) {
		reason := "SYN_RECV entries too high"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"syn_recv_ratio": synRecv}}
	}
	rate := dc.snapshot.Metric("connection_rate", math.NaN())
	if !math.IsNaN(rate) && rate >= cfg.threshold("conn_rate", 1000) {
		reason := "Connection creation rate too high"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"connection_rate": rate}}
	}
	return detectionOutcome{}
}

func detectMemoryExhaustion(dc detectionContext, cfg attackConfig) detectionOutcome {
	usage := dc.snapshot.Metric("memory_usage_ratio", math.NaN())
	if !math.IsNaN(usage) && usage >= cfg.threshold("usage", 0.9) {
		reason := "Memory usage exceeded"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"memory_usage_ratio": usage}}
	}
	growth := dc.snapshot.Metric("memory_growth_rate", math.NaN())
	if !math.IsNaN(growth) && growth >= cfg.threshold("growth_rate", 100) {
		reason := "Memory growth too fast"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"memory_growth_rate": growth}}
	}
	perConn := dc.snapshot.Metric("memory_per_connection", math.NaN())
	if !math.IsNaN(perConn) && perConn >= cfg.threshold("per_conn", 100*1024*1024) {
		reason := "Per-connection memory inflated"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"memory_per_connection": perConn}}
	}
	return detectionOutcome{}
}

func detectCPUExhaustion(dc detectionContext, cfg attackConfig) detectionOutcome {
	usage := dc.snapshot.Metric("cpu_usage", math.NaN())
	if !math.IsNaN(usage) && usage >= cfg.threshold("cpu_usage", 90) {
		reason := "CPU usage critical"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"cpu_usage": usage}}
	}
	exec := dc.snapshot.Metric("request_execution_time", math.NaN())
	if !math.IsNaN(exec) && exec >= cfg.threshold("exec_time", 10) {
		reason := "Request execution time too high"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"request_execution_time": exec}}
	}
	heavy := dc.snapshot.Metric("heavy_operation_count", math.NaN())
	if !math.IsNaN(heavy) && heavy >= cfg.threshold("heavy_ops", 5) {
		reason := "Repeated heavy operations detected"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"heavy_operation_count": heavy}}
	}
	return detectionOutcome{}
}

func detectFDExhaustion(dc detectionContext, cfg attackConfig) detectionOutcome {
	usage := dc.snapshot.Metric("fd_usage", math.NaN())
	if !math.IsNaN(usage) && usage >= cfg.threshold("usage", 0.9) {
		reason := "File descriptor usage critical"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"fd_usage": usage}}
	}
	growth := dc.snapshot.Metric("fd_growth_rate", math.NaN())
	if !math.IsNaN(growth) && growth >= cfg.threshold("growth_rate", 100) {
		reason := "File descriptor leak detected"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"fd_growth_rate": growth}}
	}
	perIP := dc.snapshot.Metric("fds_per_ip", math.NaN())
	if !math.IsNaN(perIP) && perIP >= cfg.threshold("per_ip", 1000) {
		reason := "Single IP consuming too many descriptors"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"fds_per_ip": perIP}}
	}
	return detectionOutcome{}
}

func detectReDoS(dc detectionContext, cfg attackConfig) detectionOutcome {
	exec := dc.snapshot.Metric("regex_exec_time", math.NaN())
	if !math.IsNaN(exec) && exec >= cfg.threshold("exec_time", 5) {
		reason := "Regex execution time too high"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"regex_exec_time": exec}}
	}
	complexity := dc.snapshot.Metric("regex_complexity", math.NaN())
	if !math.IsNaN(complexity) && complexity >= cfg.threshold("complexity", 100) {
		reason := "Regex complexity suspicious"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"regex_complexity": complexity}}
	}
	return detectionOutcome{}
}

func detectGraphQLComplexity(dc detectionContext, cfg attackConfig) detectionOutcome {
	depth := dc.snapshot.Metric("graphql_depth", math.NaN())
	if !math.IsNaN(depth) && depth >= cfg.threshold("depth", 10) {
		reason := "GraphQL depth exceeded"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"graphql_depth": depth}}
	}
	complexity := dc.snapshot.Metric("graphql_complexity", math.NaN())
	if !math.IsNaN(complexity) && complexity >= cfg.threshold("complexity", 1000) {
		reason := "GraphQL complexity score high"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"graphql_complexity": complexity}}
	}
	fields := dc.snapshot.Metric("graphql_field_count", math.NaN())
	if !math.IsNaN(fields) && fields >= cfg.threshold("fields", 100) {
		reason := "GraphQL field count large"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"graphql_field_count": fields}}
	}
	return detectionOutcome{}
}

func detectSQLDoS(dc detectionContext, cfg attackConfig) detectionOutcome {
	exec := dc.snapshot.Metric("sql_exec_time", math.NaN())
	if !math.IsNaN(exec) && exec >= cfg.threshold("exec_time", 30) {
		reason := "SQL execution time exceeded"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"sql_exec_time": exec}}
	}
	ops := dc.snapshot.Metric("sql_expensive_operations", math.NaN())
	if !math.IsNaN(ops) && ops >= cfg.threshold("expensive_ops", 1) {
		reason := "Expensive SQL patterns detected"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"sql_expensive_operations": ops}}
	}
	cpu := dc.snapshot.Metric("db_cpu", math.NaN())
	if !math.IsNaN(cpu) && cpu >= cfg.threshold("db_cpu", 90) {
		reason := "Database CPU saturated"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"db_cpu": cpu}}
	}
	return detectionOutcome{}
}

func detectRangeRequestAttack(dc detectionContext, cfg attackConfig) detectionOutcome {
	rangeCount := dc.snapshot.Metric("range_request_count", math.NaN())
	if !math.IsNaN(rangeCount) && rangeCount >= cfg.threshold("range_count", 100) {
		reason := "Too many range requests"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"range_request_count": rangeCount}}
	}
	micro := dc.snapshot.Metric("micro_range_count", math.NaN())
	if !math.IsNaN(micro) && micro >= cfg.threshold("micro_ranges", 50) {
		reason := "Micro range abuse detected"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"micro_range_count": micro}}
	}
	return detectionOutcome{}
}

func detectCompressionBomb(dc detectionContext, cfg attackConfig) detectionOutcome {
	ratio := dc.snapshot.Metric("compression_ratio", math.NaN())
	if !math.IsNaN(ratio) && ratio >= cfg.threshold("ratio", 1000) {
		reason := "Compression ratio suspicious"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"compression_ratio": ratio}}
	}
	size := dc.snapshot.Metric("uncompressed_size", math.NaN())
	if !math.IsNaN(size) && size >= cfg.threshold("uncompressed", 1024*1024*1024) {
		reason := "Uncompressed size extremely large"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"uncompressed_size": size}}
	}
	return detectionOutcome{}
}

func detectWebScraping(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.Metric("crawl_rate", math.NaN())
	if !math.IsNaN(rate) && rate >= cfg.threshold("crawl_rate", 30) {
		reason := "Crawl rate indicates scraping"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"crawl_rate": rate}}
	}
	score := dc.snapshot.Metric("pattern_score", math.NaN())
	if !math.IsNaN(score) && score >= cfg.threshold("pattern_score", 0.5) {
		reason := "Systematic crawling pattern"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"pattern_score": score}}
	}
	ua := strings.ToLower(dc.snapshot.UserAgent)
	if ua != "" && (strings.Contains(ua, "bot") || strings.Contains(ua, "crawler") || strings.Contains(ua, "python")) {
		reason := "Known scraper user-agent"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{}}
	}
	return detectionOutcome{}
}

func detectCredentialStuffing(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.Metric("login_attempt_rate", math.NaN())
	if !math.IsNaN(rate) && rate >= cfg.threshold("login_rate", 50) {
		reason := "Login attempts exceed rate"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"login_attempt_rate": rate}}
	}
	failure := dc.snapshot.Metric("failed_login_ratio", math.NaN())
	if !math.IsNaN(failure) && failure >= cfg.threshold("failure_ratio", 0.9) {
		reason := "Failed login ratio suspicious"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"failed_login_ratio": failure}}
	}
	accounts := dc.snapshot.Metric("accounts_targeted", math.NaN())
	if !math.IsNaN(accounts) && accounts >= cfg.threshold("accounts", 20) {
		reason := "Multiple accounts targeted"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"accounts_targeted": accounts}}
	}
	return detectionOutcome{}
}

func detectAccountEnumeration(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.Metric("lookup_rate", math.NaN())
	if !math.IsNaN(rate) && rate >= cfg.threshold("lookup_rate", 20) {
		reason := "Account lookup rate high"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"lookup_rate": rate}}
	}
	pattern := dc.snapshot.Metric("sequential_pattern_score", math.NaN())
	if !math.IsNaN(pattern) && pattern >= cfg.threshold("pattern_score", 0.5) {
		reason := "Sequential enumeration patterns detected"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"sequential_pattern_score": pattern}}
	}
	return detectionOutcome{}
}

func detectSessionExhaustion(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.Metric("session_creation_rate", math.NaN())
	if !math.IsNaN(rate) && rate >= cfg.threshold("session_rate", 100) {
		reason := "Session creation rate exceeded"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"session_creation_rate": rate}}
	}
	usage := dc.snapshot.Metric("session_usage", math.NaN())
	if !math.IsNaN(usage) && usage >= cfg.threshold("usage", 0.9) {
		reason := "Session store saturated"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"session_usage": usage}}
	}
	return detectionOutcome{}
}

func detectResourceLocking(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.Metric("lock_acquisition_rate", math.NaN())
	if !math.IsNaN(rate) && rate >= cfg.threshold("lock_rate", 50) {
		reason := "Lock acquisition rate too high"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"lock_acquisition_rate": rate}}
	}
	hold := dc.snapshot.Metric("lock_hold_time", math.NaN())
	if !math.IsNaN(hold) && hold >= cfg.threshold("hold_time", 30) {
		reason := "Locks held for too long"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"lock_hold_time": hold}}
	}
	deadlocks := dc.snapshot.Metric("deadlock_count", math.NaN())
	if !math.IsNaN(deadlocks) && deadlocks >= cfg.threshold("deadlocks", 5) {
		reason := "Deadlocks detected"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"deadlock_count": deadlocks}}
	}
	return detectionOutcome{}
}

func detectEmailBomb(dc detectionContext, cfg attackConfig) detectionOutcome {
	rate := dc.snapshot.Metric("email_send_rate", math.NaN())
	if !math.IsNaN(rate) && rate >= cfg.threshold("send_rate", 100) {
		reason := "Email send rate exceeds threshold"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"email_send_rate": rate}}
	}
	recipients := dc.snapshot.Metric("email_recipient_count", math.NaN())
	if !math.IsNaN(recipients) && recipients >= cfg.threshold("recipients", 1000) {
		reason := "Recipient list unusually large"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"email_recipient_count": recipients}}
	}
	size := dc.snapshot.Metric("email_size", math.NaN())
	if !math.IsNaN(size) && size >= cfg.threshold("size", 25*1024*1024) {
		reason := "Email payload size suspicious"
		return detectionOutcome{triggered: true, reason: reason, metrics: map[string]float64{"email_size": size}}
	}
	return detectionOutcome{}
}
