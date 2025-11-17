package tcpguard

import "strings"

var defaultMITMIndicators = []string{
	"invalid_ssl_certificate",
	"abnormal_tls_handshake",
	"suspicious_user_agent",
	"unexpected_headers",
	"anomalous_request_size",
}

func AdvancedMITMCondition(ctx *Context) any {
	if ctx == nil || ctx.FiberCtx == nil {
		return false
	}

	indicators := toStringSlice(ctx.Results["indicators"])
	if len(indicators) == 0 {
		indicators = defaultMITMIndicators
	}
	suspiciousAgents := toStringSlice(ctx.Results["suspiciousUserAgents"])
	severity := "high"
	if custom, ok := ctx.Results["severity"].(string); ok && custom != "" {
		severity = custom
	}

	telemetry := gatherTelemetrySignals(ctx)
	var findings []AttackFinding
	for _, indicator := range indicators {
		triggered, reason, metrics := evaluateMITMIndicator(indicator, ctx, suspiciousAgents, telemetry)
		if triggered {
			findings = append(findings, AttackFinding{
				Name:     "mitm_" + indicator,
				Layer:    "application",
				Severity: severity,
				Reason:   reason,
				Metrics:  metrics,
			})
		}
	}

	if len(findings) == 0 {
		return false
	}

	ctx.Results["mitmFindings"] = findings
	recordMitmObservability(ctx, findings)
	return true
}

func evaluateMITMIndicator(indicator string, ctx *Context, suspiciousAgents []string, telemetry map[string]float64) (bool, string, map[string]float64) {
	c := ctx.FiberCtx
	switch indicator {
	case "invalid_ssl_certificate":
		if isCertificateInvalid(ctx) {
			return true, "client connection presented invalid TLS certificate", nil
		}
	case "abnormal_tls_handshake":
		if ratio, ok := lookupTelemetryMetric(telemetry, ctx, "tls_handshake_failure_ratio", "tlsHandshakeFailureRatio"); ok && ratio > 0.3 {
			return true, "abnormally high TLS handshake failure ratio", map[string]float64{"tls_handshake_failure_ratio": ratio}
		}
		if latency, ok := lookupTelemetryMetric(telemetry, ctx, "tls_handshake_duration", "tlsHandshakeDurationMs"); ok && latency > 1500 {
			return true, "slow TLS handshake duration", map[string]float64{"tls_handshake_duration_ms": latency}
		}
	case "suspicious_user_agent":
		ua := strings.ToLower(c.Get("User-Agent"))
		if ua == "" {
			return true, "missing user-agent header on protected route", nil
		}
		patterns := suspiciousAgents
		if len(patterns) == 0 {
			patterns = []string{"mitmproxy", "burp", "owasp", "scanner", "curl", "python"}
		}
		for _, pattern := range patterns {
			if pattern == "" {
				continue
			}
			if strings.Contains(ua, strings.ToLower(pattern)) {
				return true, "user-agent matched suspicious pattern", map[string]float64{"pattern_match": 1}
			}
		}
	case "unexpected_headers":
		headers := c.GetReqHeaders()
		largeHeaderThreshold := 4096.0
		longHeaders := 0.0
		duplicateForwardChain := 0.0
		for name, values := range headers {
			for _, value := range values {
				if len(value) > int(largeHeaderThreshold) {
					longHeaders++
				}
				if strings.EqualFold(name, "X-Forwarded-Host") && strings.Contains(value, ",") {
					duplicateForwardChain++
				}
				if strings.EqualFold(name, "Proxy-Connection") {
					return true, "proxy connection header present", nil
				}
			}
		}
		if longHeaders > 0 {
			return true, "oversized headers detected", map[string]float64{"oversized_headers": longHeaders}
		}
		if duplicateForwardChain > 0 {
			return true, "multiple forwarded hosts in header", map[string]float64{"x_forwarded_host_entries": duplicateForwardChain}
		}
	case "anomalous_request_size":
		bodySize := float64(len(c.Body()))
		headerSize := approximateHeaderSize(c.GetReqHeaders())
		contentLength := float64(c.Request().Header.ContentLength())
		if contentLength <= 0 {
			contentLength = bodySize
		}
		if contentLength > 10*1024*1024 || headerSize > 32*1024 {
			return true, "request exceeded safe size thresholds", map[string]float64{"body_bytes": bodySize, "header_bytes": headerSize}
		}
		if ratio, ok := lookupTelemetryMetric(telemetry, ctx, "request_size_anomaly", "requestCompressionRatio"); ok && ratio > 1000 {
			return true, "suspicious compression ratio", map[string]float64{"compression_ratio": ratio}
		}
	}
	return false, "", nil
}

func gatherTelemetrySignals(ctx *Context) map[string]float64 {
	signals := make(map[string]float64)
	if ctx == nil {
		return signals
	}
	if m, ok := ctx.Results["telemetry"].(map[string]any); ok {
		for key, value := range m {
			if f, ok := toFloat(value); ok {
				signals[key] = f
			}
		}
	}
	if ctx.FiberCtx != nil {
		if payload, ok := ctx.FiberCtx.Locals("tcpguard.telemetry").(map[string]any); ok {
			for key, value := range payload {
				if _, exists := signals[key]; exists {
					continue
				}
				if f, ok := toFloat(value); ok {
					signals[key] = f
				}
			}
		}
	}
	return signals
}

func lookupTelemetryMetric(telemetry map[string]float64, ctx *Context, keys ...string) (float64, bool) {
	for _, key := range keys {
		if val, ok := telemetry[key]; ok {
			return val, true
		}
		if raw, ok := ctx.Results[key]; ok {
			if f, ok := toFloat(raw); ok {
				return f, true
			}
		}
	}
	return 0, false
}

func isCertificateInvalid(ctx *Context) bool {
	if ctx == nil || ctx.FiberCtx == nil {
		return false
	}
	if val, ok := ctx.Results["sslValid"].(bool); ok {
		return !val
	}
	if val, ok := ctx.FiberCtx.Locals("tcpguard.ssl.valid").(bool); ok {
		return !val
	}
	if val, ok := ctx.FiberCtx.Locals("tcpguard.tls.verified").(bool); ok {
		return !val
	}
	return false
}

func approximateHeaderSize(headers map[string][]string) float64 {
	size := 0
	for key, values := range headers {
		entry := len(key)
		for _, value := range values {
			entry += len(value)
		}
		size += entry
	}
	return float64(size)
}

func recordMitmObservability(ctx *Context, findings []AttackFinding) {
	if ctx == nil || ctx.RuleEngine == nil {
		return
	}
	clientIP := ""
	if ctx.FiberCtx != nil {
		clientIP = ctx.RuleEngine.GetClientIP(ctx.FiberCtx)
	}
	endpoint := ""
	if ctx.FiberCtx != nil {
		endpoint = ctx.FiberCtx.Path()
	}
	if ctx.RuleEngine.metrics != nil {
		for _, finding := range findings {
			ctx.RuleEngine.metrics.IncrementCounter("mitm_detection_total", map[string]string{
				"indicator": finding.Name,
				"severity":  finding.Severity,
			})
		}
	}
	if ctx.RuleEngine.detectionLedger != nil && clientIP != "" {
		ctx.RuleEngine.detectionLedger.Record(DetectionEvent{
			ClientIP: clientIP,
			Endpoint: endpoint,
			Findings: findings,
		})
	}
}
