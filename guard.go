package tcpguard

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type Rule interface {
	Name() string
	Check(ctx context.Context, req *http.Request, guard *Guard) (anomaly bool, actions []ActionRef, err error)
}

type Action interface {
	Name() string
	Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]any) error
}

type responseWriter struct {
	http.ResponseWriter
	written bool
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	if !rw.written {
		rw.ResponseWriter.WriteHeader(statusCode)
		rw.written = true
	}
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	if !rw.written {
		rw.ResponseWriter.WriteHeader(http.StatusOK)
		rw.written = true
	}
	return rw.ResponseWriter.Write(data)
}

func (rw *responseWriter) Header() http.Header {
	return rw.ResponseWriter.Header()
}

type RuleConfig struct {
	Name        string                     `json:"name"`
	Conditions  []ConditionConfig          `json:"conditions"`
	ActionsList []ActionRef                `json:"actions,omitempty"`
	ActionsMap  map[string]json.RawMessage `json:"actions_map,omitempty"`
	Scope       string                     `json:"scope,omitempty"`
}

type ConditionConfig struct {
	Type     string         `json:"type"`
	Config   map[string]any `json:"config"`
	Operator string         `json:"operator,omitempty"`
}

type ActionRef struct {
	Name     string         `json:"name"`
	Override map[string]any `json:"override,omitempty"`
	Stop     bool           `json:"stop,omitempty"`
}

type ActionConfig struct {
	Type     string         `json:"type"`
	Name     string         `json:"name"`
	Config   map[string]any `json:"config"`
	Response map[string]any `json:"response"`
}

type Config struct {
	Rules     []RuleConfig   `json:"rules"`
	Actions   []ActionConfig `json:"actions"`
	TCPListen string         `json:"tcp_listen,omitempty"`
	TCPRules  []RuleConfig   `json:"tcp_rules,omitempty"`
}

type GenericRule struct {
	name       string
	conditions []ConditionConfig
	actions    []ActionRef
}

func (r *GenericRule) Name() string { return r.name }

func (r *GenericRule) Check(ctx context.Context, req *http.Request, guard *Guard) (bool, []ActionRef, error) {
	if len(r.conditions) == 0 {
		return false, nil, nil
	}
	useOr := false
	for _, c := range r.conditions {
		if strings.ToLower(c.Operator) == "or" {
			useOr = true
			break
		}
	}
	if useOr {
		for _, cond := range r.conditions {
			checkFunc, ok := conditionRegistry[cond.Type]
			if !ok {
				return false, nil, fmt.Errorf("unknown condition type: %s", cond.Type)
			}
			anomaly, err := checkFunc(ctx, req, guard, cond.Config)
			if err != nil {
				return false, nil, err
			}
			if anomaly {
				return true, r.actions, nil
			}
		}
		return false, nil, nil
	}
	for _, cond := range r.conditions {
		checkFunc, ok := conditionRegistry[cond.Type]
		if !ok {
			return false, nil, fmt.Errorf("unknown condition type: %s", cond.Type)
		}
		anomaly, err := checkFunc(ctx, req, guard, cond.Config)
		if err != nil {
			return false, nil, err
		}
		if !anomaly {
			return false, nil, nil
		}
	}
	return true, r.actions, nil
}

type ConditionCheckFunc func(ctx context.Context, req *http.Request, guard *Guard, config map[string]any) (bool, error)

var conditionRegistry = map[string]ConditionCheckFunc{
	"request_count":       requestCountCondition,
	"path_prefix":         pathPrefixCondition,
	"header_equals":       headerEqualsCondition,
	"method_in":           methodInCondition,
	"ip_in":               ipInCondition,
	"global_request_rate": globalRequestRateCondition,
	"mitm_suspect":        mitmSuspectCondition,
}

// mitmSuspectCondition does light heuristics to detect MITM-like requests
// Checks for uncommon or missing TLS/proxy headers or header mutations typical of MITM
func mitmSuspectCondition(ctx context.Context, req *http.Request, guard *Guard, config map[string]any) (bool, error) {
	// Simple heuristics: if X-Forwarded-For present but missing Host, or suspicious Via header
	via := req.Header.Get("Via")
	xff := req.Header.Get("X-Forwarded-For")
	host := req.Host
	if xff != "" && host == "" {
		return true, nil
	}
	if strings.Contains(strings.ToLower(via), "mitm") || strings.Contains(strings.ToLower(via), "proxy") {
		return true, nil
	}
	// detect common TLS downgrade indicator: absence of expected headers for https routes
	if strings.HasPrefix(req.URL.Path, "/secure") {
		if req.TLS == nil {
			return true, nil
		}
	}
	return false, nil
}

func getString(m map[string]any, key string, def string) (string, error) {
	v, ok := m[key]
	if !ok {
		return def, nil
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("%s must be a string", key)
	}
	return s, nil
}

func getIntFromFloat(m map[string]any, key string, def int) (int, error) {
	v, ok := m[key]
	if !ok {
		return def, nil
	}
	switch vv := v.(type) {
	case float64:
		return int(vv), nil
	case int:
		return vv, nil
	default:
		return 0, fmt.Errorf("%s must be numeric", key)
	}
}

func requestCountCondition(ctx context.Context, req *http.Request, guard *Guard, config map[string]any) (bool, error) {
	uri := strings.TrimSuffix(config["uri"].(string), "/")
	methodsInterface := config["methods"].([]any)
	var methods []string
	for _, m := range methodsInterface {
		methods = append(methods, m.(string))
	}
	threshold := int(config["threshold"].(float64))
	unitStr := config["unit"].(string)
	var unit time.Duration
	switch unitStr {
	case "second":
		unit = time.Second
	case "minute":
		unit = time.Minute
	case "hour":
		unit = time.Hour
	default:
		unit = time.Minute
	}
	operator := config["operator"].(string)
	if !strings.HasPrefix(req.URL.Path, uri) {
		return false, nil
	}
	matched := false
	for _, m := range methods {
		if req.Method == m {
			matched = true
			break
		}
	}
	if !matched {
		return false, nil
	}
	ip := getIP(req)
	key := ip + uri
	now := time.Now()
	guard.mu.Lock()
	defer guard.mu.Unlock()
	times := guard.requestTimes[key]
	var newTimes []time.Time
	for _, t := range times {
		if now.Sub(t) < unit {
			newTimes = append(newTimes, t)
		}
	}
	newTimes = append(newTimes, now)
	guard.requestTimes[key] = newTimes
	count := len(newTimes)

	var anomaly bool
	switch operator {
	case ">":
		anomaly = count > threshold
	case ">=":
		anomaly = count >= threshold
	case "==":
		anomaly = count == threshold
	case "<":
		anomaly = count < threshold
	}
	log.Printf("IP=%s URI=%s Count=%d Threshold=%d Anomaly=%v\n", ip, uri, count, threshold, anomaly)
	return anomaly, nil
}

func pathPrefixCondition(ctx context.Context, req *http.Request, guard *Guard, config map[string]any) (bool, error) {
	prefix, err := getString(config, "prefix", "")
	if err != nil {
		return false, err
	}
	if prefix == "" {
		return false, fmt.Errorf("path_prefix requires 'prefix' field")
	}
	return strings.HasPrefix(req.URL.Path, prefix), nil
}

func headerEqualsCondition(ctx context.Context, req *http.Request, guard *Guard, config map[string]any) (bool, error) {
	headerName, err := getString(config, "header", "")
	if err != nil {
		return false, err
	}
	expected, err := getString(config, "value", "")
	if err != nil {
		return false, err
	}
	if headerName == "" {
		return false, fmt.Errorf("header_equals requires 'header' field")
	}
	val := req.Header.Get(headerName)
	return val == expected, nil
}

func methodInCondition(ctx context.Context, req *http.Request, guard *Guard, config map[string]any) (bool, error) {
	methodsRaw, ok := config["methods"]
	if !ok {
		return false, fmt.Errorf("method_in requires 'methods' array")
	}
	switch mr := methodsRaw.(type) {
	case []any:
		for _, m := range mr {
			if ms, ok := m.(string); ok && req.Method == ms {
				return true, nil
			}
		}
		return false, nil
	default:
		return false, fmt.Errorf("method_in methods must be array")
	}
}

func ipInCondition(ctx context.Context, req *http.Request, guard *Guard, config map[string]any) (bool, error) {
	raw, ok := config["ips"]
	if !ok {
		return false, fmt.Errorf("ip_in requires 'ips' array")
	}
	ip := getIP(req)
	switch ar := raw.(type) {
	case []any:
		for _, v := range ar {
			if s, ok := v.(string); ok {
				if ip == s || strings.HasPrefix(ip, s) {
					return true, nil
				}
				if strings.Contains(s, "/") {
					if strings.HasPrefix(ip, strings.TrimSuffix(s, "/")) {
						return true, nil
					}
				}
			}
		}
		return false, nil
	default:
		return false, fmt.Errorf("ip_in ips must be array of strings")
	}
}

// globalRequestRateCondition checks overall incoming HTTP request rate across all IPs
func globalRequestRateCondition(ctx context.Context, req *http.Request, guard *Guard, config map[string]any) (bool, error) {
	threshold := 0
	if t, ok := config["threshold"].(float64); ok {
		threshold = int(t)
	}
	unitStr, _ := getString(config, "unit", "second")
	var unit time.Duration
	switch unitStr {
	case "second":
		unit = time.Second
	case "minute":
		unit = time.Minute
	default:
		unit = time.Second
	}
	operator, _ := getString(config, "operator", ">")

	now := time.Now()
	guard.mu.Lock()
	defer guard.mu.Unlock()
	// prune
	var newTimes []time.Time
	for _, t := range guard.globalRequestTimes {
		if now.Sub(t) < unit {
			newTimes = append(newTimes, t)
		}
	}
	newTimes = append(newTimes, now)
	guard.globalRequestTimes = newTimes
	count := len(newTimes)
	var anomaly bool
	switch operator {
	case ">":
		anomaly = count > threshold
	case ">=":
		anomaly = count >= threshold
	case "==":
		anomaly = count == threshold
	case "<":
		anomaly = count < threshold
	}
	log.Printf("GLOBAL Count=%d Threshold=%d Anomaly=%v\n", count, threshold, anomaly)
	return anomaly, nil
}

type BanEntry struct {
	Until      time.Time
	StatusCode int
	Body       string
}

type Guard struct {
	globalRules        []Rule
	routeRules         []Rule
	actions            map[string]Action
	requestTimes       map[string][]time.Time
	bannedIPs          map[string]BanEntry
	mu                 sync.RWMutex
	tcpRules           []TCPRule
	tcpConnTimes       map[string][]time.Time
	globalRequestTimes []time.Time
	connCount          int
	connCountByIP      map[string]int
	offenses           map[string]int
}

func NewGuard(configFile string) (*Guard, error) {
	cfg, err := loadConfig(configFile)
	if err != nil {
		return nil, err
	}
	log.Printf("Loaded config with %d rules and %d actions\n", len(cfg.Rules), len(cfg.Actions))
	// rules splitting handled below
	actions, err := createActions(cfg)
	if err != nil {
		return nil, err
	}
	g := &Guard{
		globalRules:        nil,
		routeRules:         nil,
		actions:            actions,
		requestTimes:       make(map[string][]time.Time),
		bannedIPs:          make(map[string]BanEntry),
		tcpConnTimes:       make(map[string][]time.Time),
		connCountByIP:      make(map[string]int),
		offenses:           make(map[string]int),
		globalRequestTimes: make([]time.Time, 0),
	}
	// split rules into global and route based on scope
	gglobal, rroute, err := createRules(cfg)
	if err != nil {
		return nil, err
	}
	g.globalRules = gglobal
	g.routeRules = rroute

	if len(cfg.TCPRules) > 0 {
		tcpRules, err := createTCPRules(cfg)
		if err != nil {
			return nil, err
		}
		g.tcpRules = tcpRules
	}
	if cfg.TCPListen != "" {
		go g.StartTCP(cfg.TCPListen)
	}
	return g, nil
}

func loadConfig(file string) (*Config, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = json.Unmarshal(data, &cfg)
	return &cfg, err
}

func createRules(cfg *Config) ([]Rule, []Rule, error) {
	var global []Rule
	var route []Rule
	for _, rc := range cfg.Rules {
		var actions []ActionRef
		if len(rc.ActionsList) > 0 {
			actions = rc.ActionsList
		} else if len(rc.ActionsMap) > 0 {
			for name, raw := range rc.ActionsMap {
				var ov map[string]any
				if len(raw) > 0 {
					_ = json.Unmarshal(raw, &ov)
				}
				actions = append(actions, ActionRef{Name: name, Override: ov})
			}
		}
		rule := &GenericRule{
			name:       rc.Name,
			conditions: rc.Conditions,
			actions:    actions,
		}
		scope := strings.ToLower(rc.Scope)
		if scope == "global" || scope == "application" || scope == "app" {
			global = append(global, rule)
		} else {
			// default to route-level
			route = append(route, rule)
		}
	}
	return global, route, nil
}

func createActions(cfg *Config) (map[string]Action, error) {
	actions := make(map[string]Action)
	for _, ac := range cfg.Actions {
		ctor, ok := actionRegistry[ac.Type]
		if !ok {
			return nil, fmt.Errorf("unknown action type: %s", ac.Type)
		}
		action := ctor(ac.Name, ac.Config, ac.Response)
		actions[ac.Name] = action
	}
	return actions, nil
}

func createTCPRules(cfg *Config) ([]TCPRule, error) {
	var rules []TCPRule
	for _, rc := range cfg.TCPRules {
		var actions []ActionRef
		if len(rc.ActionsList) > 0 {
			actions = rc.ActionsList
		} else if len(rc.ActionsMap) > 0 {
			for name, raw := range rc.ActionsMap {
				var ov map[string]any
				if len(raw) > 0 {
					_ = json.Unmarshal(raw, &ov)
				}
				actions = append(actions, ActionRef{Name: name, Override: ov})
			}
		}
		rule := &GenericTCPRule{
			name:       rc.Name,
			conditions: rc.Conditions,
			actions:    actions,
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// TCP rule support
type TCPRule interface {
	Name() string
	CheckTCP(ctx context.Context, conn net.Conn, guard *Guard) (anomaly bool, actions []ActionRef, err error)
}

type GenericTCPRule struct {
	name       string
	conditions []ConditionConfig
	actions    []ActionRef
}

func (r *GenericTCPRule) Name() string { return r.name }

func (r *GenericTCPRule) CheckTCP(ctx context.Context, conn net.Conn, guard *Guard) (bool, []ActionRef, error) {
	if len(r.conditions) == 0 {
		return false, nil, nil
	}
	useOr := false
	for _, c := range r.conditions {
		if strings.ToLower(c.Operator) == "or" {
			useOr = true
			break
		}
	}
	if useOr {
		for _, cond := range r.conditions {
			checkFunc, ok := tcpConditionRegistry[cond.Type]
			if !ok {
				return false, nil, fmt.Errorf("unknown tcp condition type: %s", cond.Type)
			}
			anomaly, err := checkFunc(ctx, conn, guard, cond.Config)
			if err != nil {
				return false, nil, err
			}
			if anomaly {
				return true, r.actions, nil
			}
		}
		return false, nil, nil
	}
	for _, cond := range r.conditions {
		checkFunc, ok := tcpConditionRegistry[cond.Type]
		if !ok {
			return false, nil, fmt.Errorf("unknown tcp condition type: %s", cond.Type)
		}
		anomaly, err := checkFunc(ctx, conn, guard, cond.Config)
		if err != nil {
			return false, nil, err
		}
		if !anomaly {
			return false, nil, nil
		}
	}
	return true, r.actions, nil
}

type TCPConditionCheckFunc func(ctx context.Context, conn net.Conn, guard *Guard, config map[string]any) (bool, error)

var tcpConditionRegistry = map[string]TCPConditionCheckFunc{
	"conn_rate":       connRateCondition,
	"concurrent_conn": concurrentConnCondition,
}

// IP-based tcp condition registry used when evaluating tcp_rules for HTTP requests
type TCPConditionIPCheckFunc func(ctx context.Context, ip string, guard *Guard, config map[string]any) (bool, error)

var tcpConditionIPRegistry = map[string]TCPConditionIPCheckFunc{}

func init() {
	tcpConditionIPRegistry["conn_rate"] = connRateConditionIP
	tcpConditionIPRegistry["concurrent_conn"] = concurrentConnConditionIP
}

// concurrentConnCondition checks active concurrent connections, optionally per-IP
func concurrentConnCondition(ctx context.Context, conn net.Conn, guard *Guard, config map[string]any) (bool, error) {
	threshold := 0
	if t, ok := config["threshold"].(float64); ok {
		threshold = int(t)
	}
	perIP, _ := config["per_ip"].(bool)
	operator, _ := getString(config, "operator", ">=")

	guard.mu.Lock()
	defer guard.mu.Unlock()
	if perIP {
		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if ip == "" {
			ip = conn.RemoteAddr().String()
		}
		cnt := guard.connCountByIP[ip]
		var anomaly bool
		switch operator {
		case ">":
			anomaly = cnt > threshold
		case ">=":
			anomaly = cnt >= threshold
		case "==":
			anomaly = cnt == threshold
		case "<":
			anomaly = cnt < threshold
		}
		log.Printf("CONN IP=%s Count=%d Threshold=%d Anomaly=%v\n", ip, cnt, threshold, anomaly)
		return anomaly, nil
	}
	cnt := guard.connCount
	var anomaly bool
	switch operator {
	case ">":
		anomaly = cnt > threshold
	case ">=":
		anomaly = cnt >= threshold
	case "==":
		anomaly = cnt == threshold
	case "<":
		anomaly = cnt < threshold
	}
	log.Printf("CONN GLOBAL Count=%d Threshold=%d Anomaly=%v\n", cnt, threshold, anomaly)
	return anomaly, nil
}

func connRateCondition(ctx context.Context, conn net.Conn, guard *Guard, config map[string]any) (bool, error) {
	threshold := 0
	if t, ok := config["threshold"].(float64); ok {
		threshold = int(t)
	}
	unitStr, _ := getString(config, "unit", "minute")
	var unit time.Duration
	switch unitStr {
	case "second":
		unit = time.Second
	case "minute":
		unit = time.Minute
	case "hour":
		unit = time.Hour
	default:
		unit = time.Minute
	}
	operator, _ := getString(config, "operator", ">")

	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if ip == "" {
		ip = conn.RemoteAddr().String()
	}
	key := ip + ":tcp"
	now := time.Now()
	guard.mu.Lock()
	defer guard.mu.Unlock()
	times := guard.tcpConnTimes[key]
	var newTimes []time.Time
	for _, t := range times {
		if now.Sub(t) < unit {
			newTimes = append(newTimes, t)
		}
	}
	newTimes = append(newTimes, now)
	guard.tcpConnTimes[key] = newTimes
	count := len(newTimes)
	var anomaly bool
	switch operator {
	case ">":
		anomaly = count > threshold
	case ">=":
		anomaly = count >= threshold
	case "==":
		anomaly = count == threshold
	case "<":
		anomaly = count < threshold
	}
	log.Printf("TCP IP=%s Count=%d Threshold=%d Anomaly=%v\n", ip, count, threshold, anomaly)
	return anomaly, nil
}

// connRateConditionIP same as connRateCondition but works from an IP (used for HTTP requests)
func connRateConditionIP(ctx context.Context, ip string, guard *Guard, config map[string]any) (bool, error) {
	threshold := 0
	if t, ok := config["threshold"].(float64); ok {
		threshold = int(t)
	}
	unitStr, _ := getString(config, "unit", "minute")
	var unit time.Duration
	switch unitStr {
	case "second":
		unit = time.Second
	case "minute":
		unit = time.Minute
	case "hour":
		unit = time.Hour
	default:
		unit = time.Minute
	}
	operator, _ := getString(config, "operator", ">")

	key := ip + ":tcp"
	now := time.Now()
	guard.mu.Lock()
	defer guard.mu.Unlock()
	times := guard.tcpConnTimes[key]
	var newTimes []time.Time
	for _, t := range times {
		if now.Sub(t) < unit {
			newTimes = append(newTimes, t)
		}
	}
	newTimes = append(newTimes, now)
	guard.tcpConnTimes[key] = newTimes
	count := len(newTimes)
	var anomaly bool
	switch operator {
	case ">":
		anomaly = count > threshold
	case ">=":
		anomaly = count >= threshold
	case "==":
		anomaly = count == threshold
	case "<":
		anomaly = count < threshold
	}
	log.Printf("TCP(IP) %s Count=%d Threshold=%d Anomaly=%v\n", ip, count, threshold, anomaly)
	return anomaly, nil
}

// concurrentConnConditionIP checks active concurrent "connections" measured as active HTTP requests
func concurrentConnConditionIP(ctx context.Context, ip string, guard *Guard, config map[string]any) (bool, error) {
	threshold := 0
	if t, ok := config["threshold"].(float64); ok {
		threshold = int(t)
	}
	perIP, _ := config["per_ip"].(bool)
	operator, _ := getString(config, "operator", ">=")

	guard.mu.RLock()
	defer guard.mu.RUnlock()
	if perIP {
		cnt := guard.connCountByIP[ip]
		var anomaly bool
		switch operator {
		case ">":
			anomaly = cnt > threshold
		case ">=":
			anomaly = cnt >= threshold
		case "==":
			anomaly = cnt == threshold
		case "<":
			anomaly = cnt < threshold
		}
		log.Printf("CONN(IP) %s Count=%d Threshold=%d Anomaly=%v\n", ip, cnt, threshold, anomaly)
		return anomaly, nil
	}
	cnt := guard.connCount
	var anomaly bool
	switch operator {
	case ">":
		anomaly = cnt > threshold
	case ">=":
		anomaly = cnt >= threshold
	case "==":
		anomaly = cnt == threshold
	case "<":
		anomaly = cnt < threshold
	}
	log.Printf("CONN GLOBAL Count=%d Threshold=%d Anomaly=%v\n", cnt, threshold, anomaly)
	return anomaly, nil
}

// tcpResponseWriter implements minimal ResponseWriter-like behavior for TCP connections
type tcpResponseWriter struct {
	conn net.Conn
}

func (t *tcpResponseWriter) WriteHeader(statusCode int) {
	// For TCP we simply write a small header line
	_, _ = t.conn.Write([]byte(fmt.Sprintf("STATUS %d\n", statusCode)))
}

func (t *tcpResponseWriter) Write(b []byte) (int, error) {
	return t.conn.Write(b)
}

func (t *tcpResponseWriter) Header() http.Header {
	return http.Header{}
}

// StartTCP starts a simple TCP listener that applies tcp rules per incoming connection.
func (g *Guard) StartTCP(listenAddr string) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Printf("failed to start tcp listener on %s: %v", listenAddr, err)
		return
	}
	log.Printf("TCP Guard listening on %s\n", listenAddr)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("tcp accept error: %v", err)
			continue
		}
		go func(c net.Conn) {
			ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			if ip == "" {
				ip = c.RemoteAddr().String()
			}
			// increment counters
			g.mu.Lock()
			g.connCount++
			g.connCountByIP[ip] = g.connCountByIP[ip] + 1
			g.mu.Unlock()
			defer func() {
				// decrement counters on exit
				g.mu.Lock()
				g.connCount--
				if g.connCountByIP[ip] > 0 {
					g.connCountByIP[ip] = g.connCountByIP[ip] - 1
				}
				g.mu.Unlock()
				_ = c.Close()
			}()

			g.mu.RLock()
			if entry, banned := g.bannedIPs[ip]; banned && time.Now().Before(entry.Until) {
				g.mu.RUnlock()
				// drop connection (just close)
				return
			}
			g.mu.RUnlock()

			overallAnomaly := false
			for _, rule := range g.tcpRules {
				anomaly, acts, err := rule.CheckTCP(context.Background(), c, g)
				if err != nil {
					log.Printf("tcp rule check error: %v", err)
					continue
				}
				if anomaly {
					overallAnomaly = true
					for _, aref := range acts {
						act, ok := g.actions[aref.Name]
						if !ok {
							log.Printf("unknown action reference %s for tcp", aref.Name)
							continue
						}
						// For TCP actions, create a tcpResponseWriter so actions that write will get bytes
						trw := &tcpResponseWriter{conn: c}
						if err := act.Execute(context.Background(), nil, g, trw, aref.Override); err != nil {
							log.Printf("action execute error: %v", err)
						}
						if aref.Stop {
							break
						}
					}
				}
			}
			if !overallAnomaly {
				// nothing to do: simple echo read briefly or sleep then close
				buf := make([]byte, 1)
				c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				_, _ = c.Read(buf) // ignore errors
			}
		}(conn)
	}
}

func (g *Guard) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	rw := &responseWriter{ResponseWriter: w, written: false}
	ip := getIP(req)
	g.mu.RLock()
	if entry, banned := g.bannedIPs[ip]; banned && time.Now().Before(entry.Until) {
		g.mu.RUnlock()
		rw.WriteHeader(entry.StatusCode)
		_, _ = rw.Write([]byte(entry.Body))
		return
	}
	g.mu.RUnlock()
	// Treat each HTTP request as a transient "connection" for tcp_rules like concurrent_conn
	g.mu.Lock()
	g.connCount++
	g.connCountByIP[ip] = g.connCountByIP[ip] + 1
	g.mu.Unlock()
	defer func() {
		g.mu.Lock()
		g.connCount--
		if g.connCountByIP[ip] > 0 {
			g.connCountByIP[ip] = g.connCountByIP[ip] - 1
		}
		g.mu.Unlock()
	}()
	overallAnomaly := false
	stopAll := false
	// Evaluate tcp_rules (if present) mapped to this HTTP request's IP
	if len(g.tcpRules) > 0 {
		for _, tr := range g.tcpRules {
			// Evaluate each TCP rule by translating its TCP conditions to IP-based checks
			useOr := false
			// we need access to the RuleConfig-like conditions; GenericTCPRule stores them similarly
			if gtr, ok := tr.(*GenericTCPRule); ok {
				for _, c := range gtr.conditions {
					if strings.ToLower(c.Operator) == "or" {
						useOr = true
						break
					}
				}
				if useOr {
					hit := false
					for _, cond := range gtr.conditions {
						checkIP, ok := tcpConditionIPRegistry[cond.Type]
						if !ok {
							log.Printf("unknown tcp ip condition type: %s", cond.Type)
							continue
						}
						anomaly, err := checkIP(context.Background(), ip, g, cond.Config)
						if err != nil {
							log.Printf("tcp ip condition error: %v", err)
							continue
						}
						if anomaly {
							hit = true
							break
						}
					}
					if hit {
						overallAnomaly = true
						for _, aref := range gtr.actions {
							act, ok := g.actions[aref.Name]
							if !ok {
								log.Printf("unknown action reference %s for tcp", aref.Name)
								continue
							}
							if err := act.Execute(context.Background(), req, g, rw, aref.Override); err != nil {
								log.Printf("action execute error: %v", err)
							}
							if aref.Stop {
								stopAll = true
								break
							}
						}
					}
				} else {
					allMatch := true
					for _, cond := range gtr.conditions {
						checkIP, ok := tcpConditionIPRegistry[cond.Type]
						if !ok {
							log.Printf("unknown tcp ip condition type: %s", cond.Type)
							allMatch = false
							break
						}
						anomaly, err := checkIP(context.Background(), ip, g, cond.Config)
						if err != nil {
							log.Printf("tcp ip condition error: %v", err)
							allMatch = false
							break
						}
						if !anomaly {
							allMatch = false
							break
						}
					}
					if allMatch {
						overallAnomaly = true
						for _, aref := range gtr.actions {
							act, ok := g.actions[aref.Name]
							if !ok {
								log.Printf("unknown action reference %s for tcp", aref.Name)
								continue
							}
							if err := act.Execute(context.Background(), req, g, rw, aref.Override); err != nil {
								log.Printf("action execute error: %v", err)
							}
							if aref.Stop {
								stopAll = true
								break
							}
						}
					}
				}
				if stopAll {
					goto done
				}
			}
		}
	}
	// First apply global/application-level rules
	for _, rule := range g.globalRules {
		log.Printf("Checking global rule %s for %s\n", rule.Name(), req.URL.Path)
		anomaly, acts, err := rule.Check(context.Background(), req, g)
		if err != nil {
			log.Printf("global rule check error: %v\n", err)
			continue
		}
		if anomaly {
			overallAnomaly = true
			log.Printf("Global anomaly detected by %s, actions: %+v\n", rule.Name(), acts)
			for _, aref := range acts {
				act, ok := g.actions[aref.Name]
				if !ok {
					log.Printf("unknown action reference %s\n", aref.Name)
					continue
				}
				log.Printf("Executing action %s (stop=%v)\n", act.Name(), aref.Stop)
				if err := act.Execute(context.Background(), req, g, rw, aref.Override); err != nil {
					http.Error(rw, "Restricted", http.StatusForbidden)
					return
				}
				if aref.Stop {
					stopAll = true
					break
				}
			}
		}
	}

	// Then apply route-level rules
	for _, rule := range g.routeRules {
		log.Printf("Checking route rule %s for %s\n", rule.Name(), req.URL.Path)
		anomaly, acts, err := rule.Check(context.Background(), req, g)
		if err != nil {
			log.Printf("route rule check error: %v\n", err)
			continue
		}
		if anomaly {
			overallAnomaly = true
			log.Printf("Route anomaly detected by %s, actions: %+v\n", rule.Name(), acts)
			for _, aref := range acts {
				act, ok := g.actions[aref.Name]
				if !ok {
					log.Printf("unknown action reference %s\n", aref.Name)
					continue
				}
				log.Printf("Executing action %s (stop=%v)\n", act.Name(), aref.Stop)
				if err := act.Execute(context.Background(), req, g, rw, aref.Override); err != nil {
					http.Error(rw, "Restricted", http.StatusForbidden)
					return
				}
				if aref.Stop {
					stopAll = true
					break
				}
			}
		}
	}
	if stopAll {
		goto done
	}

	if !overallAnomaly {
		rw.WriteHeader(200)
		_, _ = rw.Write([]byte("OK"))
	}
done:
}

func getIP(req *http.Request) string {
	ip := req.Header.Get("X-Forwarded-For")
	if ip == "" {
		ip = req.RemoteAddr
	}
	if strings.Contains(ip, ":") {
		ip, _, _ = strings.Cut(ip, ":")
	}
	return ip
}

type RateLimitAction struct {
	name        string
	baseDelay   int
	jitterRange int
	statusCode  int
	body        string
}

func NewRateLimitAction(name string, config map[string]any, response map[string]any) Action {
	baseDelay, _ := getIntFromFloat(config, "base_delay", 0)
	jitterRange, _ := getIntFromFloat(config, "jitter_range", 0)
	statusCode := 429
	body := "Too Many Requests"
	if response != nil {
		if sc, ok := response["status_code"].(float64); ok {
			statusCode = int(sc)
		}
		if b, ok := response["body"].(string); ok {
			body = b
		}
	}
	return &RateLimitAction{
		name:        name,
		baseDelay:   baseDelay,
		jitterRange: jitterRange,
		statusCode:  statusCode,
		body:        body,
	}
}

func (a *RateLimitAction) Name() string { return a.name }

func (a *RateLimitAction) Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]any) error {
	statusCode := a.statusCode
	body := a.body
	if override != nil {
		if resp, ok := override["response"].(map[string]any); ok {
			if sc, ok := resp["status_code"].(float64); ok {
				statusCode = int(sc)
			}
			if b, ok := resp["body"].(string); ok {
				body = b
			}
		}
	}
	delay := time.Duration(a.baseDelay+rand.Intn(max(1, a.jitterRange))) * time.Millisecond
	time.Sleep(delay)
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(body))
	return nil
}

type WarningAction struct {
	name       string
	statusCode int
	body       string
}

func NewWarningAction(name string, config map[string]any, response map[string]any) Action {
	statusCode := 200
	body := "Warning Logged"
	if response != nil {
		if sc, ok := response["status_code"].(float64); ok {
			statusCode = int(sc)
		}
		if b, ok := response["body"].(string); ok {
			body = b
		}
	}
	return &WarningAction{name: name, statusCode: statusCode, body: body}
}

func (a *WarningAction) Name() string { return a.name }

func (a *WarningAction) Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]any) error {
	ip := getIP(req)
	log.Printf("Warning: Anomaly detected for IP %s\n", ip)
	statusCode := a.statusCode
	body := a.body
	if override != nil {
		if resp, ok := override["response"].(map[string]any); ok {
			if sc, ok := resp["status_code"].(float64); ok {
				statusCode = int(sc)
			}
			if b, ok := resp["body"].(string); ok {
				body = b
			}
		}
	}
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(body))
	return nil
}

type RestrictAction struct {
	name       string
	statusCode int
	body       string
}

func NewRestrictAction(name string, config map[string]any, response map[string]any) Action {
	statusCode := 403
	body := "Forbidden"
	if response != nil {
		if sc, ok := response["status_code"].(float64); ok {
			statusCode = int(sc)
		}
		if b, ok := response["body"].(string); ok {
			body = b
		}
	}
	return &RestrictAction{name: name, statusCode: statusCode, body: body}
}

func (a *RestrictAction) Name() string { return a.name }

func (a *RestrictAction) Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]any) error {
	statusCode := a.statusCode
	body := a.body
	if override != nil {
		if resp, ok := override["response"].(map[string]any); ok {
			if sc, ok := resp["status_code"].(float64); ok {
				statusCode = int(sc)
			}
			if b, ok := resp["body"].(string); ok {
				body = b
			}
		}
	}
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(body))
	return nil
}

type TempBanAction struct {
	name       string
	duration   time.Duration
	statusCode int
	body       string
}

func NewTempBanAction(name string, config map[string]any, response map[string]any) Action {
	durStr, ok := config["duration"].(string)
	if !ok {
		durStr = "1h"
	}
	dur, _ := time.ParseDuration(durStr)
	statusCode := 429
	body := "Temporarily Banned"
	if response != nil {
		if sc, ok := response["status_code"].(float64); ok {
			statusCode = int(sc)
		}
		if b, ok := response["body"].(string); ok {
			body = b
		}
	}
	return &TempBanAction{name: name, duration: dur, statusCode: statusCode, body: body}
}

// DropConnection action: for TCP, closes connection and optionally increments offense count
type DropConnectionAction struct {
	name string
}

func NewDropConnectionAction(name string, config map[string]any, response map[string]any) Action {
	return &DropConnectionAction{name: name}
}

func (a *DropConnectionAction) Name() string { return a.name }

func (a *DropConnectionAction) Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]any) error {
	// If w is a tcpResponseWriter, close underlying connection by writing a notice
	if trw, ok := w.(*tcpResponseWriter); ok {
		_, _ = trw.conn.Write([]byte("DROP\n"))
		_ = trw.conn.Close()
		return nil
	}
	// For HTTP, just respond 403
	if w != nil {
		w.WriteHeader(403)
		_, _ = w.Write([]byte("Forbidden"))
	}
	return nil
}

// DynamicTempBan increases ban duration based on past offenses
type DynamicTempBanAction struct {
	name string
	base time.Duration
}

func NewDynamicTempBanAction(name string, config map[string]any, response map[string]any) Action {
	baseStr, _ := getString(config, "base_duration", "1m")
	dur, _ := time.ParseDuration(baseStr)
	return &DynamicTempBanAction{name: name, base: dur}
}

func (a *DynamicTempBanAction) Name() string { return a.name }

func (a *DynamicTempBanAction) Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]any) error {
	ip := ""
	if req != nil {
		ip = getIP(req)
	}
	// if tcpResponseWriter provided, try to extract ip from conn
	if ip == "" {
		if trw, ok := w.(*tcpResponseWriter); ok {
			ip, _, _ = net.SplitHostPort(trw.conn.RemoteAddr().String())
		}
	}
	if ip == "" {
		return nil
	}
	guard.mu.Lock()
	prev := guard.offenses[ip]
	guard.offenses[ip] = prev + 1
	dur := a.base * time.Duration(1<<prev) // exponential backoff
	guard.bannedIPs[ip] = BanEntry{Until: time.Now().Add(dur), StatusCode: 429, Body: "Temporarily Banned"}
	guard.mu.Unlock()
	// respond
	if w != nil {
		w.WriteHeader(429)
		_, _ = w.Write([]byte("Temporarily Banned"))
	}
	return nil
}

func (a *TempBanAction) Name() string { return a.name }

func (a *TempBanAction) Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]any) error {
	ip := getIP(req)
	statusCode := a.statusCode
	body := a.body
	if override != nil {
		if resp, ok := override["response"].(map[string]any); ok {
			if sc, ok := resp["status_code"].(float64); ok {
				statusCode = int(sc)
			}
			if b, ok := resp["body"].(string); ok {
				body = b
			}
		}
	}
	guard.mu.Lock()
	guard.bannedIPs[ip] = BanEntry{
		Until:      time.Now().Add(a.duration),
		StatusCode: statusCode,
		Body:       body,
	}
	guard.mu.Unlock()
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(body))
	return nil
}

type PermBanAction struct {
	name       string
	statusCode int
	body       string
}

func NewPermBanAction(name string, config map[string]any, response map[string]any) Action {
	statusCode := 403
	body := "Permanently Banned"
	if response != nil {
		if sc, ok := response["status_code"].(float64); ok {
			statusCode = int(sc)
		}
		if b, ok := response["body"].(string); ok {
			body = b
		}
	}
	return &PermBanAction{name: name, statusCode: statusCode, body: body}
}

func (a *PermBanAction) Name() string { return a.name }

func (a *PermBanAction) Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]any) error {
	ip := getIP(req)
	statusCode := a.statusCode
	body := a.body
	if override != nil {
		if resp, ok := override["response"].(map[string]any); ok {
			if sc, ok := resp["status_code"].(float64); ok {
				statusCode = int(sc)
			}
			if b, ok := resp["body"].(string); ok {
				body = b
			}
		}
	}
	guard.mu.Lock()
	guard.bannedIPs[ip] = BanEntry{
		Until:      time.Now().Add(100 * 365 * 24 * time.Hour),
		StatusCode: statusCode,
		Body:       body,
	}
	guard.mu.Unlock()
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(body))
	return nil
}

var actionRegistry = map[string]func(name string, config map[string]any, response map[string]any) Action{
	"rate_limit":   NewRateLimitAction,
	"warning":      NewWarningAction,
	"restrict":     NewRestrictAction,
	"temp_ban":     NewTempBanAction,
	"drop_conn":    NewDropConnectionAction,
	"dyn_temp_ban": NewDynamicTempBanAction,
	"perm_ban":     NewPermBanAction,
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
