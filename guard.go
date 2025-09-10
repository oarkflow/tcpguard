package tcpguard

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// --- Interfaces ----------------------------------------------------------------

type Rule interface {
	Name() string
	Check(ctx context.Context, req *http.Request, guard *Guard) (anomaly bool, actions []ActionRef, err error)
}

type Action interface {
	Name() string
	Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]interface{}) error
}

// responseWriter wrapper to prevent multiple WriteHeader calls
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
		rw.ResponseWriter.WriteHeader(http.StatusOK) // default status
		rw.written = true
	}
	return rw.ResponseWriter.Write(data)
}

func (rw *responseWriter) Header() http.Header {
	return rw.ResponseWriter.Header()
}

// --- Config structs -----------------------------------------------------------

type RuleConfig struct {
	Name       string            `json:"name"`
	Conditions []ConditionConfig `json:"conditions"`
	// Actions: prefer list for ordering and per-action overrides
	ActionsList []ActionRef `json:"actions,omitempty"`
	// compatibility: old-style actions map[string]interface{}
	ActionsMap map[string]json.RawMessage `json:"actions_map,omitempty"`
}

type ConditionConfig struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
	// optional per-condition operator to be used when evaluated inside a group
	// (not required when conditions are evaluated as a flat AND by default)
	Operator string `json:"operator,omitempty"` // "and" | "or"
}

// ActionRef describes one action invocation in a rule
type ActionRef struct {
	Name     string                 `json:"name"`
	Override map[string]interface{} `json:"override,omitempty"` // overrides passed to Execute
	Stop     bool                   `json:"stop,omitempty"`     // if true, stop further rules/actions after this action
}

// top-level config
type ActionConfig struct {
	Type     string                 `json:"type"`
	Name     string                 `json:"name"`
	Config   map[string]interface{} `json:"config"`
	Response map[string]interface{} `json:"response"`
}

type Config struct {
	Rules   []RuleConfig   `json:"rules"`
	Actions []ActionConfig `json:"actions"`
}

// --- GenericRule implementation -----------------------------------------------

type GenericRule struct {
	name       string
	conditions []ConditionConfig
	actions    []ActionRef
}

func (r *GenericRule) Name() string { return r.name }

func (r *GenericRule) Check(ctx context.Context, req *http.Request, guard *Guard) (bool, []ActionRef, error) {
	// If there are no conditions treat as no-anomaly
	if len(r.conditions) == 0 {
		return false, nil, nil
	}

	// Evaluate conditions with simple semantics:
	// - If any condition has Operator "or", we treat the rule as OR across conditions.
	// - Otherwise default to AND across conditions.
	useOr := false
	for _, c := range r.conditions {
		if strings.ToLower(c.Operator) == "or" {
			useOr = true
			break
		}
	}

	if useOr {
		// anomaly if any condition returns true
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

	// default AND semantics
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

// --- Condition functions & registry ------------------------------------------

type ConditionCheckFunc func(ctx context.Context, req *http.Request, guard *Guard, config map[string]interface{}) (bool, error)

var conditionRegistry = map[string]ConditionCheckFunc{
	"request_count": requestCountCondition,
	"path_prefix":   pathPrefixCondition,
	"header_equals": headerEqualsCondition,
	"method_in":     methodInCondition,
	"ip_in":         ipInCondition,
}

// helper: safe string fetch
func getString(m map[string]interface{}, key string, def string) (string, error) {
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

// helper: safe float->int
func getIntFromFloat(m map[string]interface{}, key string, def int) (int, error) {
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

// --- condition: request_count (improved, robust) ------------------------------

func requestCountCondition(ctx context.Context, req *http.Request, guard *Guard, config map[string]interface{}) (bool, error) {
	uri := strings.TrimSuffix(config["uri"].(string), "/")
	methodsInterface := config["methods"].([]interface{})
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

	// Match
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

	// Clean old requests
	times := guard.requestTimes[key]
	var newTimes []time.Time
	for _, t := range times {
		if now.Sub(t) < unit {
			newTimes = append(newTimes, t)
		}
	}

	// Always record current request
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

// --- condition: path_prefix ---------------------------------------------------

func pathPrefixCondition(ctx context.Context, req *http.Request, guard *Guard, config map[string]interface{}) (bool, error) {
	prefix, err := getString(config, "prefix", "")
	if err != nil {
		return false, err
	}
	if prefix == "" {
		return false, fmt.Errorf("path_prefix requires 'prefix' field")
	}
	return strings.HasPrefix(req.URL.Path, prefix), nil
}

// --- condition: header_equals -------------------------------------------------

func headerEqualsCondition(ctx context.Context, req *http.Request, guard *Guard, config map[string]interface{}) (bool, error) {
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

// --- condition: method_in ----------------------------------------------------

func methodInCondition(ctx context.Context, req *http.Request, guard *Guard, config map[string]interface{}) (bool, error) {
	methodsRaw, ok := config["methods"]
	if !ok {
		return false, fmt.Errorf("method_in requires 'methods' array")
	}
	switch mr := methodsRaw.(type) {
	case []interface{}:
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

// --- condition: ip_in (supports CIDR list or exact list) ---------------------

func ipInCondition(ctx context.Context, req *http.Request, guard *Guard, config map[string]interface{}) (bool, error) {
	raw, ok := config["ips"]
	if !ok {
		return false, fmt.Errorf("ip_in requires 'ips' array")
	}
	ip := getIP(req)
	switch ar := raw.(type) {
	case []interface{}:
		for _, v := range ar {
			if s, ok := v.(string); ok {
				// exact match or substring (for small use cases)
				if ip == s || strings.HasPrefix(ip, s) {
					return true, nil
				}
				// support simple regex
				if strings.Contains(s, "/") {
					// treat as prefix like 10.0.0.
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

// --- Guard, bans, requestTimes -------------------------------------------------

type BanEntry struct {
	Until      time.Time
	StatusCode int
	Body       string
}

type Guard struct {
	rules        []Rule
	actions      map[string]Action
	requestTimes map[string][]time.Time
	bannedIPs    map[string]BanEntry
	mu           sync.RWMutex
}

// --- Configuration loader & creators -----------------------------------------

func NewGuard(configFile string) (*Guard, error) {
	cfg, err := loadConfig(configFile)
	if err != nil {
		return nil, err
	}
	log.Printf("Loaded config with %d rules and %d actions\n", len(cfg.Rules), len(cfg.Actions))
	rules, err := createRules(cfg)
	if err != nil {
		return nil, err
	}
	actions, err := createActions(cfg)
	if err != nil {
		return nil, err
	}
	return &Guard{
		rules:        rules,
		actions:      actions,
		requestTimes: make(map[string][]time.Time),
		bannedIPs:    make(map[string]BanEntry),
	}, nil
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

func createRules(cfg *Config) ([]Rule, error) {
	var rules []Rule
	for _, rc := range cfg.Rules {
		// convert ActionsMap to ActionsList if necessary (compatibility)
		var actions []ActionRef
		if len(rc.ActionsList) > 0 {
			actions = rc.ActionsList
		} else if len(rc.ActionsMap) > 0 {
			for name, raw := range rc.ActionsMap {
				// attempt to unmarshal override if present
				var ov map[string]interface{}
				if len(raw) > 0 {
					_ = json.Unmarshal(raw, &ov) // ignore errors; we only support empty override in legacy
				}
				actions = append(actions, ActionRef{Name: name, Override: ov})
			}
		}
		rule := &GenericRule{
			name:       rc.Name,
			conditions: rc.Conditions,
			actions:    actions,
		}
		rules = append(rules, rule)
	}
	return rules, nil
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

// --- ServeHTTP: evaluate rules & execute actions in config order --------------

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

	overallAnomaly := false
stopOuter:
	for _, rule := range g.rules {
		log.Printf("Checking rule %s for %s\n", rule.Name(), req.URL.Path)
		anomaly, acts, err := rule.Check(context.Background(), req, g)
		if err != nil {
			log.Printf("rule check error: %v\n", err)
			continue
		}
		if anomaly {
			overallAnomaly = true
			log.Printf("Anomaly detected by %s, actions: %+v\n", rule.Name(), acts)
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
					// stop processing further actions and rules
					break stopOuter
				}
			}
		}
	}

	if !overallAnomaly {
		rw.WriteHeader(200)
		_, _ = rw.Write([]byte("OK"))
	}
}

// --- helpers ------------------------------------------------------------------

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

// --- Action implementations (same as original but defensive) ------------------

type RateLimitAction struct {
	name        string
	baseDelay   int
	jitterRange int
	statusCode  int
	body        string
}

func NewRateLimitAction(name string, config map[string]interface{}, response map[string]interface{}) Action {
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

func (a *RateLimitAction) Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]interface{}) error {
	statusCode := a.statusCode
	body := a.body
	if override != nil {
		if resp, ok := override["response"].(map[string]interface{}); ok {
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

func NewWarningAction(name string, config map[string]interface{}, response map[string]interface{}) Action {
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

func (a *WarningAction) Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]interface{}) error {
	ip := getIP(req)
	log.Printf("Warning: Anomaly detected for IP %s\n", ip)
	statusCode := a.statusCode
	body := a.body
	if override != nil {
		if resp, ok := override["response"].(map[string]interface{}); ok {
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

func NewRestrictAction(name string, config map[string]interface{}, response map[string]interface{}) Action {
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

func (a *RestrictAction) Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]interface{}) error {
	statusCode := a.statusCode
	body := a.body
	if override != nil {
		if resp, ok := override["response"].(map[string]interface{}); ok {
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

func NewTempBanAction(name string, config map[string]interface{}, response map[string]interface{}) Action {
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

func (a *TempBanAction) Name() string { return a.name }

func (a *TempBanAction) Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]interface{}) error {
	ip := getIP(req)
	statusCode := a.statusCode
	body := a.body
	if override != nil {
		if resp, ok := override["response"].(map[string]interface{}); ok {
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

	// write response immediately
	w.WriteHeader(statusCode)
	_, _ = w.Write([]byte(body))
	return nil
}

type PermBanAction struct {
	name       string
	statusCode int
	body       string
}

func NewPermBanAction(name string, config map[string]interface{}, response map[string]interface{}) Action {
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

func (a *PermBanAction) Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]interface{}) error {
	ip := getIP(req)
	statusCode := a.statusCode
	body := a.body
	if override != nil {
		if resp, ok := override["response"].(map[string]interface{}); ok {
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

// register actions
var actionRegistry = map[string]func(name string, config map[string]interface{}, response map[string]interface{}) Action{
	"rate_limit": NewRateLimitAction,
	"warning":    NewWarningAction,
	"restrict":   NewRestrictAction,
	"temp_ban":   NewTempBanAction,
	"perm_ban":   NewPermBanAction,
}

// --- small helpers ------------------------------------------------------------

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
