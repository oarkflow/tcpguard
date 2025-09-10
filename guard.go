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

// Interfaces

type Rule interface {
	Name() string
	Check(ctx context.Context, req *http.Request, guard *Guard) (anomaly bool, actions map[string]interface{}, err error)
}

type Action interface {
	Name() string
	Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]interface{}) error
}

// Config structs

type RuleConfig struct {
	Name       string                 `json:"name"`
	Conditions []ConditionConfig      `json:"conditions"`
	Actions    map[string]interface{} `json:"actions"`
}

type ConditionConfig struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
}

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

// GenericRule implements Rule
type GenericRule struct {
	name       string
	conditions []ConditionConfig
	actions    map[string]interface{}
}

func (r *GenericRule) Name() string {
	return r.name
}

func (r *GenericRule) Check(ctx context.Context, req *http.Request, guard *Guard) (bool, map[string]interface{}, error) {
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

// Condition check function
type ConditionCheckFunc func(ctx context.Context, req *http.Request, guard *Guard, config map[string]interface{}) (anomaly bool, err error)

// Condition registry
var conditionRegistry = map[string]ConditionCheckFunc{
	"request_count": requestCountCondition,
}

// requestCountCondition checks if request count exceeds threshold
func requestCountCondition(ctx context.Context, req *http.Request, guard *Guard, config map[string]interface{}) (bool, error) {
	uri := config["uri"].(string)
	uri = strings.TrimSuffix(uri, "/")
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

	if !strings.HasPrefix(req.URL.Path, uri) {
		return false, nil
	}
	found := false
	for _, m := range methods {
		if req.Method == m {
			found = true
			break
		}
	}
	if !found {
		return false, nil
	}

	ip := getIP(req)
	key := ip + uri
	guard.mu.Lock()
	times := guard.requestTimes[key]
	now := time.Now()
	var newTimes []time.Time
	for _, t := range times {
		if now.Sub(t) < unit {
			newTimes = append(newTimes, t)
		}
	}
	count := len(newTimes)
	anomaly := false
	if operator == ">" && count > threshold {
		anomaly = true
	}
	if !anomaly {
		newTimes = append(newTimes, now)
		guard.requestTimes[key] = newTimes
	}
	guard.mu.Unlock()
	return anomaly, nil
}

// BanEntry holds ban information
type BanEntry struct {
	Until      time.Time
	StatusCode int
	Body       string
}

// Guard struct
type Guard struct {
	rules        []Rule
	actions      map[string]Action
	requestTimes map[string][]time.Time
	bannedIPs    map[string]BanEntry
	mu           sync.RWMutex
}

// NewGuard creates a new Guard from config file
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

// loadConfig loads the config from JSON file
func loadConfig(file string) (*Config, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var cfg Config
	err = json.Unmarshal(data, &cfg)
	return &cfg, err
}

// createRules creates rules from config
func createRules(cfg *Config) ([]Rule, error) {
	var rules []Rule
	for _, rc := range cfg.Rules {
		rule := &GenericRule{
			name:       rc.Name,
			conditions: rc.Conditions,
			actions:    rc.Actions,
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// createActions creates actions from config
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

// ServeHTTP implements http.Handler
func (g *Guard) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ip := getIP(req)
	g.mu.RLock()
	if entry, banned := g.bannedIPs[ip]; banned && time.Now().Before(entry.Until) {
		g.mu.RUnlock()
		w.WriteHeader(entry.StatusCode)
		w.Write([]byte(entry.Body))
		return
	}
	g.mu.RUnlock()
	anomalyDetected := false
	for _, rule := range g.rules {
		log.Printf("Checking rule %s for %s\n", rule.Name(), req.URL.Path)
		anomaly, actOverrides, err := rule.Check(context.Background(), req, g)
		if err != nil {
			// handle error, perhaps log
			continue
		}
		if anomaly {
			log.Printf("Anomaly detected by %s, actions: %v\n", rule.Name(), actOverrides)
			anomalyDetected = true
			for actName, override := range actOverrides {
				if act, ok := g.actions[actName]; ok {
					log.Printf("Executing action %s\n", act.Name())
					err := act.Execute(context.Background(), req, g, w, override.(map[string]interface{}))
					if err != nil {
						http.Error(w, "Restricted", 403)
						return
					}
				}
			}
		}
	}
	// Send response
	if anomalyDetected {
		// Actions have written the response
	} else {
		w.WriteHeader(200)
		w.Write([]byte("OK"))
	}
}

// getIP extracts IP from request
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

// Action implementations

type RateLimitAction struct {
	name        string
	baseDelay   int
	jitterRange int
	statusCode  int
	body        string
}

func NewRateLimitAction(name string, config map[string]interface{}, response map[string]interface{}) Action {
	baseDelay := int(config["base_delay"].(float64))
	jitterRange := int(config["jitter_range"].(float64))
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

func (a *RateLimitAction) Name() string {
	return a.name
}

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
	delay := time.Duration(a.baseDelay+rand.Intn(a.jitterRange)) * time.Millisecond
	time.Sleep(delay)
	w.WriteHeader(statusCode)
	w.Write([]byte(body))
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
	return &WarningAction{
		name:       name,
		statusCode: statusCode,
		body:       body,
	}
}

func (a *WarningAction) Name() string {
	return a.name
}

func (a *WarningAction) Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]interface{}) error {
	// Log warning
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
	w.Write([]byte(body))
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
	return &RestrictAction{
		name:       name,
		statusCode: statusCode,
		body:       body,
	}
}

func (a *RestrictAction) Name() string {
	return a.name
}

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
	w.Write([]byte(body))
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
	return &TempBanAction{
		name:       name,
		duration:   dur,
		statusCode: statusCode,
		body:       body,
	}
}

func (a *TempBanAction) Name() string {
	return a.name
}

func (a *TempBanAction) Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]interface{}) error {
	ip := getIP(req)
	guard.mu.Lock()
	guard.bannedIPs[ip] = BanEntry{
		Until:      time.Now().Add(a.duration),
		StatusCode: a.statusCode,
		Body:       a.body,
	}
	guard.mu.Unlock()
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
	return &PermBanAction{
		name:       name,
		statusCode: statusCode,
		body:       body,
	}
}

func (a *PermBanAction) Name() string {
	return a.name
}

func (a *PermBanAction) Execute(ctx context.Context, req *http.Request, guard *Guard, w http.ResponseWriter, override map[string]interface{}) error {
	ip := getIP(req)
	guard.mu.Lock()
	guard.bannedIPs[ip] = BanEntry{
		Until:      time.Now().Add(100 * 365 * 24 * time.Hour),
		StatusCode: a.statusCode,
		Body:       a.body,
	}
	guard.mu.Unlock()
	return nil
}

// Registries

var actionRegistry = map[string]func(name string, config map[string]interface{}, response map[string]interface{}) Action{
	"rate_limit": NewRateLimitAction,
	"warning":    NewWarningAction,
	"restrict":   NewRestrictAction,
	"temp_ban":   NewTempBanAction,
	"perm_ban":   NewPermBanAction,
}
