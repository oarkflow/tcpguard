package tcpguard

import (
	"context"
	"encoding/json"
	"fmt"
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
	Check(ctx context.Context, req *http.Request, guard *Guard) (anomaly bool, actions []string, err error)
}

type Action interface {
	Name() string
	Execute(ctx context.Context, req *http.Request, guard *Guard) error
}

// Config structs

type RuleConfig struct {
	Type    string                 `json:"type"`
	Name    string                 `json:"name"`
	Config  map[string]interface{} `json:"config"`
	Actions map[string]interface{} `json:"actions"`
}

type ActionConfig struct {
	Type   string                 `json:"type"`
	Name   string                 `json:"name"`
	Config map[string]interface{} `json:"config"`
}

type Config struct {
	Rules   []RuleConfig   `json:"rules"`
	Actions []ActionConfig `json:"actions"`
}

// Guard struct

type Guard struct {
	rules        []Rule
	actions      map[string]Action
	requestTimes map[string][]time.Time
	bannedIPs    map[string]time.Time
	mu           sync.RWMutex
}

// NewGuard creates a new Guard from config file
func NewGuard(configFile string) (*Guard, error) {
	cfg, err := loadConfig(configFile)
	if err != nil {
		return nil, err
	}
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
		bannedIPs:    make(map[string]time.Time),
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
		ctor, ok := ruleRegistry[rc.Type]
		if !ok {
			return nil, fmt.Errorf("unknown rule type: %s", rc.Type)
		}
		rule := ctor(rc.Name, rc.Config, rc.Actions)
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
		action := ctor(ac.Name, ac.Config)
		actions[ac.Name] = action
	}
	return actions, nil
}

// ServeHTTP implements http.Handler
func (g *Guard) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ip := getIP(req)
	g.mu.RLock()
	if banTime, banned := g.bannedIPs[ip]; banned && time.Now().Before(banTime) {
		g.mu.RUnlock()
		http.Error(w, "Banned", 403)
		return
	}
	g.mu.RUnlock()
	for _, rule := range g.rules {
		anomaly, acts, err := rule.Check(req.Context(), req, g)
		if err != nil {
			// handle error, perhaps log
			continue
		}
		if anomaly {
			for _, actName := range acts {
				if act, ok := g.actions[actName]; ok {
					err := act.Execute(req.Context(), req, g)
					if err != nil {
						// for restrict, perhaps
						http.Error(w, "Restricted", 403)
						return
					}
				}
			}
		}
	}
	// Here, proxy the request or handle normally
	// For example, if it's a proxy, forward to backend
	// But for now, just respond
	w.WriteHeader(200)
	w.Write([]byte("OK"))
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

// Rule implementations

type RateLimitRule struct {
	name      string
	uri       string
	methods   []string
	threshold int
	unit      time.Duration
	operator  string
	actions   []string
}

func NewRateLimitRule(name string, config map[string]interface{}, actions map[string]interface{}) Rule {
	uri := config["uri"].(string)
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
	var acts []string
	for k := range actions {
		acts = append(acts, k)
	}
	return &RateLimitRule{
		name:      name,
		uri:       uri,
		methods:   methods,
		threshold: threshold,
		unit:      unit,
		operator:  operator,
		actions:   acts,
	}
}

func (r *RateLimitRule) Name() string {
	return r.name
}

func (r *RateLimitRule) Check(ctx context.Context, req *http.Request, guard *Guard) (bool, []string, error) {
	if !strings.HasPrefix(req.URL.Path, r.uri) {
		return false, nil, nil
	}
	found := false
	for _, m := range r.methods {
		if req.Method == m {
			found = true
			break
		}
	}
	if !found {
		return false, nil, nil
	}
	ip := getIP(req)
	key := ip + r.uri
	guard.mu.Lock()
	times := guard.requestTimes[key]
	now := time.Now()
	var newTimes []time.Time
	for _, t := range times {
		if now.Sub(t) < r.unit {
			newTimes = append(newTimes, t)
		}
	}
	count := len(newTimes)
	anomaly := false
	if r.operator == ">" && count > r.threshold {
		anomaly = true
	}
	if !anomaly {
		newTimes = append(newTimes, now)
		guard.requestTimes[key] = newTimes
	}
	guard.mu.Unlock()
	if anomaly {
		return true, r.actions, nil
	}
	return false, nil, nil
}

// Action implementations

type RateLimitAction struct {
	name        string
	baseDelay   int
	jitterRange int
}

func NewRateLimitAction(name string, config map[string]interface{}) Action {
	baseDelay := int(config["base_delay"].(float64))
	jitterRange := int(config["jitter_range"].(float64))
	return &RateLimitAction{
		name:        name,
		baseDelay:   baseDelay,
		jitterRange: jitterRange,
	}
}

func (a *RateLimitAction) Name() string {
	return a.name
}

func (a *RateLimitAction) Execute(ctx context.Context, req *http.Request, guard *Guard) error {
	delay := time.Duration(a.baseDelay+rand.Intn(a.jitterRange)) * time.Millisecond
	time.Sleep(delay)
	return nil
}

type WarningAction struct {
	name string
}

func NewWarningAction(name string, config map[string]interface{}) Action {
	return &WarningAction{name: name}
}

func (a *WarningAction) Name() string {
	return a.name
}

func (a *WarningAction) Execute(ctx context.Context, req *http.Request, guard *Guard) error {
	// Log warning
	fmt.Printf("Warning: Anomaly detected for IP %s\n", getIP(req))
	return nil
}

type RestrictAction struct {
	name string
}

func NewRestrictAction(name string, config map[string]interface{}) Action {
	return &RestrictAction{name: name}
}

func (a *RestrictAction) Name() string {
	return a.name
}

func (a *RestrictAction) Execute(ctx context.Context, req *http.Request, guard *Guard) error {
	return fmt.Errorf("restricted")
}

type TempBanAction struct {
	name     string
	duration time.Duration
}

func NewTempBanAction(name string, config map[string]interface{}) Action {
	durStr, ok := config["duration"].(string)
	if !ok {
		durStr = "1h"
	}
	dur, _ := time.ParseDuration(durStr)
	return &TempBanAction{
		name:     name,
		duration: dur,
	}
}

func (a *TempBanAction) Name() string {
	return a.name
}

func (a *TempBanAction) Execute(ctx context.Context, req *http.Request, guard *Guard) error {
	ip := getIP(req)
	guard.mu.Lock()
	guard.bannedIPs[ip] = time.Now().Add(a.duration)
	guard.mu.Unlock()
	return nil
}

type PermBanAction struct {
	name string
}

func NewPermBanAction(name string, config map[string]interface{}) Action {
	return &PermBanAction{name: name}
}

func (a *PermBanAction) Name() string {
	return a.name
}

func (a *PermBanAction) Execute(ctx context.Context, req *http.Request, guard *Guard) error {
	ip := getIP(req)
	guard.mu.Lock()
	guard.bannedIPs[ip] = time.Now().Add(100 * 365 * 24 * time.Hour)
	guard.mu.Unlock()
	return nil
}

// Registries

var ruleRegistry = map[string]func(name string, config map[string]interface{}, actions map[string]interface{}) Rule{
	"rate_limit":        NewRateLimitRule,
	"admin_restriction": NewRateLimitRule,
}

var actionRegistry = map[string]func(name string, config map[string]interface{}) Action{
	"rate_limit": NewRateLimitAction,
	"warning":    NewWarningAction,
	"restrict":   NewRestrictAction,
	"temp_ban":   NewTempBanAction,
	"perm_ban":   NewPermBanAction,
}
