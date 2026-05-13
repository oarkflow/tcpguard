package tcpguard

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/condition"
	_ "modernc.org/sqlite"
)

const lookupContextFact = "__tcpguard_lookup_context"

type LookupContext struct {
	sec         *Context
	datasources map[string]DataSource
	lookups     map[string]LookupDefinition
	safety      PolicySafety
	mu          sync.Mutex
	cache       map[string]LookupResult
	failures    []LookupFailure
	calls       int
	started     time.Time
	budget      time.Duration
}

type LookupFailure struct {
	Lookup LookupDefinition
	Err    error
}

type datasourceCircuitState struct {
	failures int
	openTill time.Time
}

var datasourceCircuits sync.Map

func NewLookupContext(sec *Context, sources map[string]DataSource, lookups []LookupDefinition, safety PolicySafety) *LookupContext {
	byID := map[string]LookupDefinition{}
	for _, lookup := range lookups {
		byID[lookup.ID] = lookup
	}
	budget := time.Duration(0)
	if safety.MaxLookupTimeout > 0 && safety.MaxLookupsPerEval > 0 {
		budget = safety.MaxLookupTimeout * time.Duration(safety.MaxLookupsPerEval)
	}
	return &LookupContext{sec: sec, datasources: sources, lookups: byID, safety: safety, cache: map[string]LookupResult{}, started: time.Now(), budget: budget}
}

func copyDataSources(in map[string]DataSource) map[string]DataSource {
	out := make(map[string]DataSource, len(in))
	for id, source := range in {
		out[id] = source
	}
	return out
}

func configureDataSources(cfg *config) error {
	if cfg.datasources == nil {
		cfg.datasources = map[string]DataSource{}
	}
	if cfg.store != nil {
		if cfg.datasources["security_store"] == nil {
			cfg.datasources["security_store"] = MemoryDataSource{SourceID: "security_store", Store: cfg.store}
		}
	}
	for _, def := range cfg.datasourceDefs {
		if def.ID == "" {
			return errors.New("tcpguard: datasource id is required")
		}
		if cfg.datasources[def.ID] != nil {
			continue
		}
		source, err := dataSourceFromDefinition(def, cfg.store)
		if err != nil {
			return err
		}
		if source != nil {
			cfg.datasources[source.ID()] = source
		}
	}
	return nil
}

func dataSourceFromDefinition(def DataSourceDefinition, store SecurityStore) (DataSource, error) {
	switch def.Type {
	case "", "memory":
		return MemoryDataSource{SourceID: def.ID, Store: store, Prefix: def.Prefix}, nil
	case "redis":
		if redisStore, ok := store.(RedisStore); ok {
			return RedisDataSource{SourceID: def.ID, Store: redisStore, Prefix: firstNonEmpty(def.Prefix, redisStore.Prefix)}, nil
		}
		if redisStore, ok := store.(*RedisStore); ok {
			return RedisDataSource{SourceID: def.ID, Store: *redisStore, Prefix: firstNonEmpty(def.Prefix, redisStore.Prefix)}, nil
		}
		return nil, fmt.Errorf("tcpguard: redis datasource %s requires RedisStore or registered datasource", def.ID)
	case "csv":
		return CSVDataSource{SourceID: def.ID, Path: def.Path, KeyField: def.Key}, nil
	case "json":
		return JSONDataSource{SourceID: def.ID, Path: def.Path, KeyField: def.Key}, nil
	case "http":
		return HTTPDataSource{Definition: def}, nil
	case "sql":
		if def.Driver == "sqlite" && def.DSN != "" {
			db, err := sql.Open("sqlite", renderEnvString(def.DSN))
			if err != nil {
				return nil, err
			}
			return SQLDataSource{SourceID: def.ID, DB: db}, nil
		}
		return nil, fmt.Errorf("tcpguard: sql datasource %s requires registered *sql.DB unless driver sqlite with dsn is configured", def.ID)
	default:
		return nil, fmt.Errorf("tcpguard: unsupported datasource type %q", def.Type)
	}
}

func validateLookupsAgainstSafety(lookups []LookupDefinition, sources map[string]DataSource, safety PolicySafety) error {
	allowed := map[string]bool{}
	for _, typ := range safety.AllowedDataSources {
		allowed[typ] = true
	}
	for _, lookup := range lookups {
		if lookup.ID == "" {
			return errors.New("tcpguard: lookup id is required")
		}
		if lookup.Source == "" {
			return fmt.Errorf("tcpguard: lookup %s source is required", lookup.ID)
		}
		source := sources[lookup.Source]
		if source == nil {
			return fmt.Errorf("tcpguard: lookup %s references missing datasource %s", lookup.ID, lookup.Source)
		}
		if len(allowed) > 0 {
			sourceType := dataSourceType(source)
			if !allowed[sourceType] {
				return fmt.Errorf("tcpguard: datasource type %s for lookup %s is not allowlisted", sourceType, lookup.ID)
			}
		}
		if safety.MaxLookupTimeout > 0 && lookup.Timeout > safety.MaxLookupTimeout {
			return fmt.Errorf("tcpguard: lookup %s timeout %s above limit %s", lookup.ID, lookup.Timeout, safety.MaxLookupTimeout)
		}
		if strings.TrimSpace(lookup.Query) != "" && !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(lookup.Query)), "SELECT") {
			return fmt.Errorf("tcpguard: lookup %s SQL query must be read-only SELECT", lookup.ID)
		}
		if lookup.Fallback.Policy == "" {
			lookup.Fallback.Policy = LookupFallbackAllow
		}
	}
	return nil
}

func dataSourceType(source DataSource) string {
	switch source.(type) {
	case RedisDataSource:
		return "redis"
	case CSVDataSource:
		return "csv"
	case JSONDataSource:
		return "json"
	case SQLDataSource:
		return "sql"
	case HTTPDataSource:
		return "http"
	default:
		return "memory"
	}
}

func (g *Guard) runPreloadLookups(ctx context.Context, sec *Context, snap *runtimeSnapshot, candidateRules []int) {
	if sec.lookup == nil {
		return
	}
	for _, lookup := range sec.lookup.lookups {
		if lookup.Mode != "preload" {
			continue
		}
		if snap != nil && !preloadLookupNeeded(lookup.ID, snap, candidateRules) {
			continue
		}
		result, err := sec.lookup.Evaluate(ctx, lookup.ID, "")
		if err != nil {
			continue
		}
		applyLookupOutput(sec, lookup, result)
	}
}

func preloadLookupNeeded(id string, snap *runtimeSnapshot, candidateRules []int) bool {
	if id == "" || snap == nil {
		return true
	}
	if snap.lookupAlways[id] {
		return true
	}
	refs := snap.lookupRefs[id]
	if len(refs) == 0 {
		return true
	}
	if len(candidateRules) == 0 {
		return false
	}
	for _, candidate := range candidateRules {
		for _, ref := range refs {
			if candidate == ref {
				return true
			}
		}
	}
	return false
}

func applyLookupOutput(sec *Context, lookup LookupDefinition, result LookupResult) {
	for from, to := range lookup.Outputs {
		value, ok := resultField(result, from)
		if ok {
			setContextFact(sec, to, value)
		}
	}
	setLookupFacts(sec, lookup.ID, result, nil, false)
}

func setLookupFacts(sec *Context, id string, result LookupResult, err error, fallback bool) {
	base := "store." + id + "."
	setContextFact(sec, base+"found", result.Found)
	setContextFact(sec, base+"fallback_applied", fallback)
	if err != nil {
		setContextFact(sec, base+"error", err.Error())
	} else {
		setContextFact(sec, base+"error", "")
	}
	for key, value := range result.Fields {
		setContextFact(sec, base+"fields."+key, value)
	}
}

func (lc *LookupContext) Evaluate(ctx context.Context, id, keyOverride string) (LookupResult, error) {
	lookup, ok := lc.lookups[id]
	directSource := false
	if !ok {
		if lc.datasources[id] == nil {
			return LookupResult{}, fmt.Errorf("tcpguard: lookup or datasource %s not found", id)
		}
		directSource = true
		lookup = LookupDefinition{ID: id, Source: id, Key: keyOverride, Fallback: LookupFallback{Policy: LookupFallbackErrorFact}}
	}
	cacheKey := id + "\x00" + keyOverride
	lc.mu.Lock()
	if result, ok := lc.cache[cacheKey]; ok {
		lc.mu.Unlock()
		return result, nil
	}
	if lc.safety.MaxLookupsPerEval > 0 && lc.calls >= lc.safety.MaxLookupsPerEval {
		lc.mu.Unlock()
		return LookupResult{}, fmt.Errorf("tcpguard: max lookups per evaluation exceeded")
	}
	if lc.budget > 0 && time.Since(lc.started) > lc.budget {
		lc.mu.Unlock()
		return LookupResult{}, fmt.Errorf("tcpguard: lookup time budget exceeded")
	}
	lc.calls++
	lc.mu.Unlock()
	req, err := lc.requestForLookup(ctx, lookup, keyOverride)
	if err != nil {
		result, handleErr := lc.handleFailure(lookup, err)
		lc.cacheLookupResult(cacheKey, result)
		return result, handleErr
	}
	source := lc.datasources[lookup.Source]
	if source == nil {
		result, handleErr := lc.handleFailure(lookup, fmt.Errorf("tcpguard: datasource %s not found", lookup.Source))
		lc.cacheLookupResult(cacheKey, result)
		return result, handleErr
	}
	if datasourceCircuitOpen(lookup.Source) {
		result, handleErr := lc.handleFailure(lookup, fmt.Errorf("tcpguard: datasource %s circuit is open", lookup.Source))
		lc.cacheLookupResult(cacheKey, result)
		return result, handleErr
	}
	timeout := lookup.Timeout
	if timeout <= 0 {
		timeout = lc.safety.MaxLookupTimeout
	}
	callCtx := ctx
	cancel := func() {}
	if timeout > 0 {
		callCtx, cancel = context.WithTimeout(ctx, timeout)
	}
	result, err := source.Lookup(callCtx, req)
	cancel()
	if err != nil {
		datasourceCircuitFailure(lookup.Source)
		result, handleErr := lc.handleFailure(lookup, err)
		lc.cacheLookupResult(cacheKey, result)
		return result, handleErr
	}
	datasourceCircuitSuccess(lookup.Source)
	if result.Fields == nil {
		result.Fields = resultMap(result.Value)
	}
	if directSource && len(result.Fields) == 0 && result.Value != nil {
		result.Fields = map[string]any{"value": result.Value}
	}
	lc.cacheLookupResult(cacheKey, result)
	setLookupFacts(lc.sec, lookup.ID, result, nil, false)
	return result, nil
}

func (lc *LookupContext) cacheLookupResult(cacheKey string, result LookupResult) {
	lc.mu.Lock()
	lc.cache[cacheKey] = result
	lc.mu.Unlock()
}

func (lc *LookupContext) requestForLookup(ctx context.Context, lookup LookupDefinition, keyOverride string) (LookupRequest, error) {
	key := keyOverride
	if key == "" {
		value, err := evalLookupExpression(ctx, lc.sec, lookup.Key)
		if err != nil {
			return LookupRequest{}, err
		}
		key = stringify(value)
	}
	params := map[string]any{}
	for name, expr := range lookup.Params {
		value, err := evalLookupExpression(ctx, lc.sec, expr)
		if err != nil {
			return LookupRequest{}, err
		}
		params[name] = value
	}
	return LookupRequest{Source: lookup.Source, Key: key, Value: key, Query: lookup.Query, Params: params}, nil
}

func (lc *LookupContext) handleFailure(lookup LookupDefinition, err error) (LookupResult, error) {
	result := LookupResult{Fields: map[string]any{}}
	fallback := lookup.Fallback
	if fallback.Policy == "" {
		fallback.Policy = LookupFallbackAllow
	}
	if fallback.Policy == LookupFallbackDefault {
		result.Found = true
		result.Fields = cloneAnyMap(fallback.Value)
		result.Value = result.Fields
	}
	setLookupFacts(lc.sec, lookup.ID, result, err, true)
	lc.mu.Lock()
	lc.failures = append(lc.failures, LookupFailure{Lookup: lookup, Err: err})
	lc.mu.Unlock()
	if fallback.Policy == LookupFallbackDefault || fallback.Policy == LookupFallbackAllow || fallback.Policy == LookupFallbackErrorFact || fallback.Policy == LookupFallbackChallenge || fallback.Policy == LookupFallbackBlock {
		return result, nil
	}
	return result, err
}

func datasourceCircuitOpen(source string) bool {
	if source == "" {
		return false
	}
	raw, ok := datasourceCircuits.Load(source)
	if !ok {
		return false
	}
	state, ok := raw.(datasourceCircuitState)
	return ok && !state.openTill.IsZero() && time.Now().Before(state.openTill)
}

func datasourceCircuitFailure(source string) {
	if source == "" {
		return
	}
	state := datasourceCircuitState{}
	if raw, ok := datasourceCircuits.Load(source); ok {
		state, _ = raw.(datasourceCircuitState)
	}
	state.failures++
	if state.failures >= 3 {
		state.openTill = time.Now().Add(30 * time.Second)
	}
	datasourceCircuits.Store(source, state)
}

func datasourceCircuitSuccess(source string) {
	if source != "" {
		datasourceCircuits.Delete(source)
	}
}

func applyLookupFailures(sec *Context, decision *Decision) {
	if sec == nil || sec.lookup == nil || decision == nil {
		return
	}
	sec.lookup.mu.Lock()
	failures := append([]LookupFailure(nil), sec.lookup.failures...)
	sec.lookup.mu.Unlock()
	for _, failure := range failures {
		policy := failure.Lookup.Fallback.Policy
		if policy == "" {
			policy = LookupFallbackAllow
		}
		switch policy {
		case LookupFallbackBlock:
			decision.Effect = DecisionBlock
			decision.Allowed = false
			decision.Severity = SeverityCritical
			if decision.Risk.Score < 90 {
				decision.Risk.Score = 90
			}
			decision.Explanation = buildLookupFailureExplanation(sec, failure, DecisionBlock)
			return
		case LookupFallbackChallenge:
			if decision.Effect != DecisionBlock {
				decision.Effect = DecisionChallenge
				decision.Allowed = false
				if decision.Severity == SeverityInfo || decision.Severity == SeverityLow || decision.Severity == SeverityMedium {
					decision.Severity = SeverityHigh
				}
				if decision.Risk.Score < 75 {
					decision.Risk.Score = 75
				}
				decision.Explanation = buildLookupFailureExplanation(sec, failure, DecisionChallenge)
			}
		}
	}
}

func evalLookupExpression(ctx context.Context, sec *Context, expr string) (any, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return "", nil
	}
	if isQuoted(expr) {
		return trimQuotes(expr), nil
	}
	if strings.HasPrefix(expr, "concat(") && strings.HasSuffix(expr, ")") {
		return evalConcatExpression(ctx, sec, strings.TrimSuffix(strings.TrimPrefix(expr, "concat("), ")"))
	}
	if sec != nil && sec.Facts != nil {
		if value, ok := sec.Facts.Get(expr); ok {
			return value, nil
		}
	}
	return parseLiteral(expr), nil
}

func evalConcatExpression(ctx context.Context, sec *Context, raw string) (string, error) {
	parts := splitArgs(raw)
	var b strings.Builder
	for _, part := range parts {
		value, err := evalLookupExpression(ctx, sec, part)
		if err != nil {
			return "", err
		}
		b.WriteString(stringify(value))
	}
	return b.String(), nil
}

type MemoryDataSource struct {
	SourceID string
	Values   map[string]any
	Store    SecurityStore
	Prefix   string
}

func (s MemoryDataSource) ID() string { return s.SourceID }
func (s MemoryDataSource) Lookup(ctx context.Context, req LookupRequest) (LookupResult, error) {
	key := s.Prefix + req.Key
	if s.Values != nil {
		value, found := s.Values[key]
		if !found {
			value, found = s.Values[req.Key]
		}
		return lookupResultFromValue(value, found), nil
	}
	if s.Store == nil {
		return LookupResult{}, nil
	}
	data, found, err := s.Store.Get(ctx, key)
	if err != nil || !found {
		return LookupResult{}, err
	}
	return decodeLookupBytes(data), nil
}

type RedisDataSource struct {
	SourceID string
	Store    RedisStore
	Prefix   string
}

func (s RedisDataSource) ID() string { return s.SourceID }
func (s RedisDataSource) Lookup(ctx context.Context, req LookupRequest) (LookupResult, error) {
	key := req.Key
	if s.Prefix != "" && !strings.HasPrefix(key, s.Prefix) {
		key = strings.TrimPrefix(s.Prefix, s.Store.Prefix) + key
	}
	data, found, err := s.Store.Get(ctx, key)
	if err != nil || !found {
		return LookupResult{}, err
	}
	return decodeLookupBytes(data), nil
}

type CSVDataSource struct {
	SourceID string
	Path     string
	KeyField string
}

func (s CSVDataSource) ID() string { return s.SourceID }
func (s CSVDataSource) Lookup(ctx context.Context, req LookupRequest) (LookupResult, error) {
	if err := ctx.Err(); err != nil {
		return LookupResult{}, err
	}
	file, err := os.Open(s.Path)
	if err != nil {
		return LookupResult{}, err
	}
	defer file.Close()
	rows, err := csv.NewReader(file).ReadAll()
	if err != nil || len(rows) == 0 {
		return LookupResult{}, err
	}
	headers := rows[0]
	keyField := firstNonEmpty(s.KeyField, req.Key)
	if keyField == "" {
		keyField = headers[0]
	}
	for _, row := range rows[1:] {
		record := map[string]any{}
		for i, header := range headers {
			if i < len(row) {
				record[header] = row[i]
			}
		}
		if stringify(record[keyField]) == stringify(req.Value) {
			return LookupResult{Found: true, Value: record, Fields: record}, nil
		}
	}
	return LookupResult{Found: false}, nil
}

type JSONDataSource struct {
	SourceID string
	Path     string
	KeyField string
}

func (s JSONDataSource) ID() string { return s.SourceID }
func (s JSONDataSource) Lookup(ctx context.Context, req LookupRequest) (LookupResult, error) {
	if err := ctx.Err(); err != nil {
		return LookupResult{}, err
	}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return LookupResult{}, err
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return LookupResult{}, err
	}
	return lookupJSON(value, firstNonEmpty(s.KeyField, req.Key), req.Value), nil
}

type SQLDataSource struct {
	SourceID string
	DB       *sql.DB
}

func (s SQLDataSource) ID() string { return s.SourceID }
func (s SQLDataSource) Lookup(ctx context.Context, req LookupRequest) (LookupResult, error) {
	if s.DB == nil {
		return LookupResult{}, errors.New("sql datasource is not configured")
	}
	query, args := bindSQLParams(req.Query, req.Params)
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return LookupResult{}, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return LookupResult{}, err
	}
	if !rows.Next() {
		return LookupResult{Found: false}, rows.Err()
	}
	values := make([]any, len(columns))
	ptrs := make([]any, len(columns))
	for i := range values {
		ptrs[i] = &values[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return LookupResult{}, err
	}
	fields := map[string]any{}
	for i, column := range columns {
		fields[column] = normalizeSQLValue(column, values[i])
	}
	return LookupResult{Found: true, Value: fields, Fields: fields}, rows.Err()
}

type HTTPDataSource struct {
	Definition DataSourceDefinition
	Client     *http.Client
}

func (s HTTPDataSource) ID() string { return s.Definition.ID }
func (s HTTPDataSource) Lookup(ctx context.Context, req LookupRequest) (LookupResult, error) {
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}
	method := firstNonEmpty(s.Definition.Method, http.MethodPost)
	var body io.Reader
	url := renderEnvString(s.Definition.URL)
	if method == http.MethodGet {
		if req.Key != "" {
			if strings.Contains(url, "?") {
				url += "&key=" + req.Key
			} else {
				url += "?key=" + req.Key
			}
		}
	} else {
		data, _ := json.Marshal(req)
		body = bytes.NewReader(data)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return LookupResult{}, err
	}
	for key, value := range s.Definition.Headers {
		httpReq.Header.Set(key, renderEnvString(value))
	}
	if method != http.MethodGet && httpReq.Header.Get("Content-Type") == "" {
		httpReq.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return LookupResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return LookupResult{}, fmt.Errorf("http datasource returned %d", resp.StatusCode)
	}
	var value any
	if err := json.NewDecoder(resp.Body).Decode(&value); err != nil {
		return LookupResult{}, err
	}
	return lookupResultFromValue(value, true), nil
}

func lookupResultFromValue(value any, found bool) LookupResult {
	fields := resultMap(value)
	return LookupResult{Found: found, Value: value, Fields: fields}
}

func decodeLookupBytes(data []byte) LookupResult {
	var value any
	if json.Unmarshal(data, &value) == nil {
		return lookupResultFromValue(value, true)
	}
	return LookupResult{Found: true, Value: string(data), Fields: map[string]any{"value": string(data)}}
}

func lookupJSON(value any, keyField string, key any) LookupResult {
	switch v := value.(type) {
	case map[string]any:
		if item, found := v[stringify(key)]; found {
			return lookupResultFromValue(item, true)
		}
		if keyField != "" && stringify(v[keyField]) == stringify(key) {
			return lookupResultFromValue(v, true)
		}
	case []any:
		for _, item := range v {
			fields := resultMap(item)
			if keyField != "" && stringify(fields[keyField]) == stringify(key) {
				return lookupResultFromValue(item, true)
			}
		}
	}
	return LookupResult{Found: false}
}

func resultMap(value any) map[string]any {
	switch v := value.(type) {
	case map[string]any:
		return v
	case condition.MapFacts:
		return map[string]any(v)
	case map[string]string:
		out := map[string]any{}
		for key, value := range v {
			out[key] = value
		}
		return out
	default:
		return nil
	}
}

func resultField(result LookupResult, field string) (any, bool) {
	if field == "" || field == "value" {
		return result.Value, result.Found
	}
	value, ok := result.Fields[field]
	return value, ok
}

func cloneAnyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func bindSQLParams(query string, params map[string]any) (string, []any) {
	var args []any
	names := make([]string, 0, len(params))
	for name := range params {
		names = append(names, name)
	}
	sort.SliceStable(names, func(i, j int) bool {
		return strings.Index(query, ":"+names[i]) < strings.Index(query, ":"+names[j])
	})
	for _, name := range names {
		token := ":" + name
		if strings.Contains(query, token) {
			query = strings.ReplaceAll(query, token, "?")
			args = append(args, params[name])
		}
	}
	return query, args
}

func normalizeSQLValue(column string, value any) any {
	if b, ok := value.([]byte); ok {
		return string(b)
	}
	if i, ok := value.(int64); ok && isBoolColumn(column) && (i == 0 || i == 1) {
		return i == 1
	}
	return value
}

func isBoolColumn(column string) bool {
	column = strings.ToLower(column)
	return column == "locked" || strings.HasPrefix(column, "is_") || strings.HasPrefix(column, "has_") || strings.HasSuffix(column, "_enabled") || strings.HasSuffix(column, "_disabled")
}

func isQuoted(s string) bool {
	return len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\''))
}

func trimQuotes(s string) string {
	return strings.Trim(strings.TrimSpace(s), `"'`)
}

func splitArgs(raw string) []string {
	var out []string
	var b strings.Builder
	quote := rune(0)
	depth := 0
	for _, r := range raw {
		switch {
		case quote != 0:
			b.WriteRune(r)
			if r == quote {
				quote = 0
			}
		case r == '"' || r == '\'':
			quote = r
			b.WriteRune(r)
		case r == '(':
			depth++
			b.WriteRune(r)
		case r == ')':
			if depth > 0 {
				depth--
			}
			b.WriteRune(r)
		case r == ',' && depth == 0:
			out = append(out, strings.TrimSpace(b.String()))
			b.Reset()
		default:
			b.WriteRune(r)
		}
	}
	if strings.TrimSpace(b.String()) != "" {
		out = append(out, strings.TrimSpace(b.String()))
	}
	return out
}

func parseLiteral(raw string) any {
	raw = strings.TrimSpace(raw)
	if raw == "true" {
		return true
	}
	if raw == "false" {
		return false
	}
	return raw
}

func renderEnvString(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "{{env(") && strings.HasSuffix(s, ")}}") {
		name := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(s, "{{env("), ")}}"), `"`)
		return os.Getenv(name)
	}
	if strings.HasPrefix(s, "env(") && strings.HasSuffix(s, ")") {
		name := strings.Trim(strings.TrimSuffix(strings.TrimPrefix(s, "env("), ")"), `"`)
		return os.Getenv(name)
	}
	return s
}
