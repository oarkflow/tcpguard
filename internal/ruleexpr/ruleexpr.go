package ruleexpr

import (
	"context"
	"regexp"
	"sync"

	"github.com/oarkflow/bcl"
	_ "github.com/oarkflow/rules"
)

type MapFacts map[string]any

func (m MapFacts) Get(path string) (any, bool) {
	value := lookupPath(map[string]any(m), path)
	return value, value != nil
}

type EvalContext struct {
	Context context.Context
	Facts   MapFacts
}

type Function func(EvalContext, ...any) (any, error)

type functionRegistry struct {
	mu  sync.RWMutex
	fns map[string]Function
}

var globalFunctions = &functionRegistry{fns: map[string]Function{}}

func RegisterFunction(name string, fn Function) {
	globalFunctions.mu.Lock()
	defer globalFunctions.mu.Unlock()
	globalFunctions.fns[name] = fn
}

func GlobalFunctions() *functionRegistry {
	return globalFunctions
}

func (r *functionRegistry) Get(name string) (Function, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	fn, ok := r.fns[name]
	return fn, ok
}

func (r *functionRegistry) evalFunctions(ctx context.Context, facts MapFacts, names []string) map[string]bcl.EvalFunction {
	if len(names) == 0 {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]bcl.EvalFunction, len(names))
	for _, name := range names {
		fn, ok := r.fns[name]
		if !ok {
			continue
		}
		out[name] = func(args []any, _ *bcl.EvalOptions) (any, error) {
			return fn(EvalContext{Context: ctx, Facts: facts}, args...)
		}
	}
	return out
}

type Expression struct {
	program            *bcl.ExpressionProgram
	raw                string
	functionNames      []string
	numericDefaultPath []string
}

type Result struct {
	Matched bool
	Value   any
}

func Compile(raw string) (*Expression, error) {
	program, err := bcl.CompileExpression(raw)
	if err != nil {
		return nil, err
	}
	return &Expression{
		program:            program,
		raw:                raw,
		functionNames:      calledFunctions(raw),
		numericDefaultPath: numericDefaultPaths(raw),
	}, nil
}

func (e *Expression) Eval(ctx context.Context, facts MapFacts) (Result, error) {
	return e.eval(ctx, facts, facts, false)
}

// PrepareFacts creates a normalized evaluation snapshot. Call it once when a
// facts tree will be evaluated by multiple expressions.
func PrepareFacts(facts MapFacts) MapFacts {
	return MapFacts(copyFactsForEval(facts))
}

// EvalPrepared evaluates against facts returned by PrepareFacts. The prepared
// tree is read-only except that expressions requiring numeric compatibility
// defaults receive a private copy.
func (e *Expression) EvalPrepared(ctx context.Context, facts MapFacts) (Result, error) {
	return e.eval(ctx, facts, facts, true)
}

// EvalPreparedWithOriginalFacts keeps registered functions bound to the
// caller's original facts while the interpreter reads a prepared snapshot.
func (e *Expression) EvalPreparedWithOriginalFacts(ctx context.Context, facts, original MapFacts) (Result, error) {
	return e.eval(ctx, facts, original, true)
}

func (e *Expression) eval(ctx context.Context, facts, functionFacts MapFacts, prepared bool) (Result, error) {
	if e == nil || e.program == nil {
		return Result{}, nil
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
	}
	vars := map[string]any(facts)
	if !prepared {
		vars = factsForEval(facts, e.numericDefaultPath)
	} else if len(e.numericDefaultPath) > 0 {
		vars = factsForEval(facts, e.numericDefaultPath)
	}
	value, err := e.program.Eval(vars, &bcl.EvalOptions{
		AllowEncoding: true,
		AllowHash:     true,
		AllowTime:     true,
		Variables:     vars,
		Functions:     globalFunctions.evalFunctions(ctx, functionFacts, e.functionNames),
	})
	if err != nil {
		return Result{}, err
	}
	// The BCL interpreter is synchronous and cannot be preempted mid-expression.
	// Detect deadlines/cancellation immediately after it returns so callers do
	// not treat an evaluation that exceeded its budget as a valid match.
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
	}
	return Result{Matched: truthy(value), Value: value}, nil
}

func calledFunctions(raw string) []string {
	var names []string
	seen := make(map[string]struct{})
	for i := 0; i < len(raw); {
		if !isIdentifierStart(raw[i]) {
			i++
			continue
		}
		start := i
		for i < len(raw) && isIdentifierPart(raw[i]) {
			i++
		}
		end := i
		for end < len(raw) && (raw[end] == ' ' || raw[end] == '\t' || raw[end] == '\r' || raw[end] == '\n') {
			end++
		}
		if end >= len(raw) || raw[end] != '(' {
			continue
		}
		name := raw[start:i]
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

func isIdentifierStart(value byte) bool {
	return value == '_' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func isIdentifierPart(value byte) bool {
	return isIdentifierStart(value) || value >= '0' && value <= '9'
}

var numericThresholdPattern = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\s*(?:>|>=)\s*-?\d+(?:\.\d+)?\b`)

func numericDefaultPaths(raw string) []string {
	matches := numericThresholdPattern.FindAllStringSubmatch(raw, -1)
	paths := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		path := match[1]
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	return paths
}

func ensureNumericComparisonDefaults(vars map[string]any, paths []string) {
	for _, path := range paths {
		if _, found := lookupPathFound(vars, path); found {
			continue
		}
		setPath(vars, path, 0)
	}
}

func factsForEval(facts MapFacts, numericDefaultPaths []string) map[string]any {
	vars := map[string]any(facts)
	needsCopy := !isNormalizedMap(vars)
	if !needsCopy {
		for _, path := range numericDefaultPaths {
			if _, found := lookupPathFound(vars, path); !found {
				needsCopy = true
				break
			}
		}
	}
	if !needsCopy {
		// The BCL expression evaluator only reads its variable map. Reuse the
		// normalized facts directly when no compatibility defaults are needed.
		return vars
	}
	vars = copyFactsForEval(facts)
	ensureNumericComparisonDefaults(vars, numericDefaultPaths)
	return vars
}

func Chain(facts ...MapFacts) MapFacts {
	out := MapFacts{}
	for _, fact := range facts {
		for key, value := range fact {
			out[key] = value
		}
	}
	return out
}

func lookupPath(v any, path string) any {
	value, _ := lookupPathFound(v, path)
	return value
}

func lookupPathFound(v any, path string) (any, bool) {
	cur := v
	for _, part := range splitPath(path) {
		switch node := cur.(type) {
		case map[string]any:
			value, found := node[part]
			if !found {
				return nil, false
			}
			cur = value
		case MapFacts:
			value, found := node[part]
			if !found {
				return nil, false
			}
			cur = value
		default:
			return nil, false
		}
	}
	return cur, true
}

func setPath(root map[string]any, path string, value any) {
	parts := splitPath(path)
	if len(parts) == 0 {
		return
	}
	cur := root
	for _, part := range parts[:len(parts)-1] {
		next, ok := normalizeMapValue(cur[part])
		if !ok {
			next = map[string]any{}
		} else {
			next = cloneMap(next)
		}
		cur[part] = next
		cur = next
	}
	cur[parts[len(parts)-1]] = value
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case nil:
		return false
	case string:
		return x != ""
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0
	default:
		return true
	}
}

func normalizeValue(v any) any {
	switch x := v.(type) {
	case MapFacts:
		return normalizeMap(map[string]any(x))
	case map[string]any:
		return normalizeMap(x)
	case map[string]string:
		out := make(map[string]any, len(x))
		for key, value := range x {
			out[key] = value
		}
		return out
	case []any:
		if isNormalizedSlice(x) {
			return x
		}
		out := make([]any, len(x))
		for i, value := range x {
			out[i] = normalizeValue(value)
		}
		return out
	default:
		return v
	}
}

func copyFactsForEval(facts MapFacts) map[string]any {
	out := make(map[string]any, len(facts))
	for key, value := range facts {
		out[key] = normalizeValue(value)
	}
	return out
}

func normalizeMap(value map[string]any) map[string]any {
	if isNormalizedMap(value) {
		return value
	}
	return cloneNormalizedMap(value)
}

func isNormalizedMap(value map[string]any) bool {
	for _, item := range value {
		switch child := item.(type) {
		case MapFacts, map[string]string:
			return false
		case map[string]any:
			if !isNormalizedMap(child) {
				return false
			}
		case []any:
			if !isNormalizedSlice(child) {
				return false
			}
		}
	}
	return true
}

func isNormalizedSlice(value []any) bool {
	for _, item := range value {
		switch child := item.(type) {
		case MapFacts, map[string]string:
			return false
		case map[string]any:
			if !isNormalizedMap(child) {
				return false
			}
		case []any:
			if !isNormalizedSlice(child) {
				return false
			}
		}
	}
	return true
}

func normalizeMapValue(value any) (map[string]any, bool) {
	switch x := value.(type) {
	case map[string]any:
		return x, true
	case MapFacts:
		return map[string]any(x), true
	case map[string]string:
		out := make(map[string]any, len(x))
		for key, item := range x {
			out[key] = item
		}
		return out, true
	default:
		return nil, false
	}
}

func cloneMap(value map[string]any) map[string]any {
	out := make(map[string]any, len(value))
	for key, item := range value {
		out[key] = item
	}
	return out
}

func cloneNormalizedMap(value map[string]any) map[string]any {
	out := make(map[string]any, len(value))
	for key, item := range value {
		out[key] = normalizeValue(item)
	}
	return out
}

func splitPath(path string) []string {
	if path == "" {
		return nil
	}
	parts := make([]string, 0, 4)
	start := 0
	for i := 0; i < len(path); i++ {
		if path[i] == '.' {
			if start < i {
				parts = append(parts, path[start:i])
			}
			start = i + 1
		}
	}
	if start < len(path) {
		parts = append(parts, path[start:])
	}
	return parts
}
