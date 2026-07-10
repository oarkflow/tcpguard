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

func (r *functionRegistry) evalFunctions(ctx context.Context, facts MapFacts) map[string]bcl.EvalFunction {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]bcl.EvalFunction, len(r.fns))
	for name, fn := range r.fns {
		fn := fn
		out[name] = func(args []any, _ *bcl.EvalOptions) (any, error) {
			return fn(EvalContext{Context: ctx, Facts: facts}, args...)
		}
	}
	return out
}

type Expression struct {
	program *bcl.ExpressionProgram
	raw     string
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
	return &Expression{program: program, raw: raw}, nil
}

func (e *Expression) Eval(ctx context.Context, facts MapFacts) (Result, error) {
	if e == nil || e.program == nil {
		return Result{}, nil
	}
	vars := normalizeValue(map[string]any(facts)).(map[string]any)
	ensureNumericComparisonDefaults(vars, e.raw)
	value, err := e.program.Eval(vars, &bcl.EvalOptions{
		AllowEncoding: true,
		AllowHash:     true,
		AllowTime:     true,
		Variables:     vars,
		Functions:     globalFunctions.evalFunctions(ctx, facts),
	})
	if err != nil {
		return Result{}, err
	}
	return Result{Matched: truthy(value), Value: value}, nil
}

var numericThresholdPattern = regexp.MustCompile(`\b([A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\s*(?:>|>=)\s*-?\d+(?:\.\d+)?\b`)

func ensureNumericComparisonDefaults(vars map[string]any, raw string) {
	for _, match := range numericThresholdPattern.FindAllStringSubmatch(raw, -1) {
		path := match[1]
		if _, found := lookupPathFound(vars, path); found {
			continue
		}
		setPath(vars, path, 0)
	}
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
		next, _ := cur[part].(map[string]any)
		if next == nil {
			next = map[string]any{}
			cur[part] = next
		}
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
		return normalizeValue(map[string]any(x))
	case map[string]any:
		out := make(map[string]any, len(x))
		for key, value := range x {
			out[key] = normalizeValue(value)
		}
		return out
	case map[string]string:
		out := make(map[string]any, len(x))
		for key, value := range x {
			out[key] = value
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, value := range x {
			out[i] = normalizeValue(value)
		}
		return out
	default:
		return v
	}
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
