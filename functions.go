package tcpguard

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/oarkflow/condition"
)

func init() {
	condition.RegisterFunction("wildcard_match", func(_ condition.EvalContext, args ...any) (any, error) {
		if len(args) != 2 {
			return nil, fmt.Errorf("wildcard_match expects value and pattern")
		}
		value, ok := args[0].(string)
		if !ok {
			return false, nil
		}
		pattern, ok := args[1].(string)
		if !ok {
			return false, nil
		}
		return glob(pattern, value), nil
	})
	condition.RegisterFunction("pattern_match", func(ctx condition.EvalContext, args ...any) (any, error) {
		fn, _ := condition.GlobalFunctions().Get("wildcard_match")
		return fn(ctx, args...)
	})
	condition.RegisterFunction("route_match", func(ctx condition.EvalContext, args ...any) (any, error) {
		fn, _ := condition.GlobalFunctions().Get("wildcard_match")
		return fn(ctx, args...)
	})
	condition.RegisterFunction("env", func(_ condition.EvalContext, args ...any) (any, error) {
		if len(args) < 1 || len(args) > 2 {
			return nil, fmt.Errorf("env expects variable name and optional default")
		}
		name, ok := args[0].(string)
		if !ok {
			return "", nil
		}
		value := os.Getenv(name)
		if value == "" && len(args) == 2 {
			return stringify(args[1]), nil
		}
		return value, nil
	})
	condition.RegisterFunction("context", func(ctx condition.EvalContext, args ...any) (any, error) {
		if len(args) < 1 || len(args) > 2 {
			return nil, fmt.Errorf("context expects path and optional default")
		}
		path, ok := args[0].(string)
		if !ok || ctx.Facts == nil {
			if len(args) == 2 {
				return args[1], nil
			}
			return nil, nil
		}
		value, found := ctx.Facts.Get(path)
		if !found {
			if len(args) == 2 {
				return args[1], nil
			}
			return nil, nil
		}
		return value, nil
	})
	condition.RegisterFunction("session", func(ctx condition.EvalContext, args ...any) (any, error) {
		if len(args) < 1 || len(args) > 2 {
			return nil, fmt.Errorf("session expects path and optional default")
		}
		path, ok := args[0].(string)
		if !ok || ctx.Facts == nil {
			if len(args) == 2 {
				return args[1], nil
			}
			return nil, nil
		}
		if !strings.HasPrefix(path, "session.") {
			path = "session." + path
		}
		value, found := ctx.Facts.Get(path)
		if !found {
			if len(args) == 2 {
				return args[1], nil
			}
			return nil, nil
		}
		return value, nil
	})
	condition.RegisterFunction("concat", func(_ condition.EvalContext, args ...any) (any, error) {
		var b strings.Builder
		for _, arg := range args {
			b.WriteString(stringify(arg))
		}
		return b.String(), nil
	})
	condition.RegisterFunction("store_exists", func(ctx condition.EvalContext, args ...any) (any, error) {
		result, err := evalStoreFunction(ctx, args...)
		if err != nil {
			return false, nil
		}
		return result.Found, nil
	})
	condition.RegisterFunction("store_value", func(ctx condition.EvalContext, args ...any) (any, error) {
		result, err := evalStoreFunction(ctx, args...)
		if err != nil {
			return nil, nil
		}
		if len(args) >= 2 {
			if value, ok := resultField(result, stringify(args[1])); ok {
				return value, nil
			}
		}
		return result.Value, nil
	})
	condition.RegisterFunction("store_field", func(ctx condition.EvalContext, args ...any) (any, error) {
		if len(args) < 2 {
			return nil, fmt.Errorf("store.field expects lookup and field")
		}
		result, err := evalStoreFunction(ctx, args[0])
		if err != nil {
			return nil, nil
		}
		value, _ := resultField(result, stringify(args[1]))
		return value, nil
	})
	condition.RegisterFunction("store_found", func(ctx condition.EvalContext, args ...any) (any, error) {
		if len(args) < 1 || ctx.Facts == nil {
			return false, nil
		}
		value, found := ctx.Facts.Get("store." + stringify(args[0]) + ".found")
		if !found {
			return false, nil
		}
		return value, nil
	})
	condition.RegisterFunction("store_error", func(ctx condition.EvalContext, args ...any) (any, error) {
		if len(args) < 1 || ctx.Facts == nil {
			return "", nil
		}
		value, found := ctx.Facts.Get("store." + stringify(args[0]) + ".error")
		if !found {
			return "", nil
		}
		return value, nil
	})
}

func evalStoreFunction(ctx condition.EvalContext, args ...any) (LookupResult, error) {
	if len(args) < 1 || ctx.Facts == nil {
		return LookupResult{}, fmt.Errorf("store lookup expects source or lookup id")
	}
	raw, found := ctx.Facts.Get(lookupContextFact)
	if !found {
		return LookupResult{}, fmt.Errorf("tcpguard lookup context not found")
	}
	lookup, ok := raw.(*LookupContext)
	if !ok || lookup == nil {
		return LookupResult{}, fmt.Errorf("tcpguard lookup context is invalid")
	}
	key := ""
	if len(args) >= 2 {
		key = stringify(args[1])
	}
	return lookup.Evaluate(contextFromEval(ctx), stringify(args[0]), key)
}

func contextFromEval(ctx condition.EvalContext) context.Context {
	return context.Background()
}
