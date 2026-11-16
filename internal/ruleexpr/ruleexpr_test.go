package ruleexpr

import (
	"context"
	"testing"
)

func TestExpressionCallsRegisteredFunction(t *testing.T) {
	RegisterFunction("quality_test_true", func(EvalContext, ...any) (any, error) {
		return true, nil
	})
	expression, err := Compile("quality_test_true()")
	if err != nil {
		t.Fatal(err)
	}
	result, err := expression.Eval(context.Background(), MapFacts{})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched {
		t.Fatal("registered function should evaluate to a match")
	}
}

func TestExpressionDoesNotRunWhenContextIsCanceled(t *testing.T) {
	expression, err := Compile("true")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := expression.Eval(ctx, MapFacts{}); err == nil {
		t.Fatal("expected canceled context error")
	}
}

func TestNumericComparisonDefaultDoesNotMutateFacts(t *testing.T) {
	expression, err := Compile("request.body_size > 0")
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"method": "GET"}
	facts := MapFacts{"request": request}
	result, err := expression.Eval(context.Background(), facts)
	if err != nil {
		t.Fatal(err)
	}
	if result.Matched {
		t.Fatal("missing numeric fact should default to zero")
	}
	if _, found := request["body_size"]; found {
		t.Fatal("evaluation mutated the caller's nested facts")
	}
}

func TestFactsForEvalReusesNormalizedFactsWhenSafe(t *testing.T) {
	facts := MapFacts{"request": map[string]any{"method": "GET"}}
	vars := factsForEval(facts, nil)
	vars["__test_probe"] = true
	if facts["__test_probe"] != true {
		t.Fatal("normalized facts should be reused on the no-copy fast path")
	}
	delete(facts, "__test_probe")
}

func TestFactsForEvalCopiesWhenNumericDefaultsAreNeeded(t *testing.T) {
	request := map[string]any{"method": "GET"}
	facts := MapFacts{"request": request}
	vars := factsForEval(facts, []string{"request.body_size"})
	if _, found := vars["request"].(map[string]any)["body_size"]; !found {
		t.Fatal("missing numeric fact should be injected into the evaluation copy")
	}
	if _, found := request["body_size"]; found {
		t.Fatal("numeric default modified caller facts")
	}
}

func TestEvalPreparedMatchesAndKeepsCallerFactsDetached(t *testing.T) {
	expression, err := Compile(`request.params.id == "user-1"`)
	if err != nil {
		t.Fatal(err)
	}
	facts := MapFacts{"request": map[string]any{"params": map[string]string{"id": "user-1"}}}
	prepared := PrepareFacts(facts)
	result, err := expression.EvalPrepared(context.Background(), prepared)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched {
		t.Fatal("prepared evaluation did not match")
	}
	if _, ok := facts["request"].(map[string]any)["params"].(map[string]string); !ok {
		t.Fatal("preparing facts modified caller-owned nested maps")
	}
}

func TestExpressionNormalizesNestedStringMaps(t *testing.T) {
	expression, err := Compile(`metadata.environment == "prod"`)
	if err != nil {
		t.Fatal(err)
	}
	result, err := expression.Eval(context.Background(), MapFacts{
		"metadata": map[string]string{"environment": "prod"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Matched {
		t.Fatal("nested map[string]string should be available as expression facts")
	}
}
