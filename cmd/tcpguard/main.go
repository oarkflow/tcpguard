package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"slices"

	"github.com/oarkflow/tcpguard"
	"github.com/oarkflow/tcpguard/bcl"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "validate":
		err = validate(os.Args[2:])
	case "lint":
		err = lintBundle(os.Args[2:])
	case "simulate":
		err = simulate(os.Args[2:])
	case "explain":
		err = explain(os.Args[2:])
	case "diff":
		err = diff(os.Args[2:])
	case "test":
		err = testBundle(os.Args[2:])
	case "reload":
		err = reload(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func lintBundle(args []string) error {
	fs := flag.NewFlagSet("lint", flag.ContinueOnError)
	dir := fs.String("dir", ".", "directory containing TCPGuard *.bcl files")
	file := fs.String("file", "", "single TCPGuard .bcl file")
	strict := fs.Bool("strict", false, "exit non-zero on warnings as well as errors")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bundle, err := loadBundle(*dir, *file)
	if err != nil {
		return err
	}
	report := tcpguard.LintBundle(bundle)
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		return err
	}
	if !report.Valid {
		return fmt.Errorf("tcpguard lint failed")
	}
	if *strict {
		for _, issue := range report.Issues {
			if issue.Severity == "warning" {
				return fmt.Errorf("tcpguard lint strict failed")
			}
		}
	}
	return nil
}

func validate(args []string) error {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	dir := fs.String("dir", ".", "directory containing TCPGuard *.bcl files")
	file := fs.String("file", "", "single TCPGuard .bcl file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bundle, err := loadBundle(*dir, *file)
	if err != nil {
		return err
	}
	if _, err := tcpguard.New(tcpguard.WithBundle(bundle)); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"valid":   true,
		"name":    bundle.Name,
		"version": bundle.Version,
		"rules":   len(bundle.Rules),
		"actions": len(bundle.Actions),
	})
}

func simulate(args []string) error {
	fs := flag.NewFlagSet("simulate", flag.ContinueOnError)
	dir := fs.String("dir", ".", "directory containing TCPGuard *.bcl files")
	file := fs.String("file", "", "single TCPGuard .bcl file")
	request := fs.String("request", "", "JSON file containing {event, context}")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *request == "" {
		return fmt.Errorf("simulate requires -request")
	}
	bundle, err := loadBundle(*dir, *file)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(*request)
	if err != nil {
		return err
	}
	var req tcpguard.SimulationRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return err
	}
	result, err := tcpguard.Simulate(context.Background(), bundle, req)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func explain(args []string) error {
	result, err := runSimulation(args)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(tcpguard.ExplainDecision(result.Decision))
}

func diff(args []string) error {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	beforeDir := fs.String("before-dir", "", "directory containing previous TCPGuard *.bcl files")
	beforeFile := fs.String("before-file", "", "previous TCPGuard .bcl file")
	afterDir := fs.String("after-dir", "", "directory containing candidate TCPGuard *.bcl files")
	afterFile := fs.String("after-file", "", "candidate TCPGuard .bcl file")
	request := fs.String("request", "", "JSON file containing {event, context}")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *request == "" {
		return fmt.Errorf("diff requires -request")
	}
	before, err := loadBundle(*beforeDir, *beforeFile)
	if err != nil {
		return err
	}
	after, err := loadBundle(*afterDir, *afterFile)
	if err != nil {
		return err
	}
	req, err := loadSimulationRequest(*request)
	if err != nil {
		return err
	}
	result, err := tcpguard.DiffSimulations(context.Background(), before, after, req)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func testBundle(args []string) error {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	dir := fs.String("dir", ".", "directory containing TCPGuard *.bcl files")
	file := fs.String("file", "", "single TCPGuard .bcl file")
	request := fs.String("request", "", "optional JSON file containing {event, context}")
	assertFile := fs.String("assert", "", "optional JSON assertion file for the simulation decision")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bundle, err := loadBundle(*dir, *file)
	if err != nil {
		return err
	}
	guard, err := tcpguard.New(tcpguard.WithBundle(bundle))
	if err != nil {
		return err
	}
	out := map[string]any{"valid": true, "rules": len(bundle.Rules), "actions": len(bundle.Actions)}
	if *request != "" {
		req, err := loadSimulationRequest(*request)
		if err != nil {
			return err
		}
		result := tcpguard.SimulationResult{Decision: guard.Evaluate(context.Background(), req.Event, req.Context)}
		if *assertFile != "" {
			assertion, err := loadDecisionAssertion(*assertFile)
			if err != nil {
				return err
			}
			if err := assertion.Check(result.Decision); err != nil {
				return err
			}
			out["assertions"] = "passed"
		}
		out["simulation"] = result
	}
	if *assertFile != "" && *request == "" {
		return fmt.Errorf("test -assert requires -request")
	}
	return json.NewEncoder(os.Stdout).Encode(out)
}

func reload(args []string) error {
	fs := flag.NewFlagSet("reload", flag.ContinueOnError)
	dir := fs.String("dir", ".", "directory containing TCPGuard *.bcl files")
	file := fs.String("file", "", "single TCPGuard .bcl file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	bundle, err := loadBundle(*dir, *file)
	if err != nil {
		return err
	}
	if _, err := tcpguard.New(tcpguard.WithBundle(bundle)); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"reloadable": true, "rules": len(bundle.Rules)})
}

func runSimulation(args []string) (tcpguard.SimulationResult, error) {
	fs := flag.NewFlagSet("simulate", flag.ContinueOnError)
	dir := fs.String("dir", ".", "directory containing TCPGuard *.bcl files")
	file := fs.String("file", "", "single TCPGuard .bcl file")
	request := fs.String("request", "", "JSON file containing {event, context}")
	if err := fs.Parse(args); err != nil {
		return tcpguard.SimulationResult{}, err
	}
	if *request == "" {
		return tcpguard.SimulationResult{}, fmt.Errorf("simulate requires -request")
	}
	bundle, err := loadBundle(*dir, *file)
	if err != nil {
		return tcpguard.SimulationResult{}, err
	}
	req, err := loadSimulationRequest(*request)
	if err != nil {
		return tcpguard.SimulationResult{}, err
	}
	return tcpguard.Simulate(context.Background(), bundle, req)
}

func loadSimulationRequest(path string) (tcpguard.SimulationRequest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tcpguard.SimulationRequest{}, err
	}
	var req tcpguard.SimulationRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return tcpguard.SimulationRequest{}, err
	}
	return req, nil
}

type decisionAssertion struct {
	Effect       string   `json:"effect,omitempty"`
	Allowed      *bool    `json:"allowed,omitempty"`
	Severity     string   `json:"severity,omitempty"`
	MinRisk      *float64 `json:"min_risk,omitempty"`
	MaxRisk      *float64 `json:"max_risk,omitempty"`
	MatchedRules []string `json:"matched_rules,omitempty"`
	Findings     []string `json:"findings,omitempty"`
	Actions      []string `json:"actions,omitempty"`
}

func loadDecisionAssertion(path string) (decisionAssertion, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return decisionAssertion{}, err
	}
	var assertion decisionAssertion
	if err := json.Unmarshal(data, &assertion); err != nil {
		return decisionAssertion{}, err
	}
	return assertion, nil
}

func (a decisionAssertion) Check(decision tcpguard.Decision) error {
	if a.Effect != "" && string(decision.Effect) != a.Effect {
		return fmt.Errorf("assert effect: got %s want %s", decision.Effect, a.Effect)
	}
	if a.Allowed != nil && decision.Allowed != *a.Allowed {
		return fmt.Errorf("assert allowed: got %t want %t", decision.Allowed, *a.Allowed)
	}
	if a.Severity != "" && string(decision.Severity) != a.Severity {
		return fmt.Errorf("assert severity: got %s want %s", decision.Severity, a.Severity)
	}
	if a.MinRisk != nil && decision.Risk.Score < *a.MinRisk {
		return fmt.Errorf("assert min_risk: got %.2f want >= %.2f", decision.Risk.Score, *a.MinRisk)
	}
	if a.MaxRisk != nil && decision.Risk.Score > *a.MaxRisk {
		return fmt.Errorf("assert max_risk: got %.2f want <= %.2f", decision.Risk.Score, *a.MaxRisk)
	}
	for _, rule := range a.MatchedRules {
		if !slices.Contains(decision.MatchedRules, rule) {
			return fmt.Errorf("assert matched_rules: missing %s", rule)
		}
	}
	findingIDs := make([]string, 0, len(decision.Findings))
	for _, finding := range decision.Findings {
		findingIDs = append(findingIDs, finding.ID)
	}
	for _, finding := range a.Findings {
		if !slices.Contains(findingIDs, finding) {
			return fmt.Errorf("assert findings: missing %s", finding)
		}
	}
	actionIDs := make([]string, 0, len(decision.Actions))
	for _, action := range decision.Actions {
		actionIDs = append(actionIDs, action.ID)
		if action.Type != "" {
			actionIDs = append(actionIDs, action.Type)
		}
	}
	for _, action := range a.Actions {
		if !slices.Contains(actionIDs, action) {
			return fmt.Errorf("assert actions: missing %s", action)
		}
	}
	return nil
}

func loadBundle(dir, file string) (tcpguard.Bundle, error) {
	if file != "" {
		return bcl.LoadTCPGuardBundleFile(context.Background(), file)
	}
	return bcl.LoadTCPGuardBundleDir(context.Background(), dir)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tcpguard <validate|lint|simulate|explain|diff|test|reload> [flags]")
}
