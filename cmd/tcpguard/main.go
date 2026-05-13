package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/oarkflow/condition/tcpguard"
	"github.com/oarkflow/condition/tcpguard/bcl"
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
	out := map[string]any{"valid": true, "rules": len(bundle.Rules), "actions": len(bundle.Actions)}
	if *request != "" {
		req, err := loadSimulationRequest(*request)
		if err != nil {
			return err
		}
		result, err := tcpguard.Simulate(context.Background(), bundle, req)
		if err != nil {
			return err
		}
		out["simulation"] = result
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

func loadBundle(dir, file string) (tcpguard.Bundle, error) {
	if file != "" {
		return bcl.LoadTCPGuardBundleFile(context.Background(), file)
	}
	return bcl.LoadTCPGuardBundleDir(context.Background(), dir)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: tcpguard <validate|simulate|explain|diff|test|reload> [flags]")
}
