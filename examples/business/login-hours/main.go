package main

import (
	"log"
	"os"
	"path/filepath"
	"runtime"

	"github.com/oarkflow/tcpguard/examples/runner"
)

func main() {
	configDir := scenarioConfigDir()
	port := envOrDefault("PORT", "3001")

	if err := runner.Run(runner.Options{ConfigDir: configDir, Port: port}); err != nil {
		log.Fatal(err)
	}
}

func scenarioConfigDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "configs")
}

func envOrDefault(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok && value != "" {
		return value
	}
	return fallback
}
