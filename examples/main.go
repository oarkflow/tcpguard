package main

import (
	"log"
	"os"

	"github.com/oarkflow/tcpguard/examples/runner"
)

func main() {
	configDir := "configs"
	if len(os.Args) > 1 {
		configDir = os.Args[1]
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	if err := runner.Run(runner.Options{ConfigDir: configDir, Port: port}); err != nil {
		log.Fatal(err)
	}
}
