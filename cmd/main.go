package main

import (
	"fmt"
	"log"
	"net/http"

	tcpguard "github.com/example/tcpguard"
)

func main() {
	guard, err := tcpguard.NewGuard("config.json")
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/", guard)
	fmt.Println("Server starting on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
