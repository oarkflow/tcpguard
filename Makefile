.PHONY: build run test test-unit test-rules test-global test-ddos test-mitm test-business-hours test-business-region test-protected-route test-session-hijacking test-endpoint-rate-limit clean help

# Build the example application
build:
	go build -o bin/tcpguard ./examples

# Run the example server
run:
	go run ./examples/main.go

# Run unit tests and integration tests
test: test-unit test-rules

# Run unit tests (if any)
test-unit:
	go test ./...

# Test global rules only
test-global: build test-ddos test-mitm

# Test all anomaly detection rules
test-rules: build
	@echo "=== Running Comprehensive Anomaly Detection Tests ==="
	@echo "Testing global rules (DDoS, MITM) and endpoint rules..."
	@$(MAKE) test-ddos
	@echo ""
	@$(MAKE) test-mitm
	@echo ""
	@$(MAKE) test-business-hours
	@echo ""
	@$(MAKE) test-business-region
	@echo ""
	@$(MAKE) test-protected-route
	@echo ""
	@$(MAKE) test-session-hijacking
	@echo ""
	@$(MAKE) test-endpoint-rate-limit
	@echo "=== All tests completed ==="

# Test DDoS detection with multiple actions
test-ddos:
	@echo "Testing DDoS detection with rate_limit and temporary_ban..."
	@cd examples && ./../bin/tcpguard &
	@sleep 2
	@echo "Sending 60 requests to trigger DDoS detection..."
	@for i in {1..60}; do \
		response=$$(curl -s -w "HTTPSTATUS:%{http_code}" http://localhost:3000/api/status 2>/dev/null); \
		body=$$(echo "$$response" | sed 's/HTTPSTATUS:[0-9]*$$//'); \
		status=$$(echo "$$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2); \
		if [ "$$status" = "200" ]; then \
			echo "Request $$i: Allowed ($$status)"; \
		elif [ -n "$$body" ] && [ "$$body" != "HTTPSTATUS:" ]; then \
			echo "Request $$i: $$body"; \
		else \
			echo "Request $$i: Status $$status (no body)"; \
		fi; \
	done
	@pkill -f "tcpguard"
	@echo "DDoS test completed"

# Test MITM detection (using suspicious user agents from config)
test-mitm:
	@echo "Testing MITM detection..."
	@cd examples && ./../bin/tcpguard &
	@sleep 2
	@echo "Testing with suspicious user agent 'scanner'..."
	@curl -s -H "User-Agent: scanner" http://localhost:3000/api/status && echo ""
	@echo "Testing with suspicious user agent 'bot'..."
	@curl -s -H "User-Agent: bot" http://localhost:3000/api/status && echo ""
	@echo "Testing with normal user agent..."
	@curl -s -H "User-Agent: Mozilla/5.0" http://localhost:3000/api/status && echo ""
	@pkill -f "tcpguard"
	@echo "MITM test completed"

# Test business hours rule (assuming current time is outside 09:00-17:00 UTC)
test-business-hours:
	@echo "Testing business hours rule..."
	@cd examples && ./../bin/tcpguard &
	@sleep 2
	@curl -s -X POST -H "Content-Type: application/json" -d '{"username":"test","password":"test"}' http://localhost:3000/api/login && echo ""
	@pkill -f "tcpguard"
	@echo "Business hours test completed"

# Test business region rule (assuming IP is not from US/CA)
test-business-region:
	@echo "Testing business region rule..."
	@cd examples && ./../bin/tcpguard &
	@sleep 2
	@curl -s -X POST -H "Content-Type: application/json" -d '{"username":"test","password":"test"}' http://localhost:3000/api/login && echo ""
	@pkill -f "tcpguard"
	@echo "Business region test completed"

# Test protected route rule
test-protected-route:
	@echo "Testing protected route rule..."
	@cd examples && ./../bin/tcpguard &
	@sleep 2
	@curl -s http://localhost:3000/api/protected && echo ""
	@pkill -f "tcpguard"
	@echo "Protected route test completed"

# Test session hijacking rule
test-session-hijacking:
	@echo "Testing session hijacking rule..."
	@cd examples && ./../bin/tcpguard &
	@sleep 2
	@curl -s -H "X-User-ID: user1" -H "User-Agent: browser1" http://localhost:3000/api/status && echo ""
	@curl -s -H "X-User-ID: user1" -H "User-Agent: browser2" http://localhost:3000/api/status && echo ""
	@curl -s -H "X-User-ID: user1" -H "User-Agent: browser3" http://localhost:3000/api/status && echo ""
	@pkill -f "tcpguard"
	@echo "Session hijacking test completed"

# Test endpoint rate limit with multiple actions
test-endpoint-rate-limit:
	@echo "Testing endpoint rate limit..."
	@cd examples && ./../bin/tcpguard &
	@sleep 2
	@echo "Sending 15 GET requests to /api/status..."
	@for i in {1..15}; do \
		response=$$(curl -s -w "HTTPSTATUS:%{http_code}" http://localhost:3000/api/status 2>/dev/null); \
		body=$$(echo "$$response" | sed 's/HTTPSTATUS:[0-9]*$$//'); \
		status=$$(echo "$$response" | grep -o "HTTPSTATUS:[0-9]*" | cut -d: -f2); \
		if [ "$$status" = "200" ]; then \
			echo "Request $$i: Allowed ($$status)"; \
		elif [ -n "$$body" ] && [ "$$body" != "HTTPSTATUS:" ]; then \
			echo "Request $$i: $$body"; \
		else \
			echo "Request $$i: Status $$status (no body)"; \
		fi; \
	done
	@pkill -f "tcpguard"
	@echo "Endpoint rate limit test completed"

# Clean build artifacts and stop running processes
clean:
	rm -rf bin/
	@pkill -f "tcpguard" 2>/dev/null || true

# Show available targets
help:
	@echo "Available targets:"
	@echo "  build                    - Build the example application"
	@echo "  run                      - Run the example server"
	@echo "  test                     - Run unit tests and integration tests"
	@echo "  test-unit                - Run unit tests only"
	@echo "  test-rules               - Run all anomaly detection tests"
	@echo "  test-global              - Test global rules (DDoS, MITM)"
	@echo "  test-ddos                - Test DDoS detection with multiple actions"
	@echo "  test-mitm                - Test MITM detection"
	@echo "  test-business-hours      - Test business hours rule"
	@echo "  test-business-region     - Test business region rule"
	@echo "  test-protected-route     - Test protected route rule"
	@echo "  test-session-hijacking   - Test session hijacking rule"
	@echo "  test-endpoint-rate-limit - Test endpoint rate limit"
	@echo "  clean                    - Clean build artifacts and stop processes"
	@echo "  help                     - Show this help message"
