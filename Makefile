.PHONY: build run test test-rules test-ddos test-mitm test-bus# Test session hijacking rule
test-session-hijacking:
	@echo "Testing session hijacking rule..."
	@cd examples && ../bin/tcpguard &
	@sleep 3
	@echo "Making first request..."
	@curl -s -H "X-User-ID: user1" -H "User-Agent: browser1" http://localhost:3000/api/status > /dev/null
	@echo "Making second request..."
	@curl -s -H "X-User-ID: user1" -H "User-Agent: browser2" http://localhost:3000/api/status > /dev/null
	@echo "Making third request..."
	@curl -s -H "X-User-ID: user1" -H "User-Agent: browser3" http://localhost:3000/api/status
	@pkill -f "tcpguard"
	@echo "Session hijacking test completed"s test-business-region test-protected-route test-session-hijacking test-endpoint-rate-limit clean

# Build the example application
build:
	go build -o bin/tcpguard ./examples

# Run the example server
run:
	go run ./examples/main.go

# Run unit tests (if any)
test:
	go test ./...

# Test all anomaly detection rules
test-rules: build test-ddos test-mitm test-business-hours test-business-region test-protected-route test-session-hijacking test-endpoint-rate-limit

# Test DDoS detection
test-ddos:
	@echo "Testing DDoS detection..."
	@cd examples && ./../bin/tcpguard &
	@sleep 2
	@for i in {1..120}; do curl -s -o /dev/null -w "%{http_code}\n" http://localhost:3000/api/status; done | tail -10
	@pkill -f "tcpguard"
	@echo "DDoS test completed"

# Test MITM detection (using suspicious user agent)
test-mitm:
	@echo "Testing MITM detection..."
	@cd examples && ./../bin/tcpguard &
	@sleep 2
	@curl -s -H "User-Agent: suspicious-scanner" http://localhost:3000/api/status
	@pkill -f "tcpguard"
	@echo "MITM test completed"

# Test business hours rule (assuming current time is outside 09:00-17:00 UTC)
test-business-hours:
	@echo "Testing business hours rule..."
	@cd examples && ./../bin/tcpguard &
	@sleep 2
	@curl -s -X POST -H "Content-Type: application/json" -d '{"username":"test","password":"test"}' http://localhost:3000/api/login
	@pkill -f "tcpguard"
	@echo "Business hours test completed"

# Test business region rule (assuming IP is not from US/CA)
test-business-region:
	@echo "Testing business region rule..."
	@cd examples && ./../bin/tcpguard &
	@sleep 2
	@curl -s -X POST -H "Content-Type: application/json" -d '{"username":"test","password":"test"}' http://localhost:3000/api/login
	@pkill -f "tcpguard"
	@echo "Business region test completed"

# Test protected route rule
test-protected-route:
	@echo "Testing protected route rule..."
	@cd /Users/sujit/Sites/tcpguard/examples && /Users/sujit/Sites/tcpguard/bin/tcpguard &
	@sleep 2
	@curl -s http://localhost:3000/api/protected
	@pkill -f "tcpguard"
	@echo "Protected route test completed"

# Test session hijacking rule
test-session-hijacking:
	@echo "Testing session hijacking rule..."
	@cd examples && ./../bin/tcpguard &
	@sleep 2
	@curl -s -H "X-User-ID: user1" -H "User-Agent: browser1" http://localhost:3000/api/status
	@curl -s -H "X-User-ID: user1" -H "User-Agent: browser2" http://localhost:3000/api/status
	@curl -s -H "X-User-ID: user1" -H "User-Agent: browser3" http://localhost:3000/api/status
	@pkill -f "tcpguard"
	@echo "Session hijacking test completed"

# Test endpoint rate limit
test-endpoint-rate-limit:
	@echo "Testing endpoint rate limit..."
	@cd examples && ./../bin/tcpguard &
	@sleep 2
	@for i in {1..10}; do curl -s -X POST -H "Content-Type: application/json" -d '{"username":"test","password":"test"}' http://localhost:3000/api/login; done
	@pkill -f "tcpguard"
	@echo "Endpoint rate limit test completed"

# Test protected route rule
test-protected-route:
	@echo "Testing protected route rule..."
	@./bin/tcpguard &
	@sleep 2
	@curl -s http://localhost:3000/api/protected
	@pkill -f "./bin/tcpguard"
	@echo "Protected route test completed"

# Test session hijacking rule
test-session-hijacking:
	@echo "Testing session hijacking rule..."
	@./bin/tcpguard &
	@sleep 2
	@curl -s -H "X-User-ID: user1" -H "User-Agent: browser1" http://localhost:3000/api/status
	@curl -s -H "X-User-ID: user1" -H "User-Agent: browser2" http://localhost:3000/api/status
	@curl -s -H "X-User-ID: user1" -H "User-Agent: browser3" http://localhost:3000/api/status
	@pkill -f "./bin/tcpguard"
	@echo "Session hijacking test completed"

# Test endpoint rate limit
test-endpoint-rate-limit:
	@echo "Testing endpoint rate limit..."
	@./bin/tcpguard &
	@sleep 2
	@for i in {1..10}; do curl -s -X POST -H "Content-Type: application/json" -d '{"username":"test","password":"test"}' http://localhost:3000/api/login; done
	@pkill -f "./bin/tcpguard"
	@echo "Endpoint rate limit test completed"

# Clean build artifacts
clean:
	rm -rf bin/
