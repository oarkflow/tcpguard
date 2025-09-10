package tcpguard

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestRateLimitRule(t *testing.T) {
	// Create a mock conn
	conn := &mockConn{}
	req, _ := http.NewRequest("GET", "/api/test", nil)
	req.RemoteAddr = "127.0.0.1:1234"

	guard := &Guard{
		requestTimes: make(map[string][]time.Time),
		bannedIPs:    make(map[string]time.Time),
	}

	rule := &RateLimitRule{
		name:      "test_rule",
		uri:       "/api/",
		methods:   []string{"GET"},
		threshold: 1,
		unit:      time.Minute,
		operator:  ">",
		actions:   []string{"test_action"},
	}

	// First request
	anomaly, actions, err := rule.Check(context.Background(), conn, req, guard)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if anomaly {
		t.Errorf("Expected no anomaly, got %v", anomaly)
	}
	if len(actions) != 0 {
		t.Errorf("Expected no actions, got %v", actions)
	}

	// Second request
	anomaly, actions, err = rule.Check(context.Background(), conn, req, guard)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if anomaly {
		t.Errorf("Expected no anomaly, got %v", anomaly)
	}
	if len(actions) != 0 {
		t.Errorf("Expected no actions, got %v", actions)
	}

	// Third request, should trigger
	anomaly, actions, err = rule.Check(context.Background(), conn, req, guard)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if !anomaly {
		t.Errorf("Expected anomaly, got %v", anomaly)
	}
	if len(actions) != 1 || actions[0] != "test_action" {
		t.Errorf("Expected actions ['test_action'], got %v", actions)
	}
}

type mockConn struct{}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return &mockAddr{} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

type mockAddr struct{}

func (m *mockAddr) Network() string { return "tcp" }
func (m *mockAddr) String() string  { return "127.0.0.1:1234" }
