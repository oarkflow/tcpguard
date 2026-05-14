package tcpguard

import "testing"

func TestValidateOutboundURL(t *testing.T) {
	if err := validateOutboundURL("https://example.com/path", false); err != nil {
		t.Fatalf("expected public url allowed, got %v", err)
	}
	if err := validateOutboundURL("http://127.0.0.1:8080", false); err == nil {
		t.Fatal("expected private url to be blocked")
	}
	if err := validateOutboundURL("http://127.0.0.1:8080", true); err != nil {
		t.Fatalf("expected private url allowed when configured, got %v", err)
	}
}
