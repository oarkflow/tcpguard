package tcpguard

import "testing"

func TestActionStatusAllowed(t *testing.T) {
	if !actionStatusAllowed(204, nil) {
		t.Fatal("expected 204 to be allowed by default")
	}
	if actionStatusAllowed(502, []string{"2xx"}) {
		t.Fatal("expected 502 to be denied for 2xx-only policy")
	}
	if !actionStatusAllowed(502, []string{"500-599"}) {
		t.Fatal("expected 502 allowed for range policy")
	}
}

func TestShouldRetryStatus(t *testing.T) {
	if !shouldRetryStatus(502, nil) {
		t.Fatal("expected default retry on 5xx")
	}
	if !shouldRetryStatus(429, nil) {
		t.Fatal("expected default retry on 429")
	}
	if shouldRetryStatus(404, []string{"5xx"}) {
		t.Fatal("expected no retry for 404 with 5xx-only policy")
	}
}
