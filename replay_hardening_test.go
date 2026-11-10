package tcpguard

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMemoryStoreSetNXIsAtomic(t *testing.T) {
	store := NewMemoryStore()
	first, err := store.SetNX(context.Background(), "nonce:test", []byte("1"), time.Minute)
	if err != nil || !first {
		t.Fatalf("first SetNX=(%v, %v), want true, nil", first, err)
	}
	second, err := store.SetNX(context.Background(), "nonce:test", []byte("1"), time.Minute)
	if err != nil || second {
		t.Fatalf("second SetNX=(%v, %v), want false, nil", second, err)
	}
}

func TestReplayDetectorVersion2SignatureBindsRequestMetadata(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte(`{"ok":true}`)
	r := httptest.NewRequest(http.MethodPost, "https://api.example.test/payments?x=1", bytes.NewReader(body))
	r.Host = "api.example.test"
	r.Header.Set("X-TCPGuard-Signature-Version", "2")
	r.Header.Set("X-TCPGuard-Timestamp", "1700000000")
	r.Header.Set("X-TCPGuard-Nonce", "n-1")
	bodyHash := sha256.Sum256(body)
	canonical := strings.Join([]string{"tcpguard-http-v2", r.Method, r.Host, r.URL.RequestURI(), "1700000000", "n-1", hex.EncodeToString(bodyHash[:])}, "\n")
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(canonical))
	r.Header.Set("X-TCPGuard-Signature", hex.EncodeToString(mac.Sum(nil)))
	sec := &Context{Raw: r, Request: RequestContext{Headers: map[string]string{}}, Security: map[string]any{}, Extra: map[string]any{}}
	d := NewReplayDetector(NewMemoryStore(), func(*Context) []byte { return secret })
	findings, err := d.Detect(context.Background(), sec, Event{Type: "request.received"})
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.ID == "invalid_signature" {
			t.Fatal("matching v2 signature was rejected")
		}
	}
}

func TestReplayDetectorWorksWithoutRawHTTPRequest(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	detector := NewReplayDetector(store, nil)
	first := &Context{Request: RequestContext{Headers: map[string]string{"X-TCPGuard-Nonce": "n-context-only"}}}
	if findings, err := detector.Detect(ctx, first, Event{Type: "request.received"}); err != nil || containsReplayFindingID(findings, "nonce_reused") {
		t.Fatalf("first context-only nonce findings=%v err=%v", replayFindingIDs(findings), err)
	}
	second := &Context{Request: RequestContext{Headers: map[string]string{"X-TCPGuard-Nonce": "n-context-only"}}}
	findings, err := detector.Detect(ctx, second, Event{Type: "request.received"})
	if err != nil || !containsReplayFindingID(findings, "nonce_reused") {
		t.Fatalf("reused context-only nonce findings=%v err=%v", replayFindingIDs(findings), err)
	}
	otherActor := &Context{Request: RequestContext{Headers: map[string]string{"X-TCPGuard-Nonce": "n-context-only"}}, Identity: IdentityContext{ID: "another-user"}}
	findings, err = detector.Detect(ctx, otherActor, Event{Type: "request.received"})
	if err != nil || containsReplayFindingID(findings, "nonce_reused") {
		t.Fatalf("nonce reuse in a different identity scope findings=%v err=%v", replayFindingIDs(findings), err)
	}
}

func TestReplayDetectorIdempotencyWithoutRawHTTPRequest(t *testing.T) {
	ctx := context.Background()
	detector := NewReplayDetector(NewMemoryStore(), nil)
	detector.RequireIdempotency = true
	makeContext := func(path, amount string) *Context {
		return &Context{Request: RequestContext{Method: http.MethodPost, Path: path, Query: map[string]string{"amount": amount}, Headers: map[string]string{"Idempotency-Key": "key-1"}}, Identity: IdentityContext{ID: "user-1"}}
	}
	first, err := detector.Detect(ctx, makeContext("/payments", "10"), Event{Type: "request.received"})
	if err != nil || containsReplayFindingID(first, "idempotency_reused") {
		t.Fatalf("first idempotency request findings=%v err=%v", replayFindingIDs(first), err)
	}
	second, err := detector.Detect(ctx, makeContext("/payments", "10"), Event{Type: "request.received"})
	if err != nil || !containsReplayFindingID(second, "idempotency_reused") {
		t.Fatalf("reused idempotency key findings=%v err=%v", replayFindingIDs(second), err)
	}
	conflict, err := detector.Detect(ctx, makeContext("/payments", "20"), Event{Type: "request.received"})
	if err != nil || !containsReplayFindingID(conflict, "idempotency_conflict") {
		t.Fatalf("conflicting idempotency key findings=%v err=%v", replayFindingIDs(conflict), err)
	}
}

func TestRequiredSignatureDetectorRunsWithoutSignatureHeaders(t *testing.T) {
	detector := NewReplayDetector(NewMemoryStore(), func(*Context) []byte { return []byte("secret") })
	detector.RequireSignature = true
	sec := &Context{Request: RequestContext{Method: http.MethodGet}}
	if !detectorShouldRun(detector, sec, Event{Type: "request.received"}) {
		t.Fatal("required signature detector did not run for an unsigned request")
	}
	findings, err := detector.Detect(context.Background(), sec, Event{Type: "request.received"})
	if err != nil || !containsReplayFindingID(findings, "missing_signature") {
		t.Fatalf("required signature findings=%v err=%v", replayFindingIDs(findings), err)
	}
}

func TestReplayDetectorFlagsMalformedTimestampAndUnverifiableSignature(t *testing.T) {
	secret := []byte("secret")
	detector := NewReplayDetector(NewMemoryStore(), func(*Context) []byte { return secret })
	detector.RequireSignature = true
	sec := &Context{Request: RequestContext{Headers: map[string]string{
		"X-TCPGuard-Timestamp": "not-a-timestamp",
		"X-TCPGuard-Signature": "deadbeef",
	}}}
	findings, err := detector.Detect(context.Background(), sec, Event{Type: "request.received"})
	if err != nil {
		t.Fatal(err)
	}
	if !containsReplayFindingID(findings, "invalid_timestamp") || !containsReplayFindingID(findings, "signature_unverifiable") {
		t.Fatalf("malformed/unverifiable request findings=%v", replayFindingIDs(findings))
	}
}

func containsReplayFindingID(findings []Finding, id string) bool {
	for _, finding := range findings {
		if finding.ID == id {
			return true
		}
	}
	return false
}

func replayFindingIDs(findings []Finding) []string {
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		ids = append(ids, finding.ID)
	}
	return ids
}
