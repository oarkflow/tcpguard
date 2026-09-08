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
