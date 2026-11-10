package tcpguard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPContextBuilderEmitsBoundaryFacts(t *testing.T) {
	builder := HTTPContextBuilder{
		DisableGeoIP:      true,
		TrustedProxyCIDRs: []string{"10.0.0.0/8"},
		RequireHTTPS:      true,
		AllowedHosts:      []string{"api.example.test"},
		AllowedMethods:    []string{http.MethodGet},
		MaxHeaderBytes:    8,
		MaxHeaderCount:    1,
		MaxURLBytes:       4,
		MaxBodyBytes:      1,
	}
	r := httptest.NewRequest(http.MethodPost, "http://evil.example.test/long", nil)
	r.RemoteAddr = "198.51.100.10:1234"
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	sec, err := builder.BuildHTTP(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	d := HeaderAnomalyDetector{}
	findings, err := d.Detect(context.Background(), sec, Event{Type: "request.received"})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) < 5 {
		t.Fatalf("got %d hardening findings, want at least 5: %#v", len(findings), findings)
	}
}

func TestHTTPContextBuilderDoesNotTrustSpoofedForwardedHTTPS(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://api.example.test/", nil)
	request.RemoteAddr = "198.51.100.10:1234"
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-For", "203.0.113.5")
	builder := HTTPContextBuilder{
		DisableGeoIP:        true,
		TrustedProxyHeaders: true,
		TrustedProxyCIDRs:   []string{"10.0.0.0/8"},
		RequireHTTPS:        true,
	}
	sec, err := builder.BuildHTTP(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !factBool(sec, "security.https_required") {
		t.Fatal("spoofed X-Forwarded-Proto bypassed HTTPS enforcement")
	}
	if !factBool(sec, "security.forwarded_headers_untrusted") {
		t.Fatal("forwarded headers from an untrusted immediate peer were trusted")
	}
}

func TestHTTPContextBuilderAcceptsHTTPSFromConfiguredProxy(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://api.example.test/", nil)
	request.RemoteAddr = "10.2.3.4:1234"
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-Forwarded-For", "203.0.113.5")
	builder := HTTPContextBuilder{
		DisableGeoIP:        true,
		TrustedProxyHeaders: true,
		TrustedProxyCIDRs:   []string{"10.0.0.0/8"},
		RequireHTTPS:        true,
	}
	sec, err := builder.BuildHTTP(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if factBool(sec, "security.https_required") || factBool(sec, "security.forwarded_headers_untrusted") {
		t.Fatalf("trusted proxy facts incorrectly rejected: https=%v forwarded=%v", factBool(sec, "security.https_required"), factBool(sec, "security.forwarded_headers_untrusted"))
	}
}
