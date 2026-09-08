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
