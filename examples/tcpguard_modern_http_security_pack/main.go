package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/oarkflow/tcpguard"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:18183", "listen address")
	policyPath := flag.String("policy", "./examples/tcpguard_modern_http_security_pack/tcpguard.bcl", "BCL policy path")
	selfTest := flag.Bool("self-test", false, "run security scenarios and exit")
	flag.Parse()

	guard := loadGuard(*policyPath)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true,"path":"`+r.URL.Path+`"}`)
	})
	protected := guard.HTTPMiddleware(mux)

	if *selfTest {
		runSelfTest(protected)
		return
	}

	log.Printf("TCPGuard modern HTTP example listening on http://%s", *addr)
	log.Printf("run from the repository root with: go run ./examples/tcpguard_modern_http_security_pack -self-test")
	log.Fatal(http.ListenAndServe(*addr, protected))
}

func loadGuard(policyPath string) *tcpguard.Guard {
	bundle, err := tcpguard.LoadTCPGuardBundleFile(context.Background(), policyPath)
	if err != nil {
		log.Fatal(err)
	}
	store := tcpguard.NewMemoryStore()
	guard, err := tcpguard.New(
		tcpguard.WithBundle(bundle),
		tcpguard.WithStore(store),
		tcpguard.WithHMACSecretProvider(func(*tcpguard.Context) []byte {
			return []byte("development-only-change-me")
		}),
		tcpguard.WithContextBuilder(tcpguard.HTTPContextBuilder{
			TrustedProxyHeaders:   true,
			TrustedProxyCIDRs:     []string{"10.0.0.0/8"},
			AllowedHosts:          []string{"127.0.0.1:18183", "example.test", "127.0.0.1"},
			AllowedMethods:        []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			RequireHTTPS:          false,
			RequireCSRF:           true,
			RequireIdempotency:    true,
			SecureResponseHeaders: true,
			AllowedCORSOrigins:    []string{"https://app.example.test"},
			MaxHeaderBytes:        32 << 10,
			MaxHeaderCount:        100,
			MaxURLBytes:           8 << 10,
			MaxBodyBytes:          1024,
			ContentSecurityPolicy: "default-src 'none'; frame-ancestors 'none'",
			IdentityExtractor: func(r *http.Request, sec *tcpguard.Context) {
				sec.Identity.ID = r.Header.Get("X-User-ID")
				sec.Identity.Role = r.Header.Get("X-User-Role")
				sec.Identity.Tenant = r.Header.Get("X-Tenant-ID")
				sec.Tenant.ID = r.Header.Get("X-Tenant-ID")
				sec.Session.ID = r.Header.Get("X-Session-ID")
				sec.Session.DeviceID = r.Header.Get("X-Device-ID")
			},
			BusinessExtractor: func(r *http.Request, sec *tcpguard.Context) {
				if strings.Contains(r.URL.Path, "transfer") {
					sec.Business.Action = "transfer"
				}
			},
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	return guard
}

func runSelfTest(handler http.Handler) {
	server := httptest.NewServer(handler)
	defer server.Close()
	client := server.Client()

	tests := []struct {
		name string
		req  func() *http.Request
	}{
		{"allow normal request", func() *http.Request { return newRequest(http.MethodGet, server.URL+"/public", "") }},
		{"block untrusted forwarded identity", func() *http.Request {
			r := newRequest(http.MethodGet, server.URL+"/public", "")
			r.Header.Set("X-Forwarded-For", "10.0.0.10")
			return r
		}},
		{"throttle cross-origin cookie mutation", func() *http.Request {
			r := newRequest(http.MethodPost, server.URL+"/api/transfer", `{"amount":1}`)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", "https://evil.example")
			r.Header.Set("Cookie", "session=demo")
			return r
		}},
		{"block malformed JSON", func() *http.Request {
			r := newRequest(http.MethodPost, server.URL+"/api/transfer", `{"amount":`)
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", "json-1")
			return r
		}},
		{"block oversized body", func() *http.Request {
			r := newRequest(http.MethodPost, server.URL+"/api/transfer", strings.Repeat("x", 2048))
			r.Header.Set("Idempotency-Key", "large-1")
			return r
		}},
		{"allow first nonce", func() *http.Request {
			r := newRequest(http.MethodGet, server.URL+"/public", "")
			r.Header.Set("X-TCPGuard-Nonce", "demo-nonce")
			signDemoRequest(r)
			return r
		}},
		{"block reused nonce", func() *http.Request {
			r := newRequest(http.MethodGet, server.URL+"/public", "")
			r.Header.Set("X-TCPGuard-Nonce", "demo-nonce")
			signDemoRequest(r)
			return r
		}},
	}
	for _, test := range tests {
		response, err := client.Do(test.req())
		if err != nil {
			log.Printf("%-36s ERROR %v", test.name, err)
			continue
		}
		body, _ := io.ReadAll(response.Body)
		_ = response.Body.Close()
		fmt.Printf("%-36s %3d %s\n", test.name, response.StatusCode, strings.TrimSpace(string(body)))
	}
	fmt.Println("self-test complete")
}

func signDemoRequest(r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	mac := hmac.New(sha256.New, []byte("development-only-change-me"))
	_, _ = mac.Write([]byte(r.Method + "\n" + r.URL.RequestURI() + "\n"))
	_, _ = mac.Write(body)
	r.Header.Set("X-TCPGuard-Signature", hex.EncodeToString(mac.Sum(nil)))
}

func newRequest(method, url, body string) *http.Request {
	r, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		log.Fatal(err)
	}
	r.Host = "127.0.0.1"
	return r
}
