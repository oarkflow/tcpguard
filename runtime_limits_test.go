package tcpguard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestHTTPMiddlewareRejectsWhenConcurrencyLimitIsFull(t *testing.T) {
	guard, err := New(WithMaxConcurrentRequests(1))
	if err != nil {
		t.Fatal(err)
	}
	started := make(chan struct{})
	release := make(chan struct{})
	handler := guard.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		w.WriteHeader(http.StatusOK)
	}))
	firstDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
		firstDone <- recorder
	}()
	<-started
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, httptest.NewRequest(http.MethodGet, "/", nil))
	if second.Code != http.StatusServiceUnavailable {
		t.Fatalf("second status=%d, want %d", second.Code, http.StatusServiceUnavailable)
	}
	close(release)
	if first := <-firstDone; first.Code != http.StatusOK {
		t.Fatalf("first status=%d, want %d", first.Code, http.StatusOK)
	}
}

func TestHTTPMiddlewarePropagatesRequestTimeout(t *testing.T) {
	guard, err := New(WithRequestTimeout(10 * time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	handler := guard.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
		w.WriteHeader(http.StatusRequestTimeout)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil).WithContext(context.Background()))
	if recorder.Code != http.StatusRequestTimeout {
		t.Fatalf("status=%d, want %d", recorder.Code, http.StatusRequestTimeout)
	}
}
