package tcpguard

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestBuildHTTPConcurrentGeoIPInitDoesNotPanic(t *testing.T) {
	geoIPInitOnce = sync.Once{}
	geoIPInitErr = nil

	builder := HTTPContextBuilder{TrustedProxyHeaders: true}
	req := httptest.NewRequest("GET", "http://example.test/public", nil)
	req.RemoteAddr = "203.0.113.42:443"

	const workers = 16
	var wg sync.WaitGroup
	errCh := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sec, err := builder.BuildHTTP(context.Background(), req.Clone(context.Background()))
			if err != nil {
				errCh <- err
				return
			}
			if sec == nil {
				errCh <- context.Canceled
			}
		}()
	}

	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("BuildHTTP failed under concurrent geoip init: %v", err)
		}
	}
}
