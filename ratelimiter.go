package tcpguard

import (
	"sync"
	"time"
)

// TokenBucketRateLimiter implements RateLimiter using token bucket algorithm
type TokenBucketRateLimiter struct {
	mu         sync.RWMutex
	buckets    map[string]*TokenBucket
	capacity   int
	refillRate time.Duration
}

type TokenBucket struct {
	tokens     float64
	lastRefill time.Time
	mu         sync.Mutex
}

func NewTokenBucketRateLimiter(capacity int, refillRate time.Duration) *TokenBucketRateLimiter {
	return &TokenBucketRateLimiter{
		buckets:    make(map[string]*TokenBucket),
		capacity:   capacity,
		refillRate: refillRate,
	}
}

func (rl *TokenBucketRateLimiter) Allow(key string) (allowed bool, remaining int, reset time.Time, err error) {
	rl.mu.Lock()
	bucket, exists := rl.buckets[key]
	if !exists {
		bucket = &TokenBucket{
			tokens:     float64(rl.capacity),
			lastRefill: time.Now(),
		}
		rl.buckets[key] = bucket
	}
	rl.mu.Unlock()

	bucket.mu.Lock()
	defer bucket.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	tokensToAdd := elapsed.Seconds() * float64(rl.capacity) / rl.refillRate.Seconds()
	bucket.tokens += tokensToAdd
	if bucket.tokens > float64(rl.capacity) {
		bucket.tokens = float64(rl.capacity)
	}
	bucket.lastRefill = now

	if bucket.tokens >= 1 {
		bucket.tokens--
		return true, int(bucket.tokens), now.Add(rl.refillRate), nil
	}
	return false, 0, now.Add(rl.refillRate), nil
}

// HealthCheck performs a health check on the rate limiter
func (rl *TokenBucketRateLimiter) HealthCheck() error {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	// Basic health check - ensure buckets map is accessible
	_ = len(rl.buckets)

	return nil
}
