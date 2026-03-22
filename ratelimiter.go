package tcpguard

import (
	"sync"
	"time"
)

// TokenBucketRateLimiter implements RateLimiter using token bucket algorithm
// with a maximum bucket count to prevent memory exhaustion from many unique keys.
type TokenBucketRateLimiter struct {
	mu         sync.RWMutex
	buckets    map[string]*TokenBucket
	lruOrder   []string // tracks insertion/access order for eviction
	capacity   int
	refillRate time.Duration
	maxBuckets int // maximum number of tracked keys
}

type TokenBucket struct {
	tokens     float64
	lastRefill time.Time
	mu         sync.Mutex
}

// NewTokenBucketRateLimiter creates a rate limiter with a default max of 100,000 buckets.
func NewTokenBucketRateLimiter(capacity int, refillRate time.Duration) *TokenBucketRateLimiter {
	return &TokenBucketRateLimiter{
		buckets:    make(map[string]*TokenBucket),
		lruOrder:   make([]string, 0, 1024),
		capacity:   capacity,
		refillRate: refillRate,
		maxBuckets: 100_000,
	}
}

// NewTokenBucketRateLimiterWithMax creates a rate limiter with a custom max bucket count.
func NewTokenBucketRateLimiterWithMax(capacity int, refillRate time.Duration, maxBuckets int) *TokenBucketRateLimiter {
	if maxBuckets <= 0 {
		maxBuckets = 100_000
	}
	return &TokenBucketRateLimiter{
		buckets:    make(map[string]*TokenBucket),
		lruOrder:   make([]string, 0, 1024),
		capacity:   capacity,
		refillRate: refillRate,
		maxBuckets: maxBuckets,
	}
}

func (rl *TokenBucketRateLimiter) Allow(key string) (allowed bool, remaining int, reset time.Time, err error) {
	rl.mu.Lock()
	bucket, exists := rl.buckets[key]
	if !exists {
		// Evict oldest buckets if at capacity
		for len(rl.buckets) >= rl.maxBuckets && len(rl.lruOrder) > 0 {
			evictKey := rl.lruOrder[0]
			rl.lruOrder = rl.lruOrder[1:]
			delete(rl.buckets, evictKey)
		}
		bucket = &TokenBucket{
			tokens:     float64(rl.capacity),
			lastRefill: time.Now(),
		}
		rl.buckets[key] = bucket
		rl.lruOrder = append(rl.lruOrder, key)
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
