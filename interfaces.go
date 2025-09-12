package tcpguard

import (
	"context"
	"time"

	"github.com/gofiber/fiber/v2"
)

// CounterStore interface for pluggable storage
type CounterStore interface {
	IncrementGlobal(ip string) (count int, lastReset time.Time, err error)
	GetGlobal(ip string) (*RequestCounter, error)
	ResetGlobal(ip string) error

	IncrementEndpoint(ip, endpoint string) (*RequestCounter, error)
	GetEndpoint(ip, endpoint string) (*RequestCounter, error)

	IncrementActionCounter(key string, window time.Duration) (count int, first time.Time, err error)
	GetActionCounter(key string) (*GenericCounter, error)
	DeleteActionCounter(key string) error

	GetBan(ip string) (*BanInfo, error)
	SetBan(ip string, ban *BanInfo) error
	DeleteBan(ip string) error

	GetSessions(userID string) ([]*SessionInfo, error)
	PutSessions(userID string, sessions []*SessionInfo) error
}

// RateLimiter interface for different algorithms
type RateLimiter interface {
	Allow(key string) (allowed bool, remaining int, reset time.Time, err error)
}

// ActionHandler interface for extensible actions
type ActionHandler interface {
	Handle(ctx context.Context, c *fiber.Ctx, action Action, meta ActionMeta, store CounterStore) error
}

// ActionMeta contains metadata for action execution
type ActionMeta struct {
	ClientIP string
	Endpoint string
	UserID   string
}

// ConfigValidator interface for config validation
type ConfigValidator interface {
	Validate(config *AnomalyConfig) error
}

// PipelineFunctionRegistry for registering utility functions
type PipelineFunctionRegistry interface {
	Register(name string, fn func(ctx *PipelineContext) any)
	Get(name string) (func(ctx *PipelineContext) any, bool)
}

// MetricsCollector interface for observability
type MetricsCollector interface {
	IncrementCounter(name string, labels map[string]string)
	ObserveHistogram(name string, value float64, labels map[string]string)
	SetGauge(name string, value float64, labels map[string]string)
}
