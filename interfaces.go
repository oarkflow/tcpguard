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

	HealthCheck() error
}

// RateLimiter interface for different algorithms
type RateLimiter interface {
	Allow(key string) (allowed bool, remaining int, reset time.Time, err error)
	HealthCheck() error
}

// ActionHandler interface for extensible actions
type ActionHandler interface {
	Handle(ctx context.Context, c *fiber.Ctx, action Action, meta ActionMeta, store CounterStore, notificationReg *NotificationRegistry, ruleName string) error
}

// ActionMeta contains metadata for action execution
type ActionMeta struct {
	ClientIP string
	Endpoint string
	UserID   string
}

// Data structures used by the CounterStore interface
type RequestCounter struct {
	Count     int
	LastReset time.Time
	Burst     int
}

type BanInfo struct {
	Until      time.Time
	Permanent  bool
	Reason     string
	StatusCode int
}

type GenericCounter struct {
	Count int
	First time.Time
}

type SessionInfo struct {
	UA       string
	Created  time.Time
	IP       string
	LastSeen time.Time
}

// ConfigValidator interface for config validation
type ConfigValidator interface {
	Validate(config *AnomalyConfig) error
}

// PipelineFunctionRegistry for registering utility functions
type PipelineFunctionRegistry interface {
	Register(name string, fn func(ctx *Context) any)
	Get(name string) (func(ctx *Context) any, bool)
}

// MetricsCollector interface for observability
type MetricsCollector interface {
	IncrementCounter(name string, labels map[string]string)
	ObserveHistogram(name string, value float64, labels map[string]string)
	SetGauge(name string, value float64, labels map[string]string)
	HealthCheck() error
	ExportPrometheus() string // New method for Prometheus export
}
