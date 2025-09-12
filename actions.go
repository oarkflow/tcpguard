package tcpguard

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/gofiber/fiber/v2"
)

// Built-in action handlers

type RateLimitHandler struct{}

func (h *RateLimitHandler) Handle(ctx context.Context, c *fiber.Ctx, action Action, meta ActionMeta, store CounterStore) error {
	c.Set("X-RateLimit-Remaining", "0")
	if action.Duration != "" {
		if d, err := time.ParseDuration(action.Duration); err == nil {
			c.Set("Retry-After", fmt.Sprintf("%.0f", d.Seconds()))
		}
	}
	return c.Status(action.Response.Status).JSON(fiber.Map{
		"error": action.Response.Message,
		"type":  "rate_limit",
	})
}

type TemporaryBanHandler struct{}

func (h *TemporaryBanHandler) Handle(ctx context.Context, c *fiber.Ctx, action Action, meta ActionMeta, store CounterStore) error {
	duration, err := time.ParseDuration(action.Duration)
	if err != nil {
		duration = 10 * time.Minute
	}
	ban := &BanInfo{
		Until:      time.Now().Add(duration),
		Permanent:  false,
		Reason:     action.Response.Message,
		StatusCode: action.Response.Status,
	}
	err = store.SetBan(meta.ClientIP, ban)
	if err != nil {
		return err
	}
	return c.Status(action.Response.Status).JSON(fiber.Map{
		"error":        action.Response.Message,
		"type":         "temporary_ban",
		"duration":     duration.String(),
		"banned_until": time.Now().Add(duration).Format(time.RFC3339),
	})
}

type PermanentBanHandler struct{}

func (h *PermanentBanHandler) Handle(ctx context.Context, c *fiber.Ctx, action Action, meta ActionMeta, store CounterStore) error {
	ban := &BanInfo{
		Until:      time.Time{},
		Permanent:  true,
		Reason:     action.Response.Message,
		StatusCode: action.Response.Status,
	}
	err := store.SetBan(meta.ClientIP, ban)
	if err != nil {
		return err
	}
	return c.Status(action.Response.Status).JSON(fiber.Map{
		"error": action.Response.Message,
		"type":  "permanent_ban",
	})
}

type JitterWarningHandler struct{}

func (h *JitterWarningHandler) Handle(ctx context.Context, c *fiber.Ctx, action Action, meta ActionMeta, store CounterStore) error {
	// Instead of blocking sleep, return retry-after
	jitter := 1000 // ms
	if len(action.JitterRangeMs) == 2 {
		minVal := action.JitterRangeMs[0]
		maxVal := action.JitterRangeMs[1]
		jitter = rand.Intn(maxVal-minVal) + minVal
	}
	c.Set("Retry-After", fmt.Sprintf("%.3f", float64(jitter)/1000))
	return c.Status(action.Response.Status).JSON(fiber.Map{
		"error": action.Response.Message,
		"type":  "jitter_warning",
	})
}

// ActionHandlerRegistry to manage handlers
type ActionHandlerRegistry struct {
	handlers map[string]ActionHandler
}

func NewActionHandlerRegistry() *ActionHandlerRegistry {
	registry := &ActionHandlerRegistry{
		handlers: make(map[string]ActionHandler),
	}
	// Register built-ins
	registry.Register("rate_limit", &RateLimitHandler{})
	registry.Register("temporary_ban", &TemporaryBanHandler{})
	registry.Register("permanent_ban", &PermanentBanHandler{})
	registry.Register("jitter_warning", &JitterWarningHandler{})
	return registry
}

func (r *ActionHandlerRegistry) Register(actionType string, handler ActionHandler) {
	r.handlers[actionType] = handler
}

func (r *ActionHandlerRegistry) Get(actionType string) (ActionHandler, bool) {
	handler, exists := r.handlers[actionType]
	return handler, exists
}
