package tcpguard

import (
	"errors"
	"fmt"
	"os"
)

// DeploymentMode controls production readiness severity.
type DeploymentMode string

const (
	DeploymentDevelopment DeploymentMode = "development"
	DeploymentStaging     DeploymentMode = "staging"
	DeploymentProduction  DeploymentMode = "production"
)

// ProductionReadinessConfig describes the deployment-critical pieces TCPGuard
// can validate before launch. TLS can be terminated by nginx/proxy and is not
// required here.
type ProductionReadinessConfig struct {
	Mode DeploymentMode

	ConfigAPI             *ConfigAPI
	ConfigAPIAuthSecret   []byte
	BehindTrustedProxy    bool
	TrustedProxyCIDRs     []string
	CounterStore          CounterStore
	StateStore            StateStore
	EventEmitter          EventEmitter
	RequireDurableState   bool
	RequireAuditEmitter   bool
	RequireConfigVersion  bool
	RequireSignedAuth     bool
	AllowInMemoryForTests bool
}

// ProductionReadinessReport is returned by CheckProductionReadiness.
type ProductionReadinessReport struct {
	Ready    bool     `json:"ready"`
	Errors   []string `json:"errors,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

func (r ProductionReadinessReport) Err() error {
	if len(r.Errors) == 0 {
		return nil
	}
	return errors.New(stringsJoin(r.Errors, "; "))
}

// CheckProductionReadiness validates deployment-sensitive wiring. In
// production mode, unsafe config is an error; in non-production it is reported
// as warnings so teams can see drift before launch.
func CheckProductionReadiness(cfg ProductionReadinessConfig) ProductionReadinessReport {
	mode := cfg.Mode
	if mode == "" {
		mode = DeploymentProduction
	}
	report := ProductionReadinessReport{Ready: true}
	fail := func(msg string) {
		if mode == DeploymentProduction {
			report.Errors = append(report.Errors, msg)
			report.Ready = false
		} else {
			report.Warnings = append(report.Warnings, msg)
		}
	}
	warn := func(msg string) {
		report.Warnings = append(report.Warnings, msg)
	}

	if cfg.ConfigAPI != nil {
		if cfg.ConfigAPI.unsafePublicAccess {
			fail("ConfigAPI unsafe public access is enabled")
		}
		if cfg.ConfigAPI.authzEngine == nil && cfg.ConfigAPI.authorizer == nil {
			fail("ConfigAPI has no authorization backend")
		}
		if cfg.RequireSignedAuth && len(cfg.ConfigAPIAuthSecret) < minConfigAPIAuthSecretLen {
			fail(fmt.Sprintf("ConfigAPI signed auth secret must be at least %d bytes", minConfigAPIAuthSecretLen))
		}
		if cfg.ConfigAPI.csrfRequired && cfg.ConfigAPI.csrfValidator == nil {
			warn("ConfigAPI browser-origin mutations fail closed until a CSRF validator/token is configured")
		}
		if cfg.ConfigAPI.mutationLimiter == nil {
			fail("ConfigAPI mutation rate limiter is disabled")
		}
		if cfg.RequireConfigVersion {
			if _, ok := cfg.ConfigAPI.store.(VersionedConfigStore); !ok {
				fail("ConfigAPI store does not implement VersionedConfigStore")
			}
		}
		if cfg.BehindTrustedProxy && len(cfg.ConfigAPI.trustedProxyNets) == 0 {
			fail("ConfigAPI is behind a proxy but has no trusted proxy CIDRs")
		}
	}

	if cfg.BehindTrustedProxy && len(cfg.TrustedProxyCIDRs) == 0 {
		fail("deployment is behind a proxy but trusted proxy CIDRs are not configured")
	}
	if cfg.RequireAuditEmitter && cfg.EventEmitter == nil {
		fail("audit event emitter is required")
	}
	if cfg.RequireDurableState {
		if cfg.CounterStore == nil {
			fail("durable CounterStore is required")
		} else if !cfg.AllowInMemoryForTests && isInMemoryCounterStore(cfg.CounterStore) {
			fail("in-memory CounterStore is not production durable")
		}
		if cfg.StateStore == nil {
			fail("durable StateStore is required")
		} else if !cfg.AllowInMemoryForTests && isInMemoryStateStore(cfg.StateStore) {
			fail("in-memory StateStore is not production durable")
		}
		if cfg.EventEmitter != nil && !cfg.AllowInMemoryForTests && isInMemoryEventEmitter(cfg.EventEmitter) {
			fail("in-memory EventEmitter is not production durable")
		}
	}
	return report
}

// MustBeProductionReady returns an error if CheckProductionReadiness reports
// blocking launch issues.
func MustBeProductionReady(cfg ProductionReadinessConfig) error {
	return CheckProductionReadiness(cfg).Err()
}

func isInMemoryCounterStore(store CounterStore) bool {
	switch store.(type) {
	case *InMemoryCounterStore:
		return true
	case *FileCounterStore:
		return false
	default:
		return false
	}
}

func isInMemoryStateStore(store StateStore) bool {
	_, ok := store.(*InMemoryStateStore)
	return ok
}

func isInMemoryEventEmitter(emitter EventEmitter) bool {
	_, ok := emitter.(*InMemoryEventEmitter)
	return ok
}

func stringsJoin(items []string, sep string) string {
	if len(items) == 0 {
		return ""
	}
	out := items[0]
	for _, item := range items[1:] {
		out += sep + item
	}
	return out
}

// EnvDeploymentMode reads APP_ENV/TCPGUARD_ENV and maps common values.
func EnvDeploymentMode() DeploymentMode {
	env := os.Getenv("TCPGUARD_ENV")
	if env == "" {
		env = os.Getenv("APP_ENV")
	}
	switch env {
	case "prod", "production":
		return DeploymentProduction
	case "stage", "staging":
		return DeploymentStaging
	default:
		return DeploymentDevelopment
	}
}
