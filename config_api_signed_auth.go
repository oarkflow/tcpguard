package tcpguard

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v3"
)

const minConfigAPIAuthSecretLen = 32

// ConfigAPIAuthIdentity is the trusted identity projected into Fiber locals for
// DefaultConfigAPIAuthzResolver.
type ConfigAPIAuthIdentity struct {
	UserID   string
	Roles    []string
	Groups   []string
	TenantID string
}

// ConfigAPIRevocationChecker checks whether a signed auth token ID has been
// revoked before its natural expiry.
type ConfigAPIRevocationChecker func(tokenID string) (bool, error)

type configAPISignedAuthConfig struct {
	header     string
	issuer     string
	audience   string
	leeway     time.Duration
	now        func() time.Time
	revocation ConfigAPIRevocationChecker
}

// ConfigAPISignedAuthOption configures signed ConfigAPI authentication.
type ConfigAPISignedAuthOption func(*configAPISignedAuthConfig)

// WithConfigAPISignedAuthHeader changes the token header. The default is
// Authorization with a Bearer token.
func WithConfigAPISignedAuthHeader(header string) ConfigAPISignedAuthOption {
	return func(cfg *configAPISignedAuthConfig) {
		if header != "" {
			cfg.header = header
		}
	}
}

func WithConfigAPISignedAuthIssuer(issuer string) ConfigAPISignedAuthOption {
	return func(cfg *configAPISignedAuthConfig) {
		cfg.issuer = issuer
	}
}

func WithConfigAPISignedAuthAudience(audience string) ConfigAPISignedAuthOption {
	return func(cfg *configAPISignedAuthConfig) {
		cfg.audience = audience
	}
}

func WithConfigAPISignedAuthLeeway(leeway time.Duration) ConfigAPISignedAuthOption {
	return func(cfg *configAPISignedAuthConfig) {
		if leeway >= 0 {
			cfg.leeway = leeway
		}
	}
}

func WithConfigAPISignedAuthRevocation(checker ConfigAPIRevocationChecker) ConfigAPISignedAuthOption {
	return func(cfg *configAPISignedAuthConfig) {
		cfg.revocation = checker
	}
}

func defaultConfigAPISignedAuthConfig() configAPISignedAuthConfig {
	return configAPISignedAuthConfig{
		header:   "Authorization",
		issuer:   "tcpguard",
		audience: "tcpguard.config_api",
		leeway:   30 * time.Second,
		now:      time.Now,
	}
}

// NewConfigAPISignedAuthMiddleware validates short-lived HMAC-signed bearer
// tokens and writes trusted identity into Fiber locals for ConfigAPI authz.
func NewConfigAPISignedAuthMiddleware(secret []byte, opts ...ConfigAPISignedAuthOption) (fiber.Handler, error) {
	cfg := defaultConfigAPISignedAuthConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	if len(secret) < minConfigAPIAuthSecretLen {
		return nil, fmt.Errorf("config api auth secret must be at least %d bytes", minConfigAPIAuthSecretLen)
	}
	return func(c fiber.Ctx) error {
		token := c.Get(cfg.header)
		if cfg.header == "Authorization" && strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(token, "Bearer "))
		}
		claims, err := parseConfigAPISignedAuthToken(secret, token, cfg)
		if err != nil {
			return fiber.NewError(401, "config api authentication required")
		}
		if cfg.revocation != nil {
			revoked, err := cfg.revocation(claims.ID)
			if err != nil {
				return fiber.NewError(500, "config api authentication failed")
			}
			if revoked {
				return fiber.NewError(401, "config api token revoked")
			}
		}
		c.Locals("tcpguard.user_id", claims.Subject)
		c.Locals("tcpguard.user_roles", append([]string(nil), claims.Roles...))
		c.Locals("tcpguard.user_groups", append([]string(nil), claims.Groups...))
		c.Locals("tcpguard.tenant_id", claims.TenantID)
		c.Locals("tcpguard.auth_token_id", claims.ID)
		return c.Next()
	}, nil
}

// NewConfigAPISignedAuthToken creates a short-lived HMAC-signed bearer token
// for a trusted identity provider to hand to ConfigAPI clients.
func NewConfigAPISignedAuthToken(secret []byte, identity ConfigAPIAuthIdentity, ttl time.Duration, opts ...ConfigAPISignedAuthOption) (string, error) {
	cfg := defaultConfigAPISignedAuthConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	if len(secret) < minConfigAPIAuthSecretLen {
		return "", fmt.Errorf("config api auth secret must be at least %d bytes", minConfigAPIAuthSecretLen)
	}
	if identity.UserID == "" {
		return "", errors.New("config api auth identity user id is required")
	}
	if identity.TenantID == "" {
		identity.TenantID = "default"
	}
	if ttl <= 0 {
		return "", errors.New("config api auth token ttl must be positive")
	}
	now := cfg.now().UTC()
	claims := configAPISignedAuthClaims{
		ID:       strconv.FormatInt(now.UnixNano(), 36) + "." + identity.UserID,
		Subject:  identity.UserID,
		Roles:    append([]string(nil), identity.Roles...),
		Groups:   append([]string(nil), identity.Groups...),
		TenantID: identity.TenantID,
		Issuer:   cfg.issuer,
		Audience: cfg.audience,
		IssuedAt: now.Unix(),
		Expires:  now.Add(ttl).Unix(),
	}
	return signConfigAPIAuthClaims(secret, claims)
}

type configAPISignedAuthClaims struct {
	ID       string   `json:"jti"`
	Subject  string   `json:"sub"`
	Roles    []string `json:"roles,omitempty"`
	Groups   []string `json:"groups,omitempty"`
	TenantID string   `json:"tenant_id"`
	Issuer   string   `json:"iss"`
	Audience string   `json:"aud"`
	IssuedAt int64    `json:"iat"`
	Expires  int64    `json:"exp"`
}

func signConfigAPIAuthClaims(secret []byte, claims configAPISignedAuthClaims) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "HS256", "typ": "TCPGuard"})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	head := base64.RawURLEncoding.EncodeToString(header)
	body := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(head + "." + body))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return head + "." + body + "." + sig, nil
}

func parseConfigAPISignedAuthToken(secret []byte, token string, cfg configAPISignedAuthConfig) (*configAPISignedAuthClaims, error) {
	if token == "" {
		return nil, errors.New("missing token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(got, expected) != 1 {
		return nil, errors.New("invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims configAPISignedAuthClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	now := cfg.now().UTC()
	if claims.Subject == "" || claims.ID == "" {
		return nil, errors.New("invalid subject")
	}
	if claims.Issuer != cfg.issuer || claims.Audience != cfg.audience {
		return nil, errors.New("invalid issuer or audience")
	}
	if claims.Expires <= 0 || now.After(time.Unix(claims.Expires, 0).Add(cfg.leeway)) {
		return nil, errors.New("expired token")
	}
	if claims.IssuedAt > 0 && now.Add(cfg.leeway).Before(time.Unix(claims.IssuedAt, 0)) {
		return nil, errors.New("token issued in future")
	}
	if claims.TenantID == "" {
		claims.TenantID = "default"
	}
	return &claims, nil
}
