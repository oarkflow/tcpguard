package tcpguard

import (
	"github.com/gofiber/fiber/v3"
)

type UserGroupMiddleware struct {
	ruleEngine  *RuleEngine
	configStore ConfigStore
}

func NewUserGroupMiddleware(ruleEngine *RuleEngine, configStore ConfigStore) *UserGroupMiddleware {
	return &UserGroupMiddleware{
		ruleEngine:  ruleEngine,
		configStore: configStore,
	}
}

func (m *UserGroupMiddleware) Middleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		userID := c.Get("X-User-ID")
		if userID == "" {
			return c.Next()
		}

		user, err := m.configStore.GetUser(userID)
		if err != nil || user == nil {
			return c.Next()
		}

		// Store user context for rule engine to use
		c.Locals("tcpguard.user_id", userID)
		c.Locals("tcpguard.user", user)
		c.Locals("tcpguard.user_groups", user.Groups)

		return c.Next()
	}
}
