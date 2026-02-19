package tcpguard

import (
	"github.com/gofiber/fiber/v3"
)

type ConfigAPI struct {
	store ConfigStore
}

func NewConfigAPI(store ConfigStore) *ConfigAPI {
	return &ConfigAPI{store: store}
}

func (api *ConfigAPI) RegisterRoutes(app *fiber.App) {
	// Rules
	app.Get("/api/rules", api.ListRules)
	app.Get("/api/rules/:name", api.GetRule)
	app.Post("/api/rules", api.CreateRule)
	app.Put("/api/rules/:name", api.UpdateRule)
	app.Delete("/api/rules/:name", api.DeleteRule)

	// Endpoints
	app.Get("/api/endpoints", api.ListEndpoints)
	app.Get("/api/endpoints/:endpoint", api.GetEndpoint)
	app.Post("/api/endpoints", api.CreateEndpoint)
	app.Put("/api/endpoints/:endpoint", api.UpdateEndpoint)
	app.Delete("/api/endpoints/:endpoint", api.DeleteEndpoint)

	// Global config
	app.Get("/api/config/global", api.GetGlobalConfig)
	app.Put("/api/config/global", api.UpdateGlobalConfig)

	// Users
	app.Get("/api/users", api.ListUsers)
	app.Get("/api/users/:id", api.GetUser)
	app.Post("/api/users", api.CreateUser)
	app.Put("/api/users/:id", api.UpdateUser)
	app.Delete("/api/users/:id", api.DeleteUser)

	// Groups
	app.Get("/api/groups", api.ListGroups)
	app.Get("/api/groups/:id", api.GetGroup)
	app.Post("/api/groups", api.CreateGroup)
	app.Put("/api/groups/:id", api.UpdateGroup)
	app.Delete("/api/groups/:id", api.DeleteGroup)

	// User-Group associations
	app.Post("/api/users/:userId/groups/:groupId", api.AddUserToGroup)
	app.Delete("/api/users/:userId/groups/:groupId", api.RemoveUserFromGroup)
	app.Get("/api/users/:userId/groups", api.GetUserGroups)
	app.Get("/api/groups/:groupId/users", api.GetGroupUsers)
}

func (api *ConfigAPI) ListRules(c fiber.Ctx) error {
	rules, err := api.store.ListRules()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(rules)
}

func (api *ConfigAPI) GetRule(c fiber.Ctx) error {
	name := c.Params("name")
	rule, err := api.store.GetRule(name)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	if rule == nil {
		return c.Status(404).JSON(fiber.Map{"error": "rule not found"})
	}
	return c.JSON(rule)
}

func (api *ConfigAPI) CreateRule(c fiber.Ctx) error {
	var rule Rule
	if err := c.Bind().Body(&rule); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	if err := api.store.CreateRule(&rule); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(201).JSON(rule)
}

func (api *ConfigAPI) UpdateRule(c fiber.Ctx) error {
	name := c.Params("name")
	var rule Rule
	if err := c.Bind().Body(&rule); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	rule.Name = name
	if err := api.store.UpdateRule(&rule); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(rule)
}

func (api *ConfigAPI) DeleteRule(c fiber.Ctx) error {
	name := c.Params("name")
	if err := api.store.DeleteRule(name); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(204).Send(nil)
}

func (api *ConfigAPI) ListEndpoints(c fiber.Ctx) error {
	endpoints, err := api.store.ListEndpoints()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(endpoints)
}

func (api *ConfigAPI) GetEndpoint(c fiber.Ctx) error {
	endpoint := c.Params("endpoint")
	ep, err := api.store.GetEndpoint(endpoint)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	if ep == nil {
		return c.Status(404).JSON(fiber.Map{"error": "endpoint not found"})
	}
	return c.JSON(ep)
}

func (api *ConfigAPI) CreateEndpoint(c fiber.Ctx) error {
	var endpoint EndpointRules
	if err := c.Bind().Body(&endpoint); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	if err := api.store.CreateEndpoint(&endpoint); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(201).JSON(endpoint)
}

func (api *ConfigAPI) UpdateEndpoint(c fiber.Ctx) error {
	endpoint := c.Params("endpoint")
	var ep EndpointRules
	if err := c.Bind().Body(&ep); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	ep.Endpoint = endpoint
	if err := api.store.UpdateEndpoint(&ep); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(ep)
}

func (api *ConfigAPI) DeleteEndpoint(c fiber.Ctx) error {
	endpoint := c.Params("endpoint")
	if err := api.store.DeleteEndpoint(endpoint); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(204).Send(nil)
}

func (api *ConfigAPI) GetGlobalConfig(c fiber.Ctx) error {
	config, err := api.store.GetGlobalConfig()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(config)
}

func (api *ConfigAPI) UpdateGlobalConfig(c fiber.Ctx) error {
	var config GlobalRules
	if err := c.Bind().Body(&config); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	if err := api.store.UpdateGlobalConfig(&config); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(config)
}

func (api *ConfigAPI) ListUsers(c fiber.Ctx) error {
	users, err := api.store.ListUsers()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(users)
}

func (api *ConfigAPI) GetUser(c fiber.Ctx) error {
	id := c.Params("id")
	user, err := api.store.GetUser(id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	if user == nil {
		return c.Status(404).JSON(fiber.Map{"error": "user not found"})
	}
	return c.JSON(user)
}

func (api *ConfigAPI) CreateUser(c fiber.Ctx) error {
	var user User
	if err := c.Bind().Body(&user); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	if err := api.store.CreateUser(&user); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(201).JSON(user)
}

func (api *ConfigAPI) UpdateUser(c fiber.Ctx) error {
	id := c.Params("id")
	var user User
	if err := c.Bind().Body(&user); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	user.ID = id
	if err := api.store.UpdateUser(&user); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(user)
}

func (api *ConfigAPI) DeleteUser(c fiber.Ctx) error {
	id := c.Params("id")
	if err := api.store.DeleteUser(id); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(204).Send(nil)
}

func (api *ConfigAPI) ListGroups(c fiber.Ctx) error {
	groups, err := api.store.ListGroups()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(groups)
}

func (api *ConfigAPI) GetGroup(c fiber.Ctx) error {
	id := c.Params("id")
	group, err := api.store.GetGroup(id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	if group == nil {
		return c.Status(404).JSON(fiber.Map{"error": "group not found"})
	}
	return c.JSON(group)
}

func (api *ConfigAPI) CreateGroup(c fiber.Ctx) error {
	var group Group
	if err := c.Bind().Body(&group); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	if err := api.store.CreateGroup(&group); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(201).JSON(group)
}

func (api *ConfigAPI) UpdateGroup(c fiber.Ctx) error {
	id := c.Params("id")
	var group Group
	if err := c.Bind().Body(&group); err != nil {
		return c.Status(400).JSON(fiber.Map{"error": "invalid request"})
	}
	group.ID = id
	if err := api.store.UpdateGroup(&group); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(group)
}

func (api *ConfigAPI) DeleteGroup(c fiber.Ctx) error {
	id := c.Params("id")
	if err := api.store.DeleteGroup(id); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(204).Send(nil)
}

func (api *ConfigAPI) AddUserToGroup(c fiber.Ctx) error {
	userID := c.Params("userId")
	groupID := c.Params("groupId")
	if err := api.store.AddUserToGroup(userID, groupID); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(204).Send(nil)
}

func (api *ConfigAPI) RemoveUserFromGroup(c fiber.Ctx) error {
	userID := c.Params("userId")
	groupID := c.Params("groupId")
	if err := api.store.RemoveUserFromGroup(userID, groupID); err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(204).Send(nil)
}

func (api *ConfigAPI) GetUserGroups(c fiber.Ctx) error {
	userID := c.Params("userId")
	groups, err := api.store.GetUserGroups(userID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(groups)
}

func (api *ConfigAPI) GetGroupUsers(c fiber.Ctx) error {
	groupID := c.Params("groupId")
	users, err := api.store.GetGroupUsers(groupID)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(users)
}
