package tcpguard

// User represents a user in the system
type User struct {
	ID       string   `json:"id"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups"`
}

// Group represents a group of users
type Group struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Rules       []string `json:"rules"`
}

// ConfigStore interface for all TCPGuard configuration storage
type ConfigStore interface {
	// Rule operations
	GetRule(name string) (*Rule, error)
	CreateRule(rule *Rule) error
	UpdateRule(rule *Rule) error
	DeleteRule(name string) error
	ListRules() ([]*Rule, error)

	// Endpoint operations
	GetEndpoint(endpoint string) (*EndpointRules, error)
	CreateEndpoint(rules *EndpointRules) error
	UpdateEndpoint(rules *EndpointRules) error
	DeleteEndpoint(endpoint string) error
	ListEndpoints() ([]*EndpointRules, error)

	// Global config
	GetGlobalConfig() (*GlobalRules, error)
	UpdateGlobalConfig(config *GlobalRules) error

	// User operations
	GetUser(userID string) (*User, error)
	CreateUser(user *User) error
	UpdateUser(user *User) error
	DeleteUser(userID string) error
	ListUsers() ([]*User, error)

	// Group operations
	GetGroup(groupID string) (*Group, error)
	CreateGroup(group *Group) error
	UpdateGroup(group *Group) error
	DeleteGroup(groupID string) error
	ListGroups() ([]*Group, error)

	// User-Group operations
	AddUserToGroup(userID, groupID string) error
	RemoveUserFromGroup(userID, groupID string) error
	GetUserGroups(userID string) ([]*Group, error)
	GetGroupUsers(groupID string) ([]*User, error)

	// Load all config
	LoadAll() (*AnomalyConfig, error)
}

// VersionedConfigStore provides optimistic concurrency for runtime config APIs.
type VersionedConfigStore interface {
	GetConfigVersion() (int, error)
	CompareAndSwapConfigVersion(expected int) (int, error)
}
