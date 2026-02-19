package tcpguard

import (
	"database/sql"
	"encoding/json"

	"github.com/jmoiron/sqlx"
)

type SQLConfigStore struct {
	db *sqlx.DB
}

func NewSQLConfigStore(db *sqlx.DB) (*SQLConfigStore, error) {
	store := &SQLConfigStore{db: db}
	if err := store.createTables(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *SQLConfigStore) createTables() error {
	schema := `
	CREATE TABLE IF NOT EXISTS rules (
		name TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		enabled INTEGER NOT NULL DEFAULT 1,
		priority INTEGER NOT NULL DEFAULT 0,
		params TEXT NOT NULL DEFAULT '{}'
	);

	CREATE TABLE IF NOT EXISTS rule_users (
		rule_name TEXT NOT NULL,
		user_id TEXT NOT NULL,
		PRIMARY KEY (rule_name, user_id),
		FOREIGN KEY (rule_name) REFERENCES rules(name) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS rule_groups (
		rule_name TEXT NOT NULL,
		group_id TEXT NOT NULL,
		PRIMARY KEY (rule_name, group_id),
		FOREIGN KEY (rule_name) REFERENCES rules(name) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS rule_actions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_name TEXT NOT NULL,
		type TEXT NOT NULL,
		priority INTEGER DEFAULT 0,
		duration TEXT,
		response_status INTEGER NOT NULL,
		response_message TEXT NOT NULL,
		FOREIGN KEY (rule_name) REFERENCES rules(name) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS endpoints (
		endpoint TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		rate_limit_rpm INTEGER NOT NULL DEFAULT 0,
		rate_limit_burst INTEGER NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS endpoint_users (
		endpoint TEXT NOT NULL,
		user_id TEXT NOT NULL,
		PRIMARY KEY (endpoint, user_id),
		FOREIGN KEY (endpoint) REFERENCES endpoints(endpoint) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS endpoint_groups (
		endpoint TEXT NOT NULL,
		group_id TEXT NOT NULL,
		PRIMARY KEY (endpoint, group_id),
		FOREIGN KEY (endpoint) REFERENCES endpoints(endpoint) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS endpoint_actions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		endpoint TEXT NOT NULL,
		type TEXT NOT NULL,
		priority INTEGER DEFAULT 0,
		duration TEXT,
		response_status INTEGER NOT NULL,
		response_message TEXT NOT NULL,
		FOREIGN KEY (endpoint) REFERENCES endpoints(endpoint) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS global_config (
		id INTEGER PRIMARY KEY DEFAULT 1,
		trust_proxy INTEGER DEFAULT 0,
		ban_escalation_threshold INTEGER DEFAULT 3,
		ban_escalation_window TEXT DEFAULT '24h',
		CHECK (id = 1)
	);

	CREATE TABLE IF NOT EXISTS global_allow_cidrs (
		cidr TEXT PRIMARY KEY
	);

	CREATE TABLE IF NOT EXISTS global_deny_cidrs (
		cidr TEXT PRIMARY KEY
	);

	CREATE TABLE IF NOT EXISTS global_trusted_proxy_cidrs (
		cidr TEXT PRIMARY KEY
	);

	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		email TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS groups (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		description TEXT
	);

	CREATE TABLE IF NOT EXISTS user_groups (
		user_id TEXT NOT NULL,
		group_id TEXT NOT NULL,
		PRIMARY KEY (user_id, group_id),
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
	);

	INSERT OR IGNORE INTO global_config (id) VALUES (1);
	`
	_, err := s.db.Exec(schema)
	return err
}

func (s *SQLConfigStore) GetRule(name string) (*Rule, error) {
	var rule Rule
	var paramsJSON string
	err := s.db.QueryRow("SELECT name, type, enabled, priority, params FROM rules WHERE name = ?", name).
		Scan(&rule.Name, &rule.Type, &rule.Enabled, &rule.Priority, &paramsJSON)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal([]byte(paramsJSON), &rule.Params)

	// Load users
	rows, _ := s.db.Query("SELECT user_id FROM rule_users WHERE rule_name = ?", name)
	for rows.Next() {
		var userID string
		rows.Scan(&userID)
		rule.Users = append(rule.Users, userID)
	}
	rows.Close()

	// Load groups
	rows, _ = s.db.Query("SELECT group_id FROM rule_groups WHERE rule_name = ?", name)
	for rows.Next() {
		var groupID string
		rows.Scan(&groupID)
		rule.Groups = append(rule.Groups, groupID)
	}
	rows.Close()

	// Load actions
	rows, _ = s.db.Query("SELECT type, priority, duration, response_status, response_message FROM rule_actions WHERE rule_name = ? ORDER BY priority DESC", name)
	for rows.Next() {
		var action Action
		var duration sql.NullString
		rows.Scan(&action.Type, &action.Priority, &duration, &action.Response.Status, &action.Response.Message)
		if duration.Valid {
			action.Duration = duration.String
		}
		rule.Actions = append(rule.Actions, action)
	}
	rows.Close()

	return &rule, nil
}

func (s *SQLConfigStore) CreateRule(rule *Rule) error {
	tx, _ := s.db.Begin()
	defer tx.Rollback()

	paramsJSON, _ := json.Marshal(rule.Params)
	_, err := tx.Exec("INSERT INTO rules (name, type, enabled, priority, params) VALUES (?, ?, ?, ?, ?)",
		rule.Name, rule.Type, rule.Enabled, rule.Priority, string(paramsJSON))
	if err != nil {
		return err
	}

	for _, userID := range rule.Users {
		tx.Exec("INSERT INTO rule_users (rule_name, user_id) VALUES (?, ?)", rule.Name, userID)
	}

	for _, groupID := range rule.Groups {
		tx.Exec("INSERT INTO rule_groups (rule_name, group_id) VALUES (?, ?)", rule.Name, groupID)
	}

	for _, action := range rule.Actions {
		duration := sql.NullString{String: action.Duration, Valid: action.Duration != ""}
		tx.Exec("INSERT INTO rule_actions (rule_name, type, priority, duration, response_status, response_message) VALUES (?, ?, ?, ?, ?, ?)",
			rule.Name, action.Type, action.Priority, duration, action.Response.Status, action.Response.Message)
	}

	return tx.Commit()
}

func (s *SQLConfigStore) UpdateRule(rule *Rule) error {
	tx, _ := s.db.Begin()
	defer tx.Rollback()

	paramsJSON, _ := json.Marshal(rule.Params)
	_, err := tx.Exec("UPDATE rules SET type = ?, enabled = ?, priority = ?, params = ? WHERE name = ?",
		rule.Type, rule.Enabled, rule.Priority, string(paramsJSON), rule.Name)
	if err != nil {
		return err
	}

	tx.Exec("DELETE FROM rule_users WHERE rule_name = ?", rule.Name)
	tx.Exec("DELETE FROM rule_groups WHERE rule_name = ?", rule.Name)
	tx.Exec("DELETE FROM rule_actions WHERE rule_name = ?", rule.Name)

	for _, userID := range rule.Users {
		tx.Exec("INSERT INTO rule_users (rule_name, user_id) VALUES (?, ?)", rule.Name, userID)
	}

	for _, groupID := range rule.Groups {
		tx.Exec("INSERT INTO rule_groups (rule_name, group_id) VALUES (?, ?)", rule.Name, groupID)
	}

	for _, action := range rule.Actions {
		duration := sql.NullString{String: action.Duration, Valid: action.Duration != ""}
		tx.Exec("INSERT INTO rule_actions (rule_name, type, priority, duration, response_status, response_message) VALUES (?, ?, ?, ?, ?, ?)",
			rule.Name, action.Type, action.Priority, duration, action.Response.Status, action.Response.Message)
	}

	return tx.Commit()
}

func (s *SQLConfigStore) DeleteRule(name string) error {
	_, err := s.db.Exec("DELETE FROM rules WHERE name = ?", name)
	return err
}

func (s *SQLConfigStore) ListRules() ([]*Rule, error) {
	rows, err := s.db.Query("SELECT name FROM rules")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []*Rule
	for rows.Next() {
		var name string
		rows.Scan(&name)
		if rule, err := s.GetRule(name); err == nil && rule != nil {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func (s *SQLConfigStore) GetEndpoint(endpoint string) (*EndpointRules, error) {
	var ep EndpointRules
	err := s.db.QueryRow("SELECT endpoint, name, rate_limit_rpm, rate_limit_burst FROM endpoints WHERE endpoint = ?", endpoint).
		Scan(&ep.Endpoint, &ep.Name, &ep.RateLimit.RequestsPerMinute, &ep.RateLimit.Burst)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	rows, _ := s.db.Query("SELECT user_id FROM endpoint_users WHERE endpoint = ?", endpoint)
	for rows.Next() {
		var userID string
		rows.Scan(&userID)
		ep.Users = append(ep.Users, userID)
	}
	rows.Close()

	rows, _ = s.db.Query("SELECT group_id FROM endpoint_groups WHERE endpoint = ?", endpoint)
	for rows.Next() {
		var groupID string
		rows.Scan(&groupID)
		ep.Groups = append(ep.Groups, groupID)
	}
	rows.Close()

	rows, _ = s.db.Query("SELECT type, priority, duration, response_status, response_message FROM endpoint_actions WHERE endpoint = ? ORDER BY priority DESC", endpoint)
	for rows.Next() {
		var action Action
		var duration sql.NullString
		rows.Scan(&action.Type, &action.Priority, &duration, &action.Response.Status, &action.Response.Message)
		if duration.Valid {
			action.Duration = duration.String
		}
		ep.Actions = append(ep.Actions, action)
	}
	rows.Close()

	return &ep, nil
}

func (s *SQLConfigStore) CreateEndpoint(rules *EndpointRules) error {
	tx, _ := s.db.Begin()
	defer tx.Rollback()

	_, err := tx.Exec("INSERT INTO endpoints (endpoint, name, rate_limit_rpm, rate_limit_burst) VALUES (?, ?, ?, ?)",
		rules.Endpoint, rules.Name, rules.RateLimit.RequestsPerMinute, rules.RateLimit.Burst)
	if err != nil {
		return err
	}

	for _, userID := range rules.Users {
		tx.Exec("INSERT INTO endpoint_users (endpoint, user_id) VALUES (?, ?)", rules.Endpoint, userID)
	}

	for _, groupID := range rules.Groups {
		tx.Exec("INSERT INTO endpoint_groups (endpoint, group_id) VALUES (?, ?)", rules.Endpoint, groupID)
	}

	for _, action := range rules.Actions {
		duration := sql.NullString{String: action.Duration, Valid: action.Duration != ""}
		tx.Exec("INSERT INTO endpoint_actions (endpoint, type, priority, duration, response_status, response_message) VALUES (?, ?, ?, ?, ?, ?)",
			rules.Endpoint, action.Type, action.Priority, duration, action.Response.Status, action.Response.Message)
	}

	return tx.Commit()
}

func (s *SQLConfigStore) UpdateEndpoint(rules *EndpointRules) error {
	tx, _ := s.db.Begin()
	defer tx.Rollback()

	_, err := tx.Exec("UPDATE endpoints SET name = ?, rate_limit_rpm = ?, rate_limit_burst = ? WHERE endpoint = ?",
		rules.Name, rules.RateLimit.RequestsPerMinute, rules.RateLimit.Burst, rules.Endpoint)
	if err != nil {
		return err
	}

	tx.Exec("DELETE FROM endpoint_users WHERE endpoint = ?", rules.Endpoint)
	tx.Exec("DELETE FROM endpoint_groups WHERE endpoint = ?", rules.Endpoint)
	tx.Exec("DELETE FROM endpoint_actions WHERE endpoint = ?", rules.Endpoint)

	for _, userID := range rules.Users {
		tx.Exec("INSERT INTO endpoint_users (endpoint, user_id) VALUES (?, ?)", rules.Endpoint, userID)
	}

	for _, groupID := range rules.Groups {
		tx.Exec("INSERT INTO endpoint_groups (endpoint, group_id) VALUES (?, ?)", rules.Endpoint, groupID)
	}

	for _, action := range rules.Actions {
		duration := sql.NullString{String: action.Duration, Valid: action.Duration != ""}
		tx.Exec("INSERT INTO endpoint_actions (endpoint, type, priority, duration, response_status, response_message) VALUES (?, ?, ?, ?, ?, ?)",
			rules.Endpoint, action.Type, action.Priority, duration, action.Response.Status, action.Response.Message)
	}

	return tx.Commit()
}

func (s *SQLConfigStore) DeleteEndpoint(endpoint string) error {
	_, err := s.db.Exec("DELETE FROM endpoints WHERE endpoint = ?", endpoint)
	return err
}

func (s *SQLConfigStore) ListEndpoints() ([]*EndpointRules, error) {
	rows, err := s.db.Query("SELECT endpoint FROM endpoints")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var endpoints []*EndpointRules
	for rows.Next() {
		var endpoint string
		rows.Scan(&endpoint)
		if ep, err := s.GetEndpoint(endpoint); err == nil && ep != nil {
			endpoints = append(endpoints, ep)
		}
	}
	return endpoints, nil
}

func (s *SQLConfigStore) GetGlobalConfig() (*GlobalRules, error) {
	var global GlobalRules
	var trustProxy int
	var threshold int
	var window string

	err := s.db.QueryRow("SELECT trust_proxy, ban_escalation_threshold, ban_escalation_window FROM global_config WHERE id = 1").
		Scan(&trustProxy, &threshold, &window)
	if err != nil {
		return nil, err
	}

	global.TrustProxy = trustProxy == 1
	global.BanEscalationConfig = &struct {
		TempThreshold int    `json:"tempThreshold"`
		Window        string `json:"window"`
	}{TempThreshold: threshold, Window: window}

	rows, _ := s.db.Query("SELECT cidr FROM global_allow_cidrs")
	for rows.Next() {
		var cidr string
		rows.Scan(&cidr)
		global.AllowCIDRs = append(global.AllowCIDRs, cidr)
	}
	rows.Close()

	rows, _ = s.db.Query("SELECT cidr FROM global_deny_cidrs")
	for rows.Next() {
		var cidr string
		rows.Scan(&cidr)
		global.DenyCIDRs = append(global.DenyCIDRs, cidr)
	}
	rows.Close()

	rows, _ = s.db.Query("SELECT cidr FROM global_trusted_proxy_cidrs")
	for rows.Next() {
		var cidr string
		rows.Scan(&cidr)
		global.TrustedProxyCIDRs = append(global.TrustedProxyCIDRs, cidr)
	}
	rows.Close()

	global.Rules = make(map[string]Rule)
	return &global, nil
}

func (s *SQLConfigStore) UpdateGlobalConfig(config *GlobalRules) error {
	tx, _ := s.db.Begin()
	defer tx.Rollback()

	trustProxy := 0
	if config.TrustProxy {
		trustProxy = 1
	}

	threshold := 3
	window := "24h"
	if config.BanEscalationConfig != nil {
		threshold = config.BanEscalationConfig.TempThreshold
		window = config.BanEscalationConfig.Window
	}

	_, err := tx.Exec("UPDATE global_config SET trust_proxy = ?, ban_escalation_threshold = ?, ban_escalation_window = ? WHERE id = 1",
		trustProxy, threshold, window)
	if err != nil {
		return err
	}

	tx.Exec("DELETE FROM global_allow_cidrs")
	tx.Exec("DELETE FROM global_deny_cidrs")
	tx.Exec("DELETE FROM global_trusted_proxy_cidrs")

	for _, cidr := range config.AllowCIDRs {
		tx.Exec("INSERT INTO global_allow_cidrs (cidr) VALUES (?)", cidr)
	}

	for _, cidr := range config.DenyCIDRs {
		tx.Exec("INSERT INTO global_deny_cidrs (cidr) VALUES (?)", cidr)
	}

	for _, cidr := range config.TrustedProxyCIDRs {
		tx.Exec("INSERT INTO global_trusted_proxy_cidrs (cidr) VALUES (?)", cidr)
	}

	return tx.Commit()
}

func (s *SQLConfigStore) GetUser(userID string) (*User, error) {
	var user User
	err := s.db.QueryRow("SELECT id, username, email FROM users WHERE id = ?", userID).
		Scan(&user.ID, &user.Username, &user.Email)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	rows, _ := s.db.Query("SELECT group_id FROM user_groups WHERE user_id = ?", userID)
	for rows.Next() {
		var groupID string
		rows.Scan(&groupID)
		user.Groups = append(user.Groups, groupID)
	}
	rows.Close()

	return &user, nil
}

func (s *SQLConfigStore) CreateUser(user *User) error {
	tx, _ := s.db.Begin()
	defer tx.Rollback()

	_, err := tx.Exec("INSERT INTO users (id, username, email) VALUES (?, ?, ?)",
		user.ID, user.Username, user.Email)
	if err != nil {
		return err
	}

	for _, groupID := range user.Groups {
		tx.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", user.ID, groupID)
	}

	return tx.Commit()
}

func (s *SQLConfigStore) UpdateUser(user *User) error {
	tx, _ := s.db.Begin()
	defer tx.Rollback()

	_, err := tx.Exec("UPDATE users SET username = ?, email = ? WHERE id = ?",
		user.Username, user.Email, user.ID)
	if err != nil {
		return err
	}

	tx.Exec("DELETE FROM user_groups WHERE user_id = ?", user.ID)

	for _, groupID := range user.Groups {
		tx.Exec("INSERT INTO user_groups (user_id, group_id) VALUES (?, ?)", user.ID, groupID)
	}

	return tx.Commit()
}

func (s *SQLConfigStore) DeleteUser(userID string) error {
	_, err := s.db.Exec("DELETE FROM users WHERE id = ?", userID)
	return err
}

func (s *SQLConfigStore) ListUsers() ([]*User, error) {
	rows, err := s.db.Query("SELECT id FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var id string
		rows.Scan(&id)
		if user, err := s.GetUser(id); err == nil && user != nil {
			users = append(users, user)
		}
	}
	return users, nil
}

func (s *SQLConfigStore) GetGroup(groupID string) (*Group, error) {
	var group Group
	err := s.db.QueryRow("SELECT id, name, description FROM groups WHERE id = ?", groupID).
		Scan(&group.ID, &group.Name, &group.Description)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &group, nil
}

func (s *SQLConfigStore) CreateGroup(group *Group) error {
	_, err := s.db.Exec("INSERT INTO groups (id, name, description) VALUES (?, ?, ?)",
		group.ID, group.Name, group.Description)
	return err
}

func (s *SQLConfigStore) UpdateGroup(group *Group) error {
	_, err := s.db.Exec("UPDATE groups SET name = ?, description = ? WHERE id = ?",
		group.Name, group.Description, group.ID)
	return err
}

func (s *SQLConfigStore) DeleteGroup(groupID string) error {
	_, err := s.db.Exec("DELETE FROM groups WHERE id = ?", groupID)
	return err
}

func (s *SQLConfigStore) ListGroups() ([]*Group, error) {
	rows, err := s.db.Query("SELECT id, name, description FROM groups")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*Group
	for rows.Next() {
		var group Group
		rows.Scan(&group.ID, &group.Name, &group.Description)
		groups = append(groups, &group)
	}
	return groups, nil
}

func (s *SQLConfigStore) AddUserToGroup(userID, groupID string) error {
	_, err := s.db.Exec("INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?, ?)", userID, groupID)
	return err
}

func (s *SQLConfigStore) RemoveUserFromGroup(userID, groupID string) error {
	_, err := s.db.Exec("DELETE FROM user_groups WHERE user_id = ? AND group_id = ?", userID, groupID)
	return err
}

func (s *SQLConfigStore) GetUserGroups(userID string) ([]*Group, error) {
	rows, err := s.db.Query(`
		SELECT g.id, g.name, g.description
		FROM groups g
		JOIN user_groups ug ON g.id = ug.group_id
		WHERE ug.user_id = ?`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*Group
	for rows.Next() {
		var group Group
		rows.Scan(&group.ID, &group.Name, &group.Description)
		groups = append(groups, &group)
	}
	return groups, nil
}

func (s *SQLConfigStore) GetGroupUsers(groupID string) ([]*User, error) {
	rows, err := s.db.Query("SELECT user_id FROM user_groups WHERE group_id = ?", groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		var userID string
		rows.Scan(&userID)
		if user, err := s.GetUser(userID); err == nil && user != nil {
			users = append(users, user)
		}
	}
	return users, nil
}

func (s *SQLConfigStore) LoadAll() (*AnomalyConfig, error) {
	global, err := s.GetGlobalConfig()
	if err != nil {
		return nil, err
	}

	rules, _ := s.ListRules()
	for _, rule := range rules {
		global.Rules[rule.Name] = *rule
	}

	endpoints, _ := s.ListEndpoints()
	apiEndpoints := make(map[string]EndpointRules)
	for _, ep := range endpoints {
		apiEndpoints[ep.Endpoint] = *ep
	}

	return &AnomalyConfig{
		AnomalyDetectionRules: AnomalyDetectionRules{
			Global:       *global,
			APIEndpoints: apiEndpoints,
		},
	}, nil
}
