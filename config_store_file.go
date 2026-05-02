package tcpguard

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type FileConfigStore struct {
	mu        sync.RWMutex
	configDir string
	rules     map[string]*Rule
	endpoints map[string]*EndpointRules
	global    *GlobalRules
	users     map[string]*User
	groups    map[string]*Group
}

type fileConfigVersion struct {
	Version int `json:"version"`
}

func NewFileConfigStore(configDir string) (*FileConfigStore, error) {
	store := &FileConfigStore{
		configDir: configDir,
		rules:     make(map[string]*Rule),
		endpoints: make(map[string]*EndpointRules),
		users:     make(map[string]*User),
		groups:    make(map[string]*Group),
	}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *FileConfigStore) load() error {
	s.loadRules()
	s.loadEndpoints()
	s.loadGlobal()
	s.loadUsers()
	s.loadGroups()
	return nil
}

func (s *FileConfigStore) loadRules() {
	rulesDir := filepath.Join(s.configDir, "rules")
	files, _ := os.ReadDir(rulesDir)
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}
		data, _ := os.ReadFile(filepath.Join(rulesDir, file.Name()))
		var rule Rule
		if json.Unmarshal(data, &rule) == nil {
			s.rules[rule.Name] = &rule
		}
	}
}

func (s *FileConfigStore) loadEndpoints() {
	endpointsDir := filepath.Join(s.configDir, "endpoints")
	files, _ := os.ReadDir(endpointsDir)
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}
		data, _ := os.ReadFile(filepath.Join(endpointsDir, file.Name()))
		var endpoint EndpointRules
		if json.Unmarshal(data, &endpoint) == nil {
			s.endpoints[endpoint.Endpoint] = &endpoint
		}
	}
}

func (s *FileConfigStore) loadGlobal() {
	globalDir := filepath.Join(s.configDir, "global")
	files, _ := os.ReadDir(globalDir)

	global := &GlobalRules{
		Rules: make(map[string]Rule),
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}
		path := filepath.Join(globalDir, file.Name())
		data, _ := os.ReadFile(path)

		if file.Name() == "access.json" {
			json.Unmarshal(data, global)
		} else {
			var rule Rule
			if json.Unmarshal(data, &rule) == nil {
				global.Rules[rule.Name] = rule
			}
		}
	}
	s.global = global
}

func (s *FileConfigStore) loadUsers() {
	data, err := os.ReadFile(filepath.Join(s.configDir, "users.json"))
	if err != nil {
		return
	}
	var cfg struct {
		Users []User `json:"users"`
	}
	if json.Unmarshal(data, &cfg) == nil {
		for _, user := range cfg.Users {
			u := user
			s.users[u.ID] = &u
		}
	}
}

func (s *FileConfigStore) loadGroups() {
	data, err := os.ReadFile(filepath.Join(s.configDir, "groups.json"))
	if err != nil {
		return
	}
	var cfg struct {
		Groups []Group `json:"groups"`
	}
	if json.Unmarshal(data, &cfg) == nil {
		for _, group := range cfg.Groups {
			g := group
			s.groups[g.ID] = &g
		}
	}
}

func (s *FileConfigStore) GetRule(name string) (*Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rule, exists := s.rules[name]
	if !exists {
		return nil, nil
	}
	return rule, nil
}

func (s *FileConfigStore) CreateRule(rule *Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules[rule.Name] = rule
	return s.saveRule(rule)
}

func (s *FileConfigStore) UpdateRule(rule *Rule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules[rule.Name] = rule
	return s.saveRule(rule)
}

func (s *FileConfigStore) DeleteRule(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rules, name)
	os.Remove(filepath.Join(s.configDir, "rules", name+".json"))
	return nil
}

func (s *FileConfigStore) ListRules() ([]*Rule, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rules := make([]*Rule, 0, len(s.rules))
	for _, rule := range s.rules {
		rules = append(rules, rule)
	}
	return rules, nil
}

func (s *FileConfigStore) saveRule(rule *Rule) error {
	data, _ := json.MarshalIndent(rule, "", "  ")
	return os.WriteFile(filepath.Join(s.configDir, "rules", rule.Name+".json"), data, 0644)
}

func (s *FileConfigStore) GetEndpoint(endpoint string) (*EndpointRules, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ep, exists := s.endpoints[endpoint]
	if !exists {
		return nil, nil
	}
	return ep, nil
}

func (s *FileConfigStore) CreateEndpoint(rules *EndpointRules) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endpoints[rules.Endpoint] = rules
	return s.saveEndpoint(rules)
}

func (s *FileConfigStore) UpdateEndpoint(rules *EndpointRules) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endpoints[rules.Endpoint] = rules
	return s.saveEndpoint(rules)
}

func (s *FileConfigStore) DeleteEndpoint(endpoint string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.endpoints, endpoint)
	os.Remove(filepath.Join(s.configDir, "endpoints", endpoint+".json"))
	return nil
}

func (s *FileConfigStore) ListEndpoints() ([]*EndpointRules, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	endpoints := make([]*EndpointRules, 0, len(s.endpoints))
	for _, ep := range s.endpoints {
		endpoints = append(endpoints, ep)
	}
	return endpoints, nil
}

func (s *FileConfigStore) saveEndpoint(rules *EndpointRules) error {
	data, _ := json.MarshalIndent(rules, "", "  ")
	return os.WriteFile(filepath.Join(s.configDir, "endpoints", rules.Name+".json"), data, 0644)
}

func (s *FileConfigStore) GetGlobalConfig() (*GlobalRules, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.global, nil
}

func (s *FileConfigStore) UpdateGlobalConfig(config *GlobalRules) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.global = config
	data, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile(filepath.Join(s.configDir, "global", "access.json"), data, 0644)
}

func (s *FileConfigStore) GetUser(userID string) (*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, exists := s.users[userID]
	if !exists {
		return nil, nil
	}
	return user, nil
}

func (s *FileConfigStore) CreateUser(user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if user.Groups == nil {
		user.Groups = []string{}
	}
	s.users[user.ID] = user
	return s.saveUsers()
}

func (s *FileConfigStore) UpdateUser(user *User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[user.ID] = user
	return s.saveUsers()
}

func (s *FileConfigStore) DeleteUser(userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, userID)
	return s.saveUsers()
}

func (s *FileConfigStore) ListUsers() ([]*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := make([]*User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}
	return users, nil
}

func (s *FileConfigStore) saveUsers() error {
	users := make([]User, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, *u)
	}
	data, _ := json.MarshalIndent(map[string]interface{}{"users": users}, "", "  ")
	return os.WriteFile(filepath.Join(s.configDir, "users.json"), data, 0644)
}

func (s *FileConfigStore) GetGroup(groupID string) (*Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	group, exists := s.groups[groupID]
	if !exists {
		return nil, nil
	}
	return group, nil
}

func (s *FileConfigStore) CreateGroup(group *Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if group.Rules == nil {
		group.Rules = []string{}
	}
	s.groups[group.ID] = group
	return s.saveGroups()
}

func (s *FileConfigStore) UpdateGroup(group *Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups[group.ID] = group
	return s.saveGroups()
}

func (s *FileConfigStore) DeleteGroup(groupID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.groups, groupID)
	return s.saveGroups()
}

func (s *FileConfigStore) ListGroups() ([]*Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	groups := make([]*Group, 0, len(s.groups))
	for _, group := range s.groups {
		groups = append(groups, group)
	}
	return groups, nil
}

func (s *FileConfigStore) saveGroups() error {
	groups := make([]Group, 0, len(s.groups))
	for _, g := range s.groups {
		groups = append(groups, *g)
	}
	data, _ := json.MarshalIndent(map[string]interface{}{"groups": groups}, "", "  ")
	return os.WriteFile(filepath.Join(s.configDir, "groups.json"), data, 0644)
}

func (s *FileConfigStore) AddUserToGroup(userID, groupID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, exists := s.users[userID]
	if !exists {
		return nil
	}
	if _, exists := s.groups[groupID]; !exists {
		return nil
	}
	for _, gid := range user.Groups {
		if gid == groupID {
			return nil
		}
	}
	user.Groups = append(user.Groups, groupID)
	return s.saveUsers()
}

func (s *FileConfigStore) RemoveUserFromGroup(userID, groupID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user, exists := s.users[userID]
	if !exists {
		return nil
	}
	newGroups := make([]string, 0)
	for _, gid := range user.Groups {
		if gid != groupID {
			newGroups = append(newGroups, gid)
		}
	}
	user.Groups = newGroups
	return s.saveUsers()
}

func (s *FileConfigStore) GetUserGroups(userID string) ([]*Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, exists := s.users[userID]
	if !exists {
		return nil, nil
	}
	groups := make([]*Group, 0)
	for _, groupID := range user.Groups {
		if group, exists := s.groups[groupID]; exists {
			groups = append(groups, group)
		}
	}
	return groups, nil
}

func (s *FileConfigStore) GetGroupUsers(groupID string) ([]*User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, exists := s.groups[groupID]; !exists {
		return nil, nil
	}
	users := make([]*User, 0)
	for _, user := range s.users {
		for _, gid := range user.Groups {
			if gid == groupID {
				users = append(users, user)
				break
			}
		}
	}
	return users, nil
}

func (s *FileConfigStore) LoadAll() (*AnomalyConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	config := &AnomalyConfig{
		AnomalyDetectionRules: AnomalyDetectionRules{
			Global:       *s.global,
			APIEndpoints: make(map[string]EndpointRules),
		},
	}

	for endpoint, rules := range s.endpoints {
		config.AnomalyDetectionRules.APIEndpoints[endpoint] = *rules
	}

	return config, nil
}

func (s *FileConfigStore) versionPath() string {
	return filepath.Join(s.configDir, ".tcpguard-version.json")
}

func (s *FileConfigStore) GetConfigVersion() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, err := os.ReadFile(s.versionPath())
	if err != nil {
		if os.IsNotExist(err) {
			return 1, nil
		}
		return 0, err
	}
	var version fileConfigVersion
	if err := json.Unmarshal(data, &version); err != nil {
		return 0, err
	}
	if version.Version <= 0 {
		return 1, nil
	}
	return version.Version, nil
}

func (s *FileConfigStore) CompareAndSwapConfigVersion(expected int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current := 1
	data, err := os.ReadFile(s.versionPath())
	if err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	if err == nil {
		var version fileConfigVersion
		if err := json.Unmarshal(data, &version); err != nil {
			return 0, err
		}
		if version.Version > 0 {
			current = version.Version
		}
	}
	if expected > 0 && expected != current {
		return current, nil
	}
	next := current + 1
	data, err = json.MarshalIndent(fileConfigVersion{Version: next}, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(s.versionPath(), data, 0644); err != nil {
		return 0, err
	}
	return next, nil
}

var _ VersionedConfigStore = (*FileConfigStore)(nil)
