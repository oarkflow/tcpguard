# TCPGuard SQL Configuration Example

This example demonstrates using SQL database (SQLite) for all TCPGuard configuration instead of JSON files.

## Features

- All configuration stored in SQLite database
- Users, groups, rules, endpoints in SQL tables
- Full CRUD operations via REST API
- Database seeding on startup
- No JSON files needed

## Database Schema

```sql
-- Rules table
CREATE TABLE rules (
    name TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    priority INTEGER NOT NULL DEFAULT 0,
    params TEXT NOT NULL DEFAULT '{}',
    pipeline TEXT,
    actions TEXT NOT NULL DEFAULT '[]'
);

-- Endpoints table
CREATE TABLE endpoints (
    endpoint TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    rate_limit TEXT NOT NULL DEFAULT '{}',
    actions TEXT NOT NULL DEFAULT '[]'
);

-- Global config table
CREATE TABLE global_config (
    id INTEGER PRIMARY KEY DEFAULT 1,
    rules TEXT NOT NULL DEFAULT '{}',
    allow_cidrs TEXT,
    deny_cidrs TEXT,
    trust_proxy INTEGER DEFAULT 0,
    trusted_proxy_cidrs TEXT,
    ban_escalation TEXT
);

-- Users table
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    groups TEXT NOT NULL DEFAULT '[]'
);

-- Groups table
CREATE TABLE groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT,
    rules TEXT NOT NULL DEFAULT '[]'
);
```

## Running

```bash
cd examples/sql-config-example
go run main.go
```

The database file `tcpguard.db` will be created automatically.

## Seeded Data

### Users
- `user-1` (admin) - admin-group
- `user-2` (developer) - dev-group
- `user-3` (viewer) - viewer-group

### Groups
- `admin-group` - Administrators
- `dev-group` - Developers
- `viewer-group` - Viewers

### Rules
- `ddosDetection` - Applies to everyone (50 req/min)
- `strictDDoSForViewers` - Only for viewer-group (20 req/min)

### Endpoints
- `/api/login` - Rate limited (5 req/min, burst 2)

## API Usage

### View Configuration

```bash
# List all rules
curl http://localhost:3000/api/rules

# List all endpoints
curl http://localhost:3000/api/endpoints

# List all users
curl http://localhost:3000/api/users

# List all groups
curl http://localhost:3000/api/groups

# Get global config
curl http://localhost:3000/api/config/global
```

### Create New Rule

```bash
curl -X POST http://localhost:3000/api/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "customRule",
    "type": "ddos",
    "enabled": true,
    "priority": 50,
    "params": {"requestsPerMinute": 30},
    "actions": [{
      "type": "rate_limit",
      "response": {"status": 429, "message": "Rate limited"}
    }]
  }'
```

### Create New User

```bash
curl -X POST http://localhost:3000/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "id": "user-4",
    "username": "newuser",
    "email": "newuser@example.com",
    "groups": ["dev-group"]
  }'
```

### Update Rule

```bash
curl -X PUT http://localhost:3000/api/rules/ddosDetection \
  -H "Content-Type: application/json" \
  -d '{
    "name": "ddosDetection",
    "type": "ddos",
    "enabled": true,
    "priority": 100,
    "params": {"requestsPerMinute": 100},
    "actions": [...]
  }'
```

### Delete Rule

```bash
curl -X DELETE http://localhost:3000/api/rules/customRule
```

## Testing

```bash
# Test without user (applies general rules)
curl http://localhost:3000/

# Test as admin user
curl -H "X-User-ID: user-1" http://localhost:3000/admin/dashboard

# Test as viewer (strict DDoS rule applies)
curl -H "X-User-ID: user-3" http://localhost:3000/

# Test login endpoint rate limit
for i in {1..10}; do
  curl -X POST http://localhost:3000/api/login
done
```

## Database Inspection

```bash
# Install sqlite3
sudo apt-get install sqlite3  # Ubuntu/Debian
brew install sqlite3          # macOS

# Open database
sqlite3 tcpguard.db

# View tables
.tables

# View rules
SELECT name, type, enabled FROM rules;

# View users
SELECT id, username, email FROM users;

# View groups
SELECT id, name, description FROM groups;

# Exit
.quit
```

## Advantages of SQL Storage

1. **Scalability**: Handle thousands of rules/users
2. **Transactions**: Atomic updates
3. **Queries**: Complex filtering and searching
4. **Backup**: Standard database backup tools
5. **Replication**: Database replication for HA
6. **Multi-instance**: Multiple TCPGuard instances share config
7. **Audit**: Track changes with triggers
8. **Performance**: Indexed queries

## Migration from JSON

To migrate from JSON files to SQL:

```go
// Load from JSON
fileStore, _ := tcpguard.NewFileConfigStore("./configs")
config, _ := fileStore.LoadAll()

// Save to SQL
db, _ := sqlx.Connect("sqlite3", "./tcpguard.db")
sqlStore, _ := tcpguard.NewSQLConfigStore(db)

// Migrate rules
rules, _ := fileStore.ListRules()
for _, rule := range rules {
    sqlStore.CreateRule(rule)
}

// Migrate endpoints
endpoints, _ := fileStore.ListEndpoints()
for _, ep := range endpoints {
    sqlStore.CreateEndpoint(ep)
}

// Migrate users
users, _ := fileStore.ListUsers()
for _, user := range users {
    sqlStore.CreateUser(user)
}

// Migrate groups
groups, _ := fileStore.ListGroups()
for _, group := range groups {
    sqlStore.CreateGroup(group)
}
```

## Production Deployment

For production, use PostgreSQL or MySQL:

```go
// PostgreSQL
db, _ := sqlx.Connect("postgres", 
    "host=localhost port=5432 user=tcpguard password=secret dbname=tcpguard sslmode=disable")

// MySQL
db, _ := sqlx.Connect("mysql", 
    "tcpguard:secret@tcp(localhost:3306)/tcpguard?parseTime=true")

configStore, _ := tcpguard.NewSQLConfigStore(db)
```
