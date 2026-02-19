# TCPGuard React Frontend Requirements

## Project Structure

```
src/
├── api/
│   ├── client.ts
│   ├── rules.ts
│   ├── users.ts
│   ├── groups.ts
│   ├── endpoints.ts
│   ├── global.ts
│   ├── health.ts
│   └── metrics.ts
├── components/
│   ├── ui/              # shadcn/ui
│   ├── layout/
│   ├── dashboard/
│   ├── rules/
│   ├── users/
│   ├── groups/
│   ├── testing/
│   └── monitoring/
├── hooks/
├── pages/
├── store/
├── types/
├── utils/
├── App.tsx
└── main.tsx
```

## Pages & Features

### 1. Dashboard (`/`)

**Purpose**: Real-time system overview

**Features**:
- Health status cards (store, metrics, rate_limiter, rule_engine)
- Live metrics (requests, blocks, active sessions)
- Attack summary (active attacks, IPs)
- Activity log (last 50 events)
- Quick actions (reload config, clear bans)
- Charts (request rate, block rate, attack types)
- Auto-refresh (5s interval)

**APIs**:
- `GET /health`
- `GET /metrics`
- `POST /api/rules/reload`

### 2. Rules Management (`/rules`)

**Purpose**: CRUD operations for detection rules

**Features**:
- Rule list (search, filter by type/enabled, sort by priority)
- Create/edit/delete rules
- JSON editor with syntax highlighting
- Form editor with validation
- Enable/disable toggle
- Priority drag-and-drop
- Rule templates (DDoS, MITM, rate limit, etc.)
- Duplicate rule
- Bulk enable/disable
- Import/export JSON
- Test rule before save
- User/group assignment

**Rule Types**:
- Global: `ddos`, `mitm`, `business_hours`, `business_region`
- Endpoint: `rate_limit`, `protected_route`, `session_hijacking`

**APIs**:
- `GET /api/rules`
- `POST /api/rules`
- `PUT /api/rules/:name`
- `DELETE /api/rules/:name`

### 3. Endpoints (`/endpoints`)

**Purpose**: Manage endpoint-specific rules

**Features**:
- Endpoint list (search, filter)
- Create/edit/delete endpoints
- Rate limit config (RPM, burst)
- Action assignment
- User/group restrictions
- Endpoint analytics

**APIs**:
- `GET /api/endpoints`
- `POST /api/endpoints`
- `PUT /api/endpoints/:endpoint`
- `DELETE /api/endpoints/:endpoint`

### 4. Users (`/users`)

**Purpose**: User management

**Features**:
- User list (search, filter by group)
- Create/edit/delete users
- Group assignment (multi-select)
- View applied rules (from groups)
- User activity log
- Bulk operations
- Export CSV

**APIs**:
- `GET /api/users`
- `POST /api/users`
- `PUT /api/users/:id`
- `DELETE /api/users/:id`

### 5. Groups (`/groups`)

**Purpose**: Group management

**Features**:
- Group list (search)
- Create/edit/delete groups
- View members
- Rule assignment
- Group analytics (requests, blocks)
- Export CSV

**APIs**:
- `GET /api/groups`
- `POST /api/groups`
- `PUT /api/groups/:id`
- `DELETE /api/groups/:id`

### 6. Testing (`/testing`)

**Purpose**: Rule testing and simulation

**Features**:
- **User Rule Tester**
  - Select user, endpoint, request count
  - Send requests with `X-User-ID` header
  - Show allowed/blocked counts
  - Real-time log

- **Group Rule Tester**
  - Select group, endpoint, request count
  - Map group to user
  - Show results

- **Endpoint Rule Tester**
  - Select endpoint, user (optional), request count
  - Test rate limits
  - Show results

- **Global Rule Tester**
  - Select rule type (DDoS, MITM)
  - Select user, request count
  - Simulate attack
  - Show results

- **Test History**
  - Save test results
  - Compare tests
  - Export results

**APIs**:
- Test by making actual requests to endpoints
- Log results locally

### 7. Monitoring (`/monitoring`)

**Purpose**: Security events and attack analysis

**Features**:
- **Detection Ledger**
  - Active attacks list
  - Attack timeline
  - Attack type distribution
  - Severity breakdown
  - Time range filter (1h, 6h, 24h, 7d, 30d)

- **Banned IPs**
  - List (temp/permanent)
  - Expiration countdown
  - Manual ban/unban
  - Ban history
  - Export CSV

- **Geographic Map**
  - World map with attack origins
  - Country statistics
  - Regional patterns

- **Telemetry Viewer**
  - Per-IP metrics
  - Metric trends
  - Anomaly highlights

**APIs**:
- `GET /api/detections`
- `GET /api/bans`
- `POST /api/bans`
- `DELETE /api/bans/:ip`
- `GET /api/telemetry/:ip`

### 8. Analytics (`/analytics`)

**Purpose**: Historical analysis and reporting

**Features**:
- Attack trends (line chart)
- Rule effectiveness (bar chart)
- Top blocked IPs (table)
- Most targeted endpoints (table)
- Response time analysis (histogram)
- False positive tracking
- Custom date range
- Compare time periods
- Export PDF/CSV
- Scheduled reports

**APIs**:
- `GET /api/analytics/attacks`
- `GET /api/analytics/rules`
- `GET /api/analytics/ips`
- `GET /api/analytics/endpoints`

### 9. Global Config (`/global`)

**Purpose**: Global access control settings

**Features**:
- Allow CIDRs (add/remove)
- Deny CIDRs (add/remove)
- Trust proxy toggle
- Trusted proxy CIDRs
- Ban escalation config (threshold, window)
- Save/reset

**APIs**:
- `GET /api/global`
- `PUT /api/global`

### 10. Settings (`/settings`)

**Purpose**: Application settings

**Features**:
- API endpoint config
- Refresh interval (1s, 5s, 10s, 30s, off)
- Theme (light/dark/auto)
- Notification preferences
- Export all config
- Import config
- Reset to defaults

## API Specifications

### Rules API

```typescript
// GET /api/rules
{
  global: {
    "ddosDetection": {
      name: "ddosDetection",
      type: "ddos",
      enabled: true,
      priority: 100,
      users: ["user-1"],
      groups: ["admin-group"],
      params: { requestsPerMinute: 50 },
      actions: [
        {
          type: "temporary_ban",
          priority: 10,
          duration: "10m",
          response: { status: 403, message: "Banned" }
        }
      ]
    }
  },
  endpoints: {
    "/api/login": {
      endpoint: "/api/login",
      name: "login",
      users: [],
      groups: [],
      rateLimit: { requestsPerMinute: 5, burst: 2 },
      actions: [
        {
          type: "rate_limit",
          response: { status: 429, message: "Too many requests" }
        }
      ]
    }
  }
}

// POST /api/rules
Body: { name, type, enabled, priority, users, groups, params, actions }

// PUT /api/rules/:name
Body: { enabled, priority, users, groups, params, actions }

// DELETE /api/rules/:name
```

### Users API

```typescript
// GET /api/users
[
  { id: "user-1", username: "admin", email: "admin@example.com", groups: ["admin-group"] }
]

// POST /api/users
Body: { id, username, email, groups }

// PUT /api/users/:id
Body: { username, email, groups }

// DELETE /api/users/:id
```

### Groups API

```typescript
// GET /api/groups
[
  { id: "admin-group", name: "Administrators", description: "Full access" }
]

// POST /api/groups
Body: { id, name, description }

// PUT /api/groups/:id
Body: { name, description }

// DELETE /api/groups/:id
```

### Endpoints API

```typescript
// GET /api/endpoints
[
  {
    endpoint: "/api/login",
    name: "login",
    users: [],
    groups: [],
    rateLimit: { requestsPerMinute: 5, burst: 2 },
    actions: [...]
  }
]

// POST /api/endpoints
Body: { endpoint, name, users, groups, rateLimit, actions }

// PUT /api/endpoints/:endpoint
Body: { name, users, groups, rateLimit, actions }

// DELETE /api/endpoints/:endpoint
```

### Global Config API

```typescript
// GET /api/global
{
  allowCIDRs: ["192.168.0.0/16"],
  denyCIDRs: ["203.0.113.0/24"],
  trustProxy: true,
  trustedProxyCIDRs: ["10.0.0.0/8"],
  banEscalation: { tempThreshold: 3, window: "24h" }
}

// PUT /api/global
Body: { allowCIDRs, denyCIDRs, trustProxy, trustedProxyCIDRs, banEscalation }
```

### Health API

```typescript
// GET /health
{
  status: "ok" | "degraded" | "down",
  timestamp: "2025-01-18T10:00:00Z",
  services: {
    store: { status: "ok" },
    metrics: { status: "ok" },
    rate_limiter: { status: "ok" },
    rule_engine: { status: "ok" }
  }
}
```

### Metrics API

```typescript
// GET /metrics (Prometheus format)
// Parse to:
{
  totalRequests: 1000,
  blockedRequests: 50,
  activeSessions: 10,
  ddosDetections: 5,
  mitmDetections: 2,
  requestRate: 100,
  blockRate: 5
}
```

## Component Library (shadcn/ui)

Required components:
- Button
- Input
- Select
- Checkbox
- Switch
- Dialog
- Dropdown Menu
- Table
- Card
- Badge
- Alert
- Tabs
- Form
- Toast
- Tooltip
- Popover
- Command
- Separator

## Key Features

### Real-time Updates
- Auto-refresh dashboard (5s)
- WebSocket for live events (optional)
- Optimistic updates
- Loading states
- Error handling

### Data Management
- TanStack Query for caching
- Zustand for global state
- Local storage for settings
- Optimistic mutations

### Forms
- React Hook Form
- Zod validation
- Error messages
- Dirty state tracking
- Auto-save (optional)

### Charts
- Recharts library
- Line charts (trends)
- Bar charts (comparisons)
- Pie charts (distribution)
- Area charts (metrics)
- Responsive design

### Testing Interface
- Send requests with Fetch API
- Track allowed/blocked
- Real-time log
- Color-coded results
- Export results

### User Experience
- Dark theme
- Responsive design
- Loading skeletons
- Error boundaries
- Toast notifications
- Keyboard shortcuts
- Search/filter everywhere
- Bulk operations
- Export data (CSV/JSON)

## Development Setup

```bash
npm create vite@latest tcpguard-frontend -- --template react-ts
cd tcpguard-frontend
npm install

# Dependencies
npm install @tanstack/react-query zustand react-router-dom
npm install tailwindcss postcss autoprefixer
npm install recharts react-hook-form zod @hookform/resolvers
npm install axios date-fns clsx tailwind-merge

# shadcn/ui
npx shadcn-ui@latest init
npx shadcn-ui@latest add button input select card table dialog
```

## Environment Variables

```env
VITE_API_URL=http://localhost:3000
VITE_WS_URL=ws://localhost:3000
VITE_REFRESH_INTERVAL=5000
```

## Deployment

```bash
npm run build
# Serve dist/ folder with nginx or serve static from Go
```

## Priority Implementation Order

1. Dashboard (health, metrics)
2. Rules management (CRUD)
3. Users management (CRUD)
4. Groups management (CRUD)
5. Testing interface
6. Endpoints management
7. Global config
8. Monitoring
9. Analytics
10. Settings
