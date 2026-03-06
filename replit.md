# Aiglos Security Dashboard

## Overview
Enterprise-grade web dashboard for the Aiglos AI Agent Security Runtime. Provides real-time monitoring, event logging, trust management, policy configuration, CMMC compliance tracking, and full administrative capabilities for AI agents operating through MCP (Model Context Protocol) proxies.

## Architecture
- **Frontend**: React + TypeScript + Vite + Tailwind CSS + shadcn/ui
- **Backend**: Express.js + TypeScript
- **Database**: PostgreSQL with Drizzle ORM
- **Routing**: wouter (frontend), Express (backend API)
- **State**: TanStack React Query
- **Security**: Helmet, express-rate-limit, session-based auth, RBAC, API key auth for ingest
- **Real-time**: WebSocket server for event streaming from Aiglos proxy

## Enterprise Features
1. **Authentication & RBAC** - Session-based login with 3 roles (admin, analyst, viewer)
2. **Proxy Integration** - WebSocket + HTTP ingest API for Aiglos Python runtime events
3. **Data Retention** - Configurable retention policies per resource type with manual purge
4. **Audit Trail** - Logs all system mutations (who did what, when, from where)
5. **Multi-tenancy** - Organization-scoped data isolation across all tables
6. **API Security** - Rate limiting, helmet headers, API key validation, secure cookies
7. **Report Export** - JSON and CSV exports for events, sessions, compliance, audit logs
8. **Alerting** - Webhook/Slack/Splunk/SIEM/PagerDuty alert destination management

## Pages
1. **Login** (`/`) - Authentication gate, redirects to dashboard after login
2. **Dashboard** (`/`) - Security overview with metrics, recent events, active sessions
3. **Sessions** (`/sessions`) - Agent session monitoring with integrity/anomaly scores
4. **Events** (`/events`) - Security event log with severity/type filtering
5. **Trust Registry** (`/trust`) - Manage trusted/blocked MCP servers
6. **Policies** (`/policies`) - Security policy rules with toggle/create
7. **Compliance** (`/compliance`) - CMMC/NIST control coverage visualization
8. **Users** (`/users`) - User management with role assignment (admin only)
9. **Audit Trail** (`/audit`) - System activity log with resource type filtering (admin only)
10. **Data Retention** (`/retention`) - Retention policy management with manual purge (admin only)
11. **Alerting** (`/alerts`) - Alert destination configuration and testing (admin/analyst)
12. **Reports** (`/reports`) - Report export, API key management, integration docs

## Data Models
- `organizations` - Multi-tenant organization entities
- `users` - Auth users with roles and org membership
- `sessions` - AI agent sessions with goal integrity and anomaly scores
- `securityEvents` - Security events (goal drift, credential detection, policy violations, etc.)
- `toolCalls` - MCP tool call audit log
- `trustedServers` - MCP server trust registry
- `policyRules` - Security policy rules
- `auditLogs` - System audit trail
- `dataRetentionPolicies` - Data lifecycle configuration
- `alertDestinations` - Alert delivery endpoints
- `apiKeys` - Hashed API keys for ingest authentication

## Theme
- Dark-first cybersecurity theme with cyan primary (`hsl(199, 89%, 48%)`)
- Inter font family, JetBrains Mono for code
- Custom severity badge system (critical/high/medium/low/info)

## API Routes
All prefixed with `/api/`:

### Auth
- `POST /auth/login` - Authenticate with username/password
- `POST /auth/logout` - End session
- `GET /auth/me` - Get current user
- `POST /auth/register` - Create user (admin only)

### Monitoring
- `GET /dashboard/stats` - Aggregate dashboard metrics
- `GET /sessions` - List sessions (with `?active=true` filter)
- `GET /events` - List events with `?severity=` and `?type=` filters
- `GET/POST /trust` - Trust registry CRUD
- `GET/POST /policies` - Policy rules CRUD
- `GET /compliance` - CMMC compliance data

### Administration
- `GET /users` - List users (admin)
- `PATCH /users/:id` - Update user role (admin)
- `DELETE /users/:id` - Delete user (admin)
- `GET /audit-logs` - Audit trail (admin)
- `GET/POST /retention` - Data retention policies (admin)
- `POST /retention/purge` - Manual data purge (admin)
- `GET/POST /alerts` - Alert destinations (admin/analyst)
- `POST /alerts/:id/test` - Test alert delivery (admin)
- `GET/POST /api-keys` - API key management (admin)

### Reports
- `GET /reports/events` - Export events (JSON/CSV)
- `GET /reports/sessions` - Export sessions (JSON/CSV)
- `GET /reports/compliance` - Export compliance report
- `GET /reports/audit` - Export audit trail (admin, JSON/CSV)

### Ingest (API key required)
- `POST /ingest/event` - Push security event from proxy
- `POST /ingest/session` - Push session data from proxy
- `WS /ws?apiKey=KEY` - WebSocket real-time event streaming

## Demo Credentials
- admin / admin123 (full access)
- analyst / analyst123 (monitoring + policies)
- viewer / viewer123 (read-only)

## GitHub Repository
https://github.com/w1123581321345589/aiglos-dashboard
