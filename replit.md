# Aiglos Security Dashboard

## Overview
Enterprise-grade web dashboard for the Aiglos AI Agent Security Runtime. Provides real-time monitoring, event logging, trust management, policy configuration, CMMC compliance tracking, autonomous threat scanning, and full administrative capabilities for AI agents operating through MCP (Model Context Protocol) proxies.

## Python Package (aiglos/ v0.19.0)
The `aiglos/` directory contains the Python security runtime package covering threat families T01-T43.

### Package Structure
- `aiglos/__init__.py` -- Module-level API (attach, check, close, adaptive_run, etc.), version 0.19.0
- `aiglos/integrations/openclaw.py` -- OpenClaw guard with threat detection (T01-T43)
- `aiglos/integrations/hermes.py` -- Hermes integration guard with trajectory signing
- `aiglos/integrations/multi_agent.py` -- AgentDefGuard, MultiAgentRegistry, SessionIdentityChain
- `aiglos/integrations/memory_guard.py` -- Memory write guard (T31) with C2 channel corpus signals
- `aiglos/integrations/rl_guard.py` -- RL feedback guard (T39)
- `aiglos/integrations/http_intercept.py` -- HTTP interception engine (T25, T37, T22, T19/T20, T35, T36)
- `aiglos/integrations/subprocess_intercept.py` -- Subprocess interception (3-tier, 12 threat rules, T36_AGENTDEF extended for SKILL.md)
- `aiglos/integrations/context_guard.py` -- T40 SHARED_CONTEXT_POISON (ContextDirectoryGuard, ContextWriteResult)
- `aiglos/integrations/outbound_guard.py` -- T41 OUTBOUND_SECRET_LEAK (OutboundGuard, scan_for_secrets, contains_secret)
- `aiglos/integrations/honeypot.py` -- T43 HONEYPOT_ACCESS (HoneypotManager, synthetic credential files)
- `aiglos/integrations/override.py` -- OverrideManager (6-char codes, 120s expiry, 3 attempts)
- `aiglos/adaptive/source_reputation.py` -- SourceReputationGraph (cross-session source tracking, 4 risk levels)
- `aiglos/adaptive/observation.py` -- ObservationGraph with source_records, honeypot_events, override_challenges tables
- `aiglos/adaptive/campaign.py` -- CampaignAnalyzer (12 patterns including SKILL_CHAIN, SANDBOX_ESCAPE_ATTEMPT)
- `aiglos/adaptive/skill_reputation.py` -- SkillReputationGraph (ClawKeeper badge data, sync_security_feed)
- `aiglos/audit/scanner.py` -- AuditScanner (5-phase, 50+ checks, A-F grade)
- `aiglos/audit/report.py` -- AuditReporter (5 formats: summary, full, json, briefing, clawkeeper)
- `aiglos/autoresearch/` -- CitationVerifier, ThreatLiteratureSearch, ComplianceReportGenerator
- `aiglos/skills/SKILL.md` -- Context Hub skill distribution for Claude Code
- `aiglos/desktop/` -- Tauri desktop app (main.rs, App.jsx, aiglos_sidecar.py, install.sh)
- `aiglos/cli.py` -- CLI: scan-message, honeypot, override, reputation, audit, skill

- `server/federation/` -- Federation server (FastAPI, aggregator, auth, Supabase store, Railway deploy)
- `sdk/typescript/src/` -- TypeScript SDK (full parity: behavioral_baseline, policy_proposals, federation, security_surfaces, index)
- `website/` -- Landing site source (index.html, changelog.html, pricing.html) also served at /aiglos, /changelog, /pricing
- `.github/actions/aiglos-scan/action.yml` -- Reusable GitHub Action for Aiglos security audit
- `.github/workflows/aiglos-scan.yml` -- CI workflow (push/PR/nightly scan, deep mode, grade gating)

### Test Suites (1378 tests)
21 test files covering all modules and integrations.

### Class Name Map (important for imports)
- `ContextWriteResult` (NOT ContextGuardResult)
- `OutboundGuard` (NOT OutboundSecretGuard)
- `OutboundScanResult`
- Public helpers: `is_shared_context_write()`, `contains_secret()`, `scan_for_secrets()`

### GitHub Repo
Pushed to `w1123581321345589/aiglos` on the `main` branch.

## Architecture
- **Frontend**: React + TypeScript + Vite + Tailwind CSS + shadcn/ui
- **Backend**: Express.js + TypeScript
- **Database**: PostgreSQL with Drizzle ORM
- **Routing**: wouter (frontend), Express (backend API)
- **State**: TanStack React Query
- **Security**: Helmet, express-rate-limit, session-based auth, RBAC, API key auth for ingest
- **Real-time**: WebSocket server for event streaming from Aiglos proxy
- **Autonomous Engine**: In-process threat scanner (server/engine.ts), ported from aiglos_autonomous.py

## Enterprise Features
1. **Authentication & RBAC** - Session-based login with 3 roles (admin, analyst, viewer)
2. **Proxy Integration** - WebSocket + HTTP ingest API for Aiglos Python runtime events (org-scoped broadcast)
3. **Data Retention** - Configurable retention policies per resource type with scheduled enforcement (6h cycle) and manual purge
4. **Audit Trail** - Logs all system mutations (who did what, when, from where)
5. **Multi-tenancy** - Organization-scoped data isolation across all tables
6. **API Security** - Rate limiting, helmet headers, API key validation, secure cookies
7. **Report Export** - JSON and CSV exports for events, sessions, compliance, audit logs
8. **Alerting** - Webhook/Slack/Splunk/SIEM/PagerDuty alert destination management
9. **Autonomous Engine (Command Center)** - Always-on threat scanner with 5 hunt modules, 8 built-in threat patterns from NVD/OWASP/internal research, scheduler, and watchdog

## Autonomous Engine (server/engine.ts)
Ported from `aiglos_autonomous.py`. Runs in-process as a TypeScript singleton.

### 5 Hunt Modules
- **Credential Scan** - Detects API keys, tokens, passwords in tool call logs
- **Injection Hunt** - Finds prompt injection patterns (ignore-instructions, role-override, unicode steganography)
- **Behavioral Trends** - Rising anomaly scores, goal drift patterns across sessions
- **Policy Trends** - Repeated policy violations suggesting automated probing
- **Server Exposure** - MCP servers bound to 0.0.0.0, missing manifest hashes

### 8 Threat Intelligence Patterns
- tp-001: MCP Tool Poisoning via Hidden System Prompt (internal)
- tp-002: MCP Preference Manipulation Attack (internal)
- tp-003: GitHub Copilot YOLO Mode RCE, CVE-2025-53773 (NVD)
- tp-004: Cursor RCE via MCP Config Poisoning, CVE-2025-54135 (NVD)
- tp-005: OWASP Agentic #1 Prompt Injection via Tool Response (OWASP)
- tp-006: OWASP Agentic #2 Covert Exfiltration (OWASP)
- tp-007: OAuth Token Harvest via Compromised MCP Server (internal)
- tp-008: Unicode Steganography in Tool Arguments (internal)

On intel refresh, the engine auto-creates policy rules in the DB from these patterns.

### Engine Lifecycle
- Start: Creates singleton, runs initial scan + intel refresh, starts scheduled intervals
- Scheduler: Scan every 5m, Intel every 1h (configurable)
- Watchdog: Monitors for repeated scan failures (possible interference)
- Stop: Clears all intervals, sets state to shutdown

## Pages
1. **Login** (`/`) - Authentication gate, redirects to dashboard after login
2. **Dashboard** (`/`) - Security overview with metrics, recent events, active sessions
3. **Command Center** (`/engine`) - Engine controls, threat level, findings, intel patterns, architecture
4. **Sessions** (`/sessions`) - Agent session monitoring with integrity/anomaly scores
5. **Events** (`/events`) - Security event log with severity/type filtering
6. **Trust Registry** (`/trust`) - Manage trusted/blocked MCP servers
7. **Policies** (`/policies`) - Security policy rules with toggle/create (includes auto-generated intel rules)
8. **Compliance** (`/compliance`) - CMMC/NIST control coverage visualization
9. **Users** (`/users`) - User management with role assignment (admin only)
10. **Audit Trail** (`/audit`) - System activity log with resource type filtering (admin only)
11. **Data Retention** (`/retention`) - Retention policy management with manual purge (admin only)
12. **Alerting** (`/alerts`) - Alert destination configuration and testing (admin/analyst)
13. **Reports** (`/reports`) - Report export, API key management, integration docs

## Data Models
- `organizations` - Multi-tenant organization entities
- `users` - Auth users with roles and org membership
- `sessions` - AI agent sessions with goal integrity and anomaly scores
- `securityEvents` - Security events (goal drift, credential detection, policy violations, etc.)
- `toolCalls` - MCP tool call audit log
- `trustedServers` - MCP server trust registry
- `policyRules` - Security policy rules (seed + auto-generated from threat intel)
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

### Engine (Command Center)
- `GET /engine/status` - Engine state, threat level, task stats, schedule info
- `POST /engine/start` - Start the autonomous engine (admin)
- `POST /engine/stop` - Stop the engine (admin)
- `POST /engine/scan` - Trigger one-shot threat hunt (admin/analyst)
- `POST /engine/intel` - Trigger one-shot intel refresh (admin/analyst)
- `GET /engine/findings` - Latest hunt findings
- `GET /engine/patterns` - Built-in threat intelligence patterns

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

## Key Files
- `server/engine.ts` - Autonomous engine (orchestrator, hunter, intel, scheduler, watchdog)
- `aiglos_autonomous.py` - Original Python engine (reference)
- `shared/schema.ts` - All data models and Zod schemas
- `server/routes.ts` - All API routes
- `server/storage.ts` - Database access layer
- `server/middleware.ts` - Auth, RBAC, audit logging middleware
- `client/src/pages/engine.tsx` - Command Center UI

## Landing Page
- **Route**: `/landing` — standalone vanilla HTML/CSS/JS landing page
- **File**: `client/public/landing.html`
- **Design**: cursor.com aesthetic — warm bg (#F7F7F4), text (#26251E), borders (#E6E5E0), Helvetica Neue system font stack, pill buttons (border-radius: 9999px), dark product panels (#111113)
- **Sections**: Hero with live interceptor feed, logo strip, 3 feature sections (alternating layout), OSS callout, footer
- **No pricing** on this page — pricing lives at `/pricing`

## Pricing Page
- **Route**: `/pricing` — standalone vanilla HTML/CSS/JS pricing page
- **File**: `client/public/pricing.html`
- **Design**: Same cursor.com warm palette, Helvetica Neue system font, pill buttons, sharp-cornered inputs (border-radius: 0)
- **Tiers**: Pro ($39/mo per developer) + Enterprise (custom/contact)
- **Features**: Two-column pricing grid, 6-item FAQ accordion, email signup modal with confirmation flow

## Demo Credentials
- admin / admin123 (full access)
- analyst / analyst123 (monitoring + policies)
- viewer / viewer123 (read-only)

## GitHub Repository
https://github.com/w1123581321345589/aiglos-dashboard
