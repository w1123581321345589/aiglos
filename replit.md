# Aiglos Security Dashboard

## Overview
Enterprise-grade web dashboard for the Aiglos AI Agent Security Runtime. Provides real-time monitoring, event logging, trust management, policy configuration, CMMC compliance tracking, autonomous threat scanning. Serves marketing/static pages and an authenticated dashboard.

## Python Package (aiglos/ v0.25.22)
The `aiglos/` directory contains the Python security runtime package covering threat families T01-T95 (95 total). 2,064 tests passing. 27 campaign patterns, 32 known agents. GovBench 6-dimension governance benchmark.

### Package Structure
- `aiglos/__init__.py` -- Module-level API (attach, check, close, adaptive_run, etc.), version 0.25.22. Exports T44-T95 match functions, Phantom integration, ForensicStore, OllamaGuard.
- `aiglos/integrations/openclaw.py` -- OpenClaw guard with threat detection (T01-T91), lockdown policy, sandbox_context, allow_tool/tool_grants, normalize_shell_command
- `aiglos/core/threat_engine_v2.py` -- T44-T95 threat rule library (52 rules: T44-T68 infrastructure + T69-T70 GHSA + T71-T75 ATLAS + T76-T82 NemoClaw/memory/uncensored + T83-T89 protocol/identity/VCS + T90 dynamic tool registration + T91 sycophancy + T92 scanner compromise + T93 credential in tool args + T94 provider policy rejection + T95 cross-trust-boundary inject)
- `aiglos/integrations/ollama.py` -- OllamaGuard runtime security for Ollama/LM Studio local model deployments (attach_for_ollama, lmstudio_guard, provider_dependency_risk)
- `aiglos/core/behavioral_baseline.py` -- AgentBaseline, BaselineScore, set_hardening_mode, is_suppressed
- `aiglos/autoresearch/wiki.py` -- ThreatWiki engine: INGEST, PROPOSE, LINT, EVOLVE (999 lines). Compiles raw intel into wiki pages and machine-readable T-rule proposals
- `aiglos/autoresearch/feeds.py` -- Feed connectors: NVD CVE, GHSA, MITRE ATLAS, RSS (656 lines). Normalizes sources to RawItem envelope
- `aiglos/autoresearch/SCHEMA.md` -- Governing schema for wiki page types, operations, cross-referencing, proposal promotion workflow
- `aiglos/autoresearch/atlas_coverage.py` -- ATLASCoverage, ATLAS_THREAT_MAP (22 threats, 93% coverage)
- `aiglos/autoresearch/ghsa_watcher.py` -- GHSAWatcher, KNOWN_ADVISORIES (3/3 covered)
- `aiglos/integrations/hermes.py` -- Hermes integration guard with trajectory signing
- `aiglos/integrations/multi_agent.py` -- AgentDefGuard, MultiAgentRegistry, SessionIdentityChain
- `aiglos/integrations/memory_guard.py` -- Memory write guard (T31) with C2 channel corpus signals
- `aiglos/integrations/rl_guard.py` -- RL feedback guard (T39)
- `aiglos/integrations/http_intercept.py` -- HTTP interception engine (T25, T37, T22, T19/T20, T35, T36)
- `aiglos/integrations/subprocess_intercept.py` -- Subprocess interception (3-tier, 12 threat rules)
- `aiglos/integrations/context_guard.py` -- T40 SHARED_CONTEXT_POISON
- `aiglos/integrations/outbound_guard.py` -- T41 OUTBOUND_SECRET_LEAK
- `aiglos/integrations/honeypot.py` -- T43 HONEYPOT_ACCESS
- `aiglos/integrations/override.py` -- OverrideManager (6-char codes, 120s expiry, 3 attempts)
- `aiglos/adaptive/campaign.py` -- CampaignAnalyzer (27 patterns including PHANTOM_COMPROMISE_CHAIN, MERCOR_BREACH_CHAIN)
- `aiglos/adaptive/skill_reputation.py` -- SkillReputationGraph
- `aiglos/benchmark/govbench.py` -- GovBench, GovBenchResult (6-dimension: campaign detection, agentdef resistance, memory belief, RL exploitation, outbound leakage, anti-sycophancy)
- `aiglos/audit/scanner.py` -- AuditScanner (5-phase, 50+ checks, A-F grade)
- `aiglos/audit/report.py` -- AuditReporter (5 formats)
- `aiglos/cli.py` -- CLI: scan-message, scan-exposed, honeypot, override, reputation, audit, skill, baseline, benchmark

### GitHub Repo
Pushed to `w1123581321345589/aiglos` on the `main` branch.

## Architecture
- **Frontend**: React + TypeScript + Vite + Tailwind CSS + shadcn/ui
- **Backend**: Express.js + TypeScript
- **Database**: PostgreSQL with Drizzle ORM
- **Routing**: wouter (frontend), Express (backend API)
- **State**: TanStack React Query
- **Security**: Helmet, express-rate-limit, session-based auth
- **Real-time**: WebSocket server for event streaming
- **Autonomous Engine**: In-process threat scanner (server/engine.ts)

## Data Models (Simplified Schema)
- `users` - Auth users (id, username, password)
- `sessions` - AI agent sessions with goal integrity and anomaly scores
- `securityEvents` - Security events (goal drift, credential detection, policy violations, etc.)
- `toolCalls` - MCP tool call audit log
- `trustedServers` - MCP server trust registry
- `policyRules` - Security policy rules (seed + auto-generated from threat intel)

Note: organizations, auditLogs, alertDestinations, dataRetentionPolicies, apiKeys tables were removed in the Task #9 schema simplification.

## Pages
1. **Login** (`/auth`) - Authentication gate
2. **Dashboard** (`/`) - Security overview with metrics, recent events, active sessions
3. **Command Center** (`/engine`) - Engine controls, threat level, findings, intel patterns
4. **Sessions** (`/sessions`) - Agent session monitoring
5. **Events** (`/events`) - Security event log with severity/type filtering
6. **Trust Registry** (`/trust`) - Manage trusted/blocked MCP servers
7. **Policies** (`/policies`) - Security policy rules
8. **Compliance** (`/compliance`) - CMMC/NIST control coverage

## Autonomous Engine (server/engine.ts)
5 Hunt Modules: Credential Scan, Injection Hunt, Behavioral Trends, Policy Trends, Server Exposure.
8 Threat Intelligence Patterns (tp-001 through tp-008).
Engine methods: start(), stop(), runScan(), runIntel(), getStatus(), getFindings(), getThreatPatterns().

## Website (Static Pages)
- **Design**: Dark theme (#09090b bg), Plus Jakarta Sans + DM Mono fonts, blue (#2563eb) accent
- **Routes**: Static HTML pages served from `client/public/`
  - `/landing` and `/aiglos` -- hero with live interceptor feed, pricing
  - `/changelog` -- v0.19 through v0.25.22 changelog
  - `/govbench-paper` -- GOVBENCH 6-dimension governance benchmark paper
  - `/compare/clawkeeper` -- competitive comparison
  - `/tutorial-github-actions` -- CI integration tutorial
  - `/tutorial-openclaw-hardening` -- OpenClaw hardening tutorial
  - `/tutorial-advanced` -- Advanced topics
  - `/docs` -- documentation
  - `/pricing` -- pricing tiers (Pro $39/dev/mo + Enterprise)

## API Routes
All prefixed with `/api/`:

### Auth
- `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`, `POST /auth/register`

### Monitoring
- `GET /dashboard/stats`, `GET /sessions`, `GET /sessions/:id`
- `GET /events`, `GET/POST /trust`, `PATCH /trust/:id`
- `GET/POST /policies`, `PATCH /policies/:id`, `GET /compliance`

### Engine
- `GET /engine/status`, `POST /engine/start`, `POST /engine/stop`
- `POST /engine/scan`, `POST /engine/intel`
- `GET /engine/findings`, `GET /engine/patterns`

### Ingest (auth required)
- `POST /ingest/event`, `POST /ingest/session`
- `WS /ws` -- WebSocket real-time event streaming

## Demo Credentials
- admin / admin123 (full access)

## Key Files
- `server/engine.ts` - Autonomous engine
- `shared/schema.ts` - Data models and Zod schemas
- `server/routes.ts` - All API routes
- `server/storage.ts` - Database access layer
- `server/middleware.ts` - Auth middleware (simplified)
- `server/auth.ts` - Password hashing utilities

## GitHub Repository
https://github.com/w1123581321345589/aiglos-dashboard
