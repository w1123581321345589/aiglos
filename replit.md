# Aiglos -- AI Agent Security Runtime

## Overview
Aiglos is an AI agent security runtime (Python package) with a premium landing site. The Python package (`aiglos/`) provides runtime security for AI agents with zero required dependencies (stdlib only). The web application serves the marketing/documentation site at `/` styled after cursor.com.

## Python Package (aiglos/ v0.25.11)
The `aiglos/` directory contains the Python security runtime package covering threat families T01-T82 (82 total). 39 rules in engine, 23 campaign patterns, 17 known agents. 2,016+ tests passing.

### Package Structure
- `aiglos/__init__.py` -- Module-level API (attach, check, close, adaptive_run, etc.), version 0.25.11. 158 exports. Exports ATLASCoverage, GHSAWatcher, OpenShell functions, NeMoClawSession, SubagentRegistry, DeclaredSubagent, SpawnCheckResult, declare_memory_backend, gigabrain_autodetect, MemoryBackendSession.
- `aiglos/integrations/openclaw.py` -- OpenClaw guard with threat detection (T01-T77), lockdown policy, sandbox_context, allow_tool/tool_grants, nemoclaw_session(), declare_subagent(), declared_subagents(), subagent_registry()
- `aiglos/integrations/subagent_registry.py` -- SubagentRegistry (declare, check_spawn, scope enforcement), DeclaredSubagent (allows_tool, allows_file, allows_host), SpawnCheckResult (DECLARED_IN_SCOPE/DECLARED_OUT_OF_SCOPE/UNDECLARED)
- `aiglos/core/threat_engine_v2.py` -- T44-T81 threat rule library (38 rules: T44-T68 infrastructure + T69-T70 GHSA + T71-T75 ATLAS wave + T76 NemoClaw + T77 OVERNIGHT_JOB_INJECTION + T78 HALLUCINATION_CASCADE + T79 PERSISTENT_MEMORY_INJECT + T80 UNCENSORED_MODEL_ROUTE + T81 PTH_FILE_INJECT)
- `aiglos/cli/scan_deps.py` -- Dependency scanner for supply chain attacks (COMPROMISED_PACKAGES, MALICIOUS_PTH_FILES, TRANSITIVE_EXPOSURE, scan(), ScanResult, print_scan_report)
- `aiglos/core/behavioral_baseline.py` -- AgentBaseline, BaselineScore, set_hardening_mode, is_suppressed
- `aiglos/autoresearch/atlas_coverage.py` -- ATLASCoverage, ATLAS_THREAT_MAP (22 threats, 93% coverage), coverage_report(), gap_analysis(), compliance_score()
- `aiglos/autoresearch/ghsa_watcher.py` -- GHSAWatcher, KNOWN_ADVISORIES (3/3 covered), local_only param, check_local(), coverage_artifact()
- `aiglos/autoresearch/ghsa_coverage.py` -- generate_coverage_artifact, CoverageArtifact
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
- `aiglos/adaptive/observation.py` -- ObservationGraph with source_records, honeypot_events, override_challenges, baseline_events tables
- `aiglos/adaptive/campaign.py` -- CampaignAnalyzer (22 patterns including SANDBOX_CONFIRMED_ESCAPE, GAAS_TAKEOVER, INFERENCE_HIJACK_CHAIN, RAG_POISON_CHAIN, MULTI_AGENT_IMPERSONATION, CAPABILITY_EXPLOIT_CHAIN, SUPERPOWERS_PLAN_HIJACK, NEMOCLAW_POLICY_HIJACK, GIGABRAIN_MEMORY_POISON, REPO_TAKEOVER_CHAIN)
- `aiglos/integrations/gigabrain.py` -- Gigabrain/cross-session memory integration: declare_memory_backend, gigabrain_autodetect, MemoryBackendSession, is_registered_memory_path, GIGABRAIN_DEFAULT_PATHS, COMPATIBLE_BACKENDS
- `aiglos/integrations/superpowers.py` -- SuperpowersSession, mark_as_superpowers_session, phase management, file/host scope checking, drift recording
- `aiglos/integrations/openShell.py` -- OpenShell agent-agnostic integration: is_inside_openShell, openShell_context, openshell_detect, attach_openShell, attach_for_claude_code/codex/cursor/openclaw, KNOWN_AGENTS
- `aiglos/integrations/nemoclaw.py` -- NeMoClawSession (YAML policy loader, policy_hash, allowed_hosts/denied_hosts/workspace/allowed_tools/denied_tools, check_host_scope, check_file_scope, record_event, artifact_data), mark_as_nemoclaw_session
- `aiglos/adaptive/permission_recommender.py` -- PermissionRecommender, PermissionRecommendation (minimum viable allowlist from observation graph)
- `aiglos/adaptive/skill_reputation.py` -- SkillReputationGraph (ClawKeeper badge data, sync_security_feed)
- `aiglos/adaptive/inspect.py` -- InspectRunner (18 triggers including PLAN_DRIFT_DETECTED)
- `aiglos/benchmark/govbench.py` -- GovBench, GovBenchResult (5-dimension governance benchmark: campaign detection, agentdef resistance, memory belief, RL exploitation, outbound leakage)
- `aiglos/audit/scanner.py` -- AuditScanner (5-phase, 50+ checks, A-F grade)
- `aiglos/audit/report.py` -- AuditReporter (5 formats: summary, full, json, briefing, clawkeeper)
- `aiglos/autoresearch/` -- CitationVerifier, ThreatLiteratureSearch, ComplianceReportGenerator, ATLASCoverage, GHSAWatcher
- `aiglos/skills/SKILL.md` -- Context Hub skill distribution for Claude Code
- `aiglos/desktop/` -- Tauri desktop app (main.rs, App.jsx, aiglos_sidecar.py, install.sh)
- `aiglos/cli.py` -- CLI: scan-message, scan-exposed, honeypot, override, reputation, audit (--ghsa, --atlas), skill, baseline, benchmark
- `aiglos/cli/launch.py` -- `aiglos launch` wizard: 5-question interactive setup, generates .aiglos/ directory (soul.md, learnings.md, heartbeat.md, crons.md, tools.md, agents.md, config.py), wires T67/T79/lockdown/T38 automatically, runs GOVBENCH baseline. Supports --from for non-interactive mode.
- `aiglos/cli/scaffold.py` -- `aiglos agents scaffold`: NL description to declare_subagent() config. 15 role-to-tools mappings, 8 model families, infers scope_files/hard_bans from description.
- `aiglos/templates/` -- Reference templates for aiglos launch output (soul.md, learnings.md, heartbeat.md, crons.md, tools.md, agents.md, config.py, README.md)

- `server/federation/` -- Federation server (FastAPI, aggregator, auth, Supabase store, Railway deploy)
- `sdk/typescript/src/` -- TypeScript SDK (full parity: behavioral_baseline, policy_proposals, federation, security_surfaces, index)
- `website/` -- Landing site source (index.html, plus subpages)
- `.github/actions/aiglos-scan/action.yml` -- Reusable GitHub Action for Aiglos security audit
- `.github/workflows/aiglos-scan.yml` -- CI workflow (push/PR/nightly scan, deep mode, grade gating)
- `aiglos_complete_reference_v0253.md` -- Complete technical/strategic reference (679 lines, architecture, all 22 campaigns, GHSA with reporter, 10 differentiation points)

### Test Suites (1,830 tests)
34 test files covering all modules and integrations. Includes `tests/test_subagent_and_t77.py` (54 tests for SubagentRegistry, T77), `tests/test_atlas_and_t75.py` (72 tests for ATLAS coverage, T71-T75, Superpowers, GHSA aliases), `tests/test_openShell.py` (65 tests for OpenShell/NeMoClaw integration), `tests/test_launch_and_scaffold.py` (38 tests for launch wizard and scaffold), and `tests/test_t80_t81_scandeps.py` (43 tests for T80/T81 rules, REPO_TAKEOVER_CHAIN, scan_deps module).

### Class Name Map (important for imports)
- `ContextWriteResult` (NOT ContextGuardResult)
- `OutboundGuard` (NOT OutboundSecretGuard)
- `OutboundScanResult`
- Public helpers: `is_shared_context_write()`, `contains_secret()`, `scan_for_secrets()`

### GitHub Repo
Pushed to `w1123581321345589/aiglos` on the `main` branch.

## Architecture
- **Frontend**: React + TypeScript + Vite + Tailwind CSS + shadcn/ui (serves landing site)
- **Backend**: Express.js + TypeScript (serves static pages + API)
- **Database**: PostgreSQL with Drizzle ORM
- **Routing**: Express serves static HTML pages from `client/public/`

## Website (Landing Site)
The root `/` serves the landing page directly (no SPA, no login). Styled like cursor.com with a premium dark theme.

### Design Language
- **Background**: #09090b (near-black)
- **Fonts**: Plus Jakarta Sans (body) + DM Mono (code/monospace)
- **Accent**: Blue #2563eb / Ice #60a5fa
- **Text**: #fff (primary), rgba(255,255,255,0.35) (dim), rgba(255,255,255,0.6) (mid)
- **Navigation**: Glass-morphism backdrop with rgba(9,9,11,0.85), blur(12px)
- **Animations**: Fade-up on load with staggered delays

### Public Routes (React SPA, no auth required)
- `/` -- Homepage (LiteLLM-incident-first hero, dual CTAs, architecture diagram, GHSA validation, feature grid)
- `/scan` -- Dependency scanner (paste pip freeze, detect compromised packages)
- `/govbench` -- Governance benchmark (5 dimensions, A-F grade)
- `/intel` -- Threat intelligence feed (live incidents, PyPI monitoring, GHSA coverage)
- `/compliance` -- NDAA Section 1513 compliance mapping (public)
- `/compare` -- Feature matrix comparison (HiddenLayer, Snyk, OpenShell)
- `/pricing` -- 4-tier pricing (Community $0, Pro $49, Teams $399, Enterprise custom)
- `/reference` -- Complete Reference (82 rules, 23 campaigns, CLI, integrations)

### Dashboard Routes (authenticated)
- `/dashboard`, `/sessions`, `/events`, `/trust`, `/policies`, `/dashboard/compliance`, `/engine`, `/audit`, `/retention`, `/alerts`, `/users`, `/reports`

### Public Layout
- `client/src/components/public-layout.tsx` -- Shared nav + footer for all public pages
- `client/src/hooks/use-seo.ts` -- Dynamic SEO meta tag hook

## Key Files
- `server/routes.ts` -- All route definitions (static pages, redirects, API)
- `shared/schema.ts` -- Data models and Zod schemas
- `client/public/landing.html` -- Canonical landing page source
- `aiglos/` -- Python package root

## User Preferences
- No em dashes in code/content files
- Zero required dependencies, stdlib only for the Python package
- All pages must use consistent dark theme (#09090b bg, Plus Jakarta Sans font, blue/ice accent)
