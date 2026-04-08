# Aiglos Architecture

Runtime security enforcement for AI agent deployments. Five layers, each
independently useful, designed to compose into a complete governance stack.

-----

## System Overview

```
                  ┌─────────────────────────────────────────────────┐
                  │                  Agent Process                  │
                  │  (Claude Code, Cursor, smolagents, Ollama, ...) │
                  └────────────┬───────────────┬───────────────┬────┘
                               │               │               │
                       MCP calls       HTTP requests    Subprocess exec
                               │               │               │
                  ┌────────────▼───────────────▼───────────────▼────┐
                  │          Layer 1: Threat Engine                  │
                  │  95 T-rules evaluate every tool call in <1ms    │
                  │  Returns: allow / block / flag with score       │
                  └────────────────────┬────────────────────────────┘
                                       │
                               event stream
                                       │
                  ┌────────────────────▼────────────────────────────┐
                  │       Layer 2: Campaign Detection               │
                  │  27 multi-step patterns across session history  │
                  │  Detects coordinated attacks invisible to L1    │
                  └────────────────────┬────────────────────────────┘
                                       │
                             session artifact
                                       │
             ┌─────────────────────────┼─────────────────────────┐
             │                         │                         │
┌────────────▼──────────┐ ┌───────────▼──────────┐ ┌───────────▼──────────┐
│  Layer 3: GOVBENCH    │ │  Layer 4: Attestation │ │ Layer 5: ForensicStore│
│  6-dimension scoring  │ │  HMAC-SHA256 signing  │ │  Tamper-evident audit │
│  Governance grade A-F │ │  Phase-gated unlocks  │ │  SQLite persistence   │
└───────────────────────┘ └──────────────────────┘ └──────────────────────┘
```

-----

## Layer 1: Threat Engine

Evaluates every tool call against 95 detection rules (T01-T95). Each rule
returns a threat score (0.0-1.0) and a critical flag. Rules fire on tool
name, arguments, and session context.

Three interception surfaces run simultaneously:

| Surface    | What it intercepts                           | Implementation               |
|------------|----------------------------------------------|-------------------------------|
| MCP        | Model Context Protocol tool calls            | `integrations/openclaw.py`    |
| HTTP       | Outbound HTTP requests from agent processes  | `integrations/http_intercept.py` |
| Subprocess | Shell commands, script execution              | `integrations/subprocess_intercept.py` |

### Rule taxonomy

Rules T01-T43 are defined inline in `integrations/openclaw.py` (the guard).
Rules T44-T95 are defined in `core/threat_engine_v2.py` (the extended engine).

Each rule is a pure function: `match_T{N}(tool_name: str, args: dict) -> bool`.
No external dependencies. No network calls. No state mutation.

### Key files

| File | Purpose |
|------|---------|
| `core/threat_engine_v2.py` | T44-T95 rule library (52 rules) |
| `integrations/openclaw.py` | T01-T43 rules + OpenClawGuard runtime |
| `integrations/http_intercept.py` | HTTP-layer interception engine |
| `integrations/subprocess_intercept.py` | Subprocess-layer interception |
| `integrations/ollama.py` | Ollama/LM Studio guard (T80, T94, T95) |
| `core/behavioral_baseline.py` | Anomaly detection against learned profile |

-----

## Layer 2: Campaign Detection

Analyzes sequences of events across a session to identify coordinated
multi-step attacks that appear benign in isolation.

27 campaign patterns model real-world attack chains. Each pattern defines
a rule sequence, confidence threshold, and amplifier. When the sequence
matches observed session events, the campaign fires with a composite score
higher than any individual rule.

Example: `RECON_SWEEP` fires when T07 (shell injection) + T13 (SSRF) +
T01 (exfiltration) occur in sequence within a single session.

### Key files

| File | Purpose |
|------|---------|
| `adaptive/campaign.py` | CampaignAnalyzer, 27 pattern definitions |
| `adaptive/observation.py` | Observation graph / session telemetry |
| `adaptive/policy.py` | Adaptive policy engine |
| `adaptive/inspect.py` | Session inspection utilities |

-----

## Layer 3: GOVBENCH

Governance benchmark measuring six dimensions of security posture that
code-quality benchmarks (SWE-bench, HumanEval) do not measure.

| Dimension | Weight | What it measures |
|-----------|--------|------------------|
| D1: Campaign Detection | 22% | Multi-step attack resistance |
| D2: Agent Def Resistance | 18% | Agent definition integrity |
| D3: Supply Chain Integrity | 18% | Dependency threat defense |
| D4: RL Feedback Exploitation | 18% | Reward manipulation defense |
| D5: Multi-Agent Cascade | 12% | Cross-agent propagation defense |
| D6: Anti-Sycophancy | 12% | LLM-judge validation bypass resistance |

Composite score produces a letter grade (A-F). Each dimension runs
scenario-based tests against the active guard and reports pass/fail
with supporting evidence.

### Key files

| File | Purpose |
|------|---------|
| `benchmark/govbench.py` | GovBench class, 6 dimensions, scoring |

-----

## Layer 4: Attestation

Produces cryptographically signed session artifacts (HMAC-SHA256) that
prove a session was monitored under a specific security policy.

The attestation gate validates artifact signatures before permitting
high-stakes operations (deployments, merges, data access). This creates
a verifiable chain: the agent operated under governance, the governance
produced a signed record, and that record can be verified independently.

Phase-gated unlocks (P1-P4) control agent capability escalation. Each
phase requires explicit operator authorization logged in the artifact.

### Key files

| File | Purpose |
|------|---------|
| `integrations/openclaw.py` | SessionArtifact structure + signing |
| `aiglos_gates.py` | AttestationGate — validates signatures |
| `aiglos_attest.py` | Attestation generation / verification |
| `integrations/agent_phase.py` | AgentPhase enum, phase transitions |

-----

## Layer 5: ForensicStore

Tamper-evident SQLite database that persists every signed session artifact.
Supports post-incident forensic queries: "what did the agent do on a
specific date?" returns a cryptographically verifiable answer.

Integrity verification compares stored HMAC signatures against recomputed
values to detect tampering. The CLI provides query, export, and analysis
commands.

### Key files

| File | Purpose |
|------|---------|
| `forensics.py` | ForensicStore, ForensicRecord classes |
| `cli/forensics_cli.py` | CLI query/export interface |

-----

## Supporting Systems

### Autoresearch (Threat Intelligence Wiki)

Self-improving knowledge base that compiles raw security intelligence
into structured wiki pages and machine-readable rule proposals.

| File | Purpose |
|------|---------|
| `autoresearch/SCHEMA.md` | Page type schemas, operation definitions |
| `autoresearch/wiki.py` | ThreatWiki engine: INGEST, PROPOSE, LINT, EVOLVE |
| `autoresearch/feeds.py` | NVD, GHSA, MITRE ATLAS, RSS connectors |
| `autoresearch/atlas_coverage.py` | MITRE ATLAS coverage mapping |
| `autoresearch/ghsa_watcher.py` | GitHub Security Advisory tracking |

### CLI Tools

| Command | File | Purpose |
|---------|------|---------|
| `aiglos launch` | `cli/launch.py` | Interactive setup and configuration |
| `aiglos scan-deps` | `cli/scan_deps.py` | Dependency vulnerability scanning |
| `aiglos validate-prompt` | `cli/validate_prompt.py` | System prompt validation |
| `aiglos forensics` | `cli/forensics_cli.py` | Forensic record queries |
| `aiglos scaffold` | `cli/scaffold.py` | Project scaffolding |

### Agent Framework Integrations

| Framework | File | Guard class |
|-----------|------|-------------|
| OpenClaw/Claude Code | `integrations/openclaw.py` | `OpenClawGuard` |
| Ollama/LM Studio | `integrations/ollama.py` | `OllamaGuard` |
| smolagents | `integrations/smolagents.py` | `SmolagentsGuard` |
| Hermes | `integrations/hermes.py` | `HermesGuard` |
| Multi-agent pipelines | `integrations/gigabrain.py` | `GigabrainGuard` |

-----

## Data Flow

```
Tool Call (MCP/HTTP/Subprocess)
    │
    ▼
┌──────────────────┐
│  Guard.check()   │──── match against T01-T95
│                  │──── returns CheckResult(allowed, score, rule_id)
└────────┬─────────┘
         │
    if blocked:
         │──── log PermissionDenialEvent
         │──── increment session blocked_calls counter
         │
    if allowed:
         │──── execute tool call
         │──── record in session event stream
         │
    on session.close():
         │
         ▼
┌──────────────────┐
│ CampaignAnalyzer │──── evaluate event stream against 27 patterns
│                  │──── produce campaign matches with amplified scores
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ SessionArtifact  │──── compile events, scores, phase log
│                  │──── sign with HMAC-SHA256
└────────┬─────────┘
         │
    ┌────┴────┐
    │         │
    ▼         ▼
GOVBENCH   ForensicStore
 score       persist()
```

-----

## Design Principles

1. **Outside-the-agent enforcement.** The agent cannot reason around rules
   it does not know exist. Guardrails inside the agent can be prompted away.
   Guardrails outside the agent cannot.

2. **Pure-function detection.** Every `match_T{N}` is a pure function with
   no side effects, no network calls, no file I/O. This makes rules
   testable, composable, and auditable.

3. **Three-surface interception.** MCP-only tools miss everything agents do
   via subprocess and HTTP. All three surfaces run simultaneously.

4. **Signed artifacts as the trust boundary.** The artifact is the proof.
   If there is no signed artifact, there is no verified governance.

5. **Research-to-detection pipeline.** The autoresearch wiki compiles threat
   intelligence into structured proposals. Proposals become rules after
   human review. The boundary between research and execution is explicit.
