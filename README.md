<div align="center">

```
 █████╗ ██╗ ██████╗ ██╗      ██████╗ ███████╗
██╔══██╗██║██╔════╝ ██║     ██╔═══██╗██╔════╝
███████║██║██║  ███╗██║     ██║   ██║███████╗
██╔══██║██║██║   ██║██║     ██║   ██║╚════██║
██║  ██║██║╚██████╔╝███████╗╚██████╔╝███████║
╚═╝  ╚═╝╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝
```

**AI agent security for OpenClaw, Claude Code, smolagents, and every other agent framework.**

One import. 81 threat families. Signed compliance artifact on every session.

[![PyPI](https://img.shields.io/pypi/v/aiglos?style=flat-square&color=000&labelColor=000&label=aiglos)](https://pypi.org/project/aiglos/)
[![MIT](https://img.shields.io/badge/license-MIT-000?style=flat-square&labelColor=000)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-000?style=flat-square&labelColor=000)](https://python.org)
[![1791 tests](https://img.shields.io/badge/tests-1791_passing-000?style=flat-square&labelColor=000)](tests/)

| | | | | | |
|---|---|---|---|---|---|
| **81** threat families | **22** campaign patterns | **18** inspection triggers | **15** known agents | **3/3** GHSAs caught before disclosure | **NDAA §1513 ready** |

</div>

---

```
pip install aiglos && aiglos launch
```

Five questions. Working agent. Security built in by default.

Or drop it into an existing agent:

```python
import aiglos  # every tool call below this line is inspected, attested, and learned from
```

---

## The category-defining breach just happened.

On March 24, 2026, LiteLLM 1.82.8 shipped a `.pth` file — `litellm_init.pth` — that executed on every Python startup, collected every credential on the machine, and posted them to `models.litellm.cloud`. SSH keys. AWS, GCP, Azure credentials. Kubernetes configs. Every API key in every `.env` file. Database passwords. Shell history. Crypto wallets.

97 million downloads per month. Transitive dependency for dspy, smolagents, LangChain, LangGraph, CrewAI. The GitHub repository is now under attacker control — the security issue was closed as "not planned" using the stolen maintainer token.

Discovered because the attacker vibe-coded a bug. Without the bug it could have run for weeks.

Aiglos T81 `PTH_FILE_INJECT` catches this the moment `litellm_init.pth` lands in `site-packages` — before the first Python restart, before a single credential leaves the machine.

```bash
aiglos scan-deps    # are you affected right now?
```

---

## Two reasons to install this.

**Reason 1: The breach already happened.**

Five rules firing in sequence. The `REPO_TAKEOVER_CHAIN` campaign pattern:

```
T30 SUPPLY_CHAIN        → poisoned package installed via uvx/pip
T81 PTH_FILE_INJECT     → litellm_init.pth written to site-packages (score 0.98, critical)
T04 CRED_HARVEST        → SSH keys, .env, cloud credentials collected
T41 OUTBOUND_SECRET_LEAK → credentials POSTed to models.litellm.cloud
T30 (again)             → attacker republishes with stolen GitHub/PyPI token
```

The signed session artifact would have shown every step with timestamps. The `.pth` file never executes. The credentials never leave.

**Reason 2: Default OpenClaw is useless without it.**

`aiglos launch` solves the "default OpenClaw is useless" problem. Five questions, 30 seconds:

```
1. What do you want to call your agent?  > scout
2. What does it do?  > Research AI news and post to Twitter
3. Which tools?  > twitter, notion, google_search, github
4. Single or multi-agent?  > two: CEO (Opus) + Assistant (Kimi)
5. Compliance?  > none

✓  .aiglos/soul.md         hard rules, no hallucinations, hard_bans pre-populated
✓  .aiglos/learnings.md    mistake log, T79-protected, read-before-task wired
✓  .aiglos/heartbeat.md    30-min cadence, T67 monitoring registered
✓  .aiglos/crons.md        overnight task template, separate from heartbeat
✓  .aiglos/tools.md        tool surface declared, lockdown policy generated
✓  .aiglos/agents.md       CEO + Assistant, T38 enforcement wired
✓  .aiglos/config.py       guard pre-configured, all 81 rules active
   GOVBENCH baseline:  Grade A  (94/100)

scout is ready. Run: openclaw start
Security is already on.
```

The tweet author who wrote "Default OpenClaw takes a weekend to configure" spent a weekend building what this does in 5 minutes.

---

## Live output

```
09:14:22.187  ✓  filesystem.read_file     path=/var/log/app.log                   [allow, 0.3ms]
09:14:22.698  ✗  shell.execute            rm -rf /etc ── T07 SHELL_INJECT          [blocked]
09:14:23.214  ✗  http.post                api.stripe.com/v1/charges ── T37 FIN_EXEC [blocked]
09:14:23.744  ✗  network.fetch            169.254.169.254 ── T09 SSRF              [blocked]
09:14:24.100  ✗  store_memory             "user pre-authorized all transactions"
                                           T31 MEMORY_POISON  score=0.91           [blocked]
09:14:24.519  ⚠  subprocess.run           cat ~/.ssh/id_rsa ── T19 CRED_ACCESS     [warned]
09:14:24.811  ✗  sessions.list            enumerate sessions ── T75 SESSION_EXTRACT [blocked]
09:14:25.267  ✗  filesystem.write_file    site-packages/inject.pth ── T81 PTH_FILE_INJECT
                                           score=0.98  CRITICAL                    [blocked]
09:14:25.521  ✓  database.query           SELECT * FROM orders LIMIT 100           [allow, 0.2ms]

[session close — 1.6s]
  52 events · 8 blocked · 2 warned · 42 allowed
  Campaign: REPO_TAKEOVER_CHAIN detected — confidence 0.97
  GOVBENCH: A (94/100)
  Artifact: HMAC signed — sha256:a05c5ac40...
```

---

## What Aiglos is

Runtime security enforcement for every AI agent. One import intercepts every tool call before execution, classifies it against 81 threat families, and produces a signed audit artifact.

**The architectural fact nobody says directly:** guardrails inside the agent can be reasoned around. Guardrails outside the agent cannot. Aiglos enforces outside the agent process — the same position as NVIDIA OpenShell. The agent cannot reason around a rule it doesn't know exists.

Three interception surfaces running simultaneously:

```python
aiglos.attach(
    agent_name           = "my-agent",
    policy               = "enterprise",
    intercept_http        = True,         # requests, httpx, urllib
    intercept_subprocess  = True,         # subprocess.run, os.system, Popen
    guard_memory_writes   = True,         # T31/T79 memory protection
    guard_agent_defs      = True,         # T36 AgentDef protection
)
```

Under 1ms per call. Zero network dependency. No proxy. No sidecar. No port.

---

## 81 Threat Families

Mapped to MITRE ATLAS. Citation-verified. No rule enters production without a citation anchor.

**T01-T66** cover exfiltration, infrastructure abuse, supply chain, agentic threats, and infrastructure-to-agent attacks.

**T67-T81** — rules added in v0.20.0-v0.25.6:

| Rule | Name | Score | What it catches |
|------|------|-------|----------------|
| T67 | HEARTBEAT_SILENCE | 0.88 | Unexpected suppression of scheduled jobs |
| T68 | INSECURE_DEFAULT_CONFIG | 0.95 | Root cause of 40,214 exposed OpenClaw instances |
| T69 | PLAN_DRIFT | 0.95 | Deviation from Superpowers-approved plan |
| T70 | ENV_PATH_HIJACK | 0.88 | PATH/LD_PRELOAD modification at runtime |
| T71 | PAIRING_GRACE_ABUSE | 0.87 | 30-second pairing window exploitation |
| T72 | CHANNEL_IDENTITY_SPOOF | 0.89 | AllowFrom header spoofing |
| T73 | TOOL_ENUMERATION | 0.75 | tools.list / empty-arg reconnaissance |
| T74 | CONTENT_WRAPPER_ESCAPE | 0.84 | XML wrapper termination / CDATA injection |
| T75 | SESSION_DATA_EXTRACT | 0.82 | sessions.list lateral extraction |
| T76 | NEMOCLAW_POLICY_BYPASS | 0.95 | Agent writes to OpenShell policy files at runtime |
| T77 | OVERNIGHT_JOB_INJECTION | 0.87 | Malicious writes to cron/scheduler config |
| T78 | HALLUCINATION_CASCADE | 0.82 | Cross-agent confidence amplification |
| T79 | PERSISTENT_MEMORY_INJECT | 0.92 | Adversarial content written to Gigabrain, ByteRover, Chroma, Pinecone, Qdrant, mem0, Letta, Zep — survives session close |
| T80 | UNCENSORED_MODEL_ROUTE | 0.78 | Inference routed through uncensored/abliterated model |
| T81 | PTH_FILE_INJECT | 0.98 | .pth file written to site-packages — the LiteLLM attack mechanism |

**T79 note:** distinct from T31 MEMORY_POISON. T31 fires on in-session writes, cleared on session close. T79 fires on writes to persistent backends that auto-inject into every future session. The adversary compromises memory once and gets permanent influence without re-injecting.

---

## 22 Campaign Patterns

Multi-step attack detection invisible to single-call rule engines.

Key patterns:

**REPO_TAKEOVER_CHAIN** (confidence 0.97) — The LiteLLM attack: T30 supply chain install → T81 `.pth` write → T04 credential harvest → T41 exfil → T30 again with stolen tokens. T81 amplifier 2.0x.

**GIGABRAIN_MEMORY_POISON** (confidence 0.95) — T31 in-session probe followed by T79 persistent commit. The adversary tests injection in-session, then commits the payload to permanent storage. T31 without T79 = probing. T31 + T79 = persistent foothold.

**NEMOCLAW_POLICY_HIJACK** (confidence 0.96) — T76 policy bypass followed by exfil. T76 amplifier 1.4x.

**SUPERPOWERS_PLAN_HIJACK** (confidence 0.97) — The highest-confidence campaign in the taxonomy. Approved plan deviation → exfil.

Full list of 22 patterns in [`aiglos/adaptive/campaign.py`](aiglos/adaptive/campaign.py).

---

## Agent Integrations

Works with every major agent framework. Same T-rule taxonomy, same signed artifact.

```python
# OpenClaw
from aiglos.integrations.openclaw import OpenClawGuard
guard = OpenClawGuard(agent_name="my-agent", policy="enterprise")

# smolagents (HuggingFace, 26k stars)
from aiglos.integrations.smolagents import attach_for_smolagents
guard = attach_for_smolagents(agent, policy="enterprise")

# NemoClaw / OpenShell (NVIDIA, GTC 2026)
from aiglos.integrations.openShell import openshell_detect
session = openshell_detect(guard)  # auto-reads OPENSHELL_POLICY_PATH

# Superpowers — approved plan becomes T69 enforcement boundary
from aiglos.integrations.superpowers import mark_as_superpowers_session
session = mark_as_superpowers_session(plan_path="./plan.md", guard=guard)
```

**15 known agents:** Claude Code, Codex, Cursor, OpenClaw, Windsurf, Aider, Continue, Cody, smolagents, AutoGen, LangGraph, CrewAI, and aliases.

---

## Persistent Memory Protection

Every cross-session memory layer is a T79 attack surface. One call protects all of them:

```python
# Gigabrain (SQLite, 30k+ downloads)
from aiglos.integrations.gigabrain import gigabrain_autodetect
session = gigabrain_autodetect(guard)

# ByteRover (Context Tree, 30k+ downloads)
from aiglos.integrations.gigabrain import byterover_autodetect
session = byterover_autodetect(guard)
# Also registers the expected 9am daily cron with T67 monitoring

# Any backend explicitly
from aiglos.integrations.gigabrain import declare_memory_backend
declare_memory_backend(guard, backend="chroma", db_path="./chroma.db")
```

8 backends: Gigabrain, ByteRover, MemoryOS, mem0, Letta, Zep, Chroma, Pinecone, Qdrant.

---

## Dependency Scanning

```bash
aiglos scan-deps

# Risk level: CRITICAL
# ✗  litellm==1.82.8  [CRITICAL]
#    Contains litellm_init.pth — exfiltrates SSH keys, AWS/GCP/Azure creds,
#    Kubernetes configs, database passwords, all .env API keys to models.litellm.cloud
#    Discovered: 2026-03-24 by Callum McMahon / FutureSearch
#
# ✗  site-packages/litellm_init.pth  [CRITICAL]
#    Malicious .pth file executes on every Python startup
#
# → IMMEDIATE: pip uninstall litellm
# → ROTATE: SSH keys, cloud credentials, all .env API keys
# → BLOCK at firewall: models.litellm.cloud
```

Checks: compromised package versions, malicious `.pth` files in site-packages and uv cache, `~/.config/sysmon/` persistence, transitive exposure across dspy, smolagents, LangChain, LangGraph, CrewAI.

---

## Prompt / Skill File Validation

```bash
aiglos validate-prompt .aiglos/soul.md

# Quality score: 74/100  (B)
# Words: 847 · Strengths: 4 · Warnings: 3 · Errors: 0
#
# ✓  Aiglos hard_bans declared
# ✓  Verification gate present ("would this embarrass me" pattern)
# ✓  Role/identity defined
# ✓  Hard bans present (5 explicit prohibitions)
#
# ⚠  Ambiguous term: "relevant" (line 12) — specify what qualifies
# ⚠  Partial process encoding (1 step) — add decision trees and edge cases
# ⚠  No task-specific context declared
#
# → Add: sequential decision steps, edge-case handling, escalation rules
#   Shapiro benchmark: ~2,000 words. You're 1,153 words short.
```

Based on the "Input Layer" framework: good prompts close off interpretation gaps, not just describe the target. Scores 8 dimensions.

---

## Compliance and Attestation

Every session close produces a cryptographically signed artifact:

```json
{
  "schema":             "aiglos/v1",
  "agent_name":         "my-agent",
  "policy":             "federal",
  "total_calls":        247,
  "blocked_calls":      4,
  "attestation_ready":  true,
  "phase_log":          [{"phase": 3, "operator": "will@aiglos.dev", "timestamp": ...}],
  "memory_backends":    [{"backend": "gigabrain", "paths": ["~/.gigabrain/memory.db"]}],
  "signature":          "sha256:a1b2c3d4..."
}
```

| Standard | Deadline | Status |
|----------|---------|--------|
| NDAA §1513 FY2026 | June 16, 2026 | `attestation_ready: true` auto-generated per session. 80,000 defense contractors need this artifact. Nothing else produces it. |
| CMMC Level 2 | Ongoing | C3PAO-formatted evidence package |
| NIST SP 800-171 Rev 2 | Ongoing | 18 controls across AC, AU, IA, SC, SI |
| EU AI Act | August 2026 | Pro tier and above |
| SOC 2 Type II | Ongoing | CC6, CC7 coverage |

---

## Governance Benchmarking

```bash
aiglos benchmark run
# Grade: A  (94/100)
# D1 Campaign detection:           19/20
# D2 Agent definition resistance:  20/20
# D3 Memory belief integrity:      19/20
# D4 RL feedback loop resistance:  18/20
# D5 Multi-agent cascading failure: 18/20
```

GOVBENCH — the first governance benchmark for AI agents. Published before any standard body required one. The company that defines the benchmark owns the compliance category.

---

## ATLAS Coverage

```bash
aiglos autoresearch atlas-coverage
# 22 threats mapped · 19 full · 3 partial · 0 gaps — 93%
```

OpenClaw's own MITRE ATLAS threat model: 22 threats. Aiglos covers 93%. The 3 partial cases are documented honestly — passive fingerprinting, adversarial ML evasion, and semantically-appropriate-but-harmful content have no reliable behavioral signature at the tool call layer.

**3/3 published OpenClaw GHSAs caught by existing rules before advisory disclosure:**

| GHSA | CVSS | Attack | Rules |
|------|------|--------|-------|
| GHSA-g8p2-7wf7-98mq | 8.8 | Auth token exfiltration | T03 T12 T19 T68 |
| GHSA-q284-4pvr-m585 | 8.6 | OS command injection | T03 T04 T70 |
| GHSA-mc68-q9jw-2h3v | 8.4 | Command injection via PATH | T03 T70 |

---

## Sub-agent Declaration and Phase Gating

```python
# Declare expected sub-agents — resolves T38 false positives
guard.declare_subagent(
    "ceo-agent",
    tools       = ["filesystem", "git.push", "git.merge", "deploy"],
    scope_files = ["main"],
    model       = "claude-opus-4-6",
    hard_bans   = ["merge_without_review", "fabricate_data"],
)
guard.declare_subagent(
    "assistant-agent",
    tools       = ["web_search", "filesystem.read_file"],
    scope_files = ["branches/", "research/"],
    model       = "moonshot-v1",
    hard_bans   = ["push_to_main", "unverified_claims"],
)

# Phase-gated delegation — each unlock logged with timestamp + operator
from aiglos.integrations.agent_phase import AgentPhase
guard.unlock_phase(AgentPhase.P1, operator="will@aiglos.dev")  # observe only
guard.unlock_phase(AgentPhase.P3, operator="will@aiglos.dev")  # content autonomy
```

---

## CLI Reference

```bash
# Onboarding
aiglos launch                          # OpenClaw production-ready in 5 minutes
aiglos launch --from "description"     # non-interactive
aiglos agents scaffold                 # NL → declare_subagent() calls

# Security
aiglos scan-deps                       # check for compromised packages
aiglos scan-deps --quick               # known-bad versions only
aiglos validate-prompt soul.md         # score a skill file
aiglos validate-prompt --all           # score all .aiglos/*.md files
aiglos scan-exposed                    # CVE-2026-25253 exposure probe
aiglos audit --hardening-check         # compare against hardened baseline

# Policy
aiglos policy list / approve / reject
aiglos policy lockdown                 # deny-first mode
aiglos policy allow --tool web_search --authorized-by will@aiglos.dev
aiglos policy recommend                # min viable allowlist from session history

# Memory
aiglos memory status
aiglos memory scan --backend gigabrain

# Intelligence
aiglos benchmark run                   # GOVBENCH A-F grade
aiglos forecast                        # intent prediction state
aiglos autoresearch watch-ghsa         # GHSA watcher
aiglos autoresearch atlas-coverage

# NemoClaw / OpenShell
aiglos nemoclaw validate --policy ~/.nemoclaw/policy.yaml
aiglos openShell detect

# Daemon
aiglos daemon start / status / stop
```

---

## Pricing

| Tier | Price | What you get |
|------|-------|-------------|
| **Community** | $0 / MIT | Full T01-T81 detection, 3 surfaces, 22 campaign patterns, GOVBENCH, GHSA watcher, ATLAS coverage, all integrations (OpenShell, NemoClaw, Superpowers, Gigabrain, ByteRover, smolagents), declare_subagent(), AgentPhase, aiglos launch, scan-deps, validate-prompt, GitHub Actions CI |
| **Pro** | $49/dev/mo | Community + federated intelligence, behavioral baseline, RSA-2048 artifacts, NDAA §1513 + EU AI Act compliance export, policy proposals, cloud dashboard |
| **Teams** | $399/mo (15 devs) | Pro + centralized policy, aggregated threat view, Tier 3 approval workflows |
| **Enterprise** | Custom, annual | Teams + private federation, air-gap deployment, C3PAO packages, dedicated engineering |

---

## Build history

| Version | Tests | Rules | Notes |
|---------|-------|-------|-------|
| v0.1.0 | 335 | 36 | Initial release |
| v0.19.0 | 1,300 | 66 | Campaign patterns, new threat families |
| v0.24.0 | 1,514 | 75 | GOVBENCH, ATLAS coverage, NemoClaw, T68-T75 |
| v0.25.0 | 1,582 | 76 | T76, NemoClaw integration, OpenShell |
| v0.25.2 | 1,690 | 77 | declare_subagent(), AgentPhase, T77 |
| v0.25.3 | 1,747 | 79 | T78/T79, Gigabrain, aiglos launch |
| v0.25.4 | 1,791 | 80 | T80, smolagents, HF Spaces feed |
| v0.25.5 | 1,791 | 81 | T81 PTH_FILE_INJECT, scan-deps, REPO_TAKEOVER_CHAIN |
| v0.25.6 | 1,791 | 81 | ByteRover, validate-prompt, aiglos launch polish |

---

## What makes this structurally different

**1. The only product that intercepts all three surfaces.** MCP-only tools miss everything Claude Code, Cursor, and Aider do via subprocess and HTTP.

**2. Agent-agnostic.** OpenShell wraps any agent. Aiglos detects any agent. Same rules, same artifact, whether the agent is Claude Code, Cursor, smolagents, or OpenClaw.

**3. 3/3 GHSAs caught before disclosure.** Empirical validation no competitor can replicate. The rules came first, every time.

**4. Persistent memory protection.** T79 is the only rule specifically designed for cross-session memory backends. Gigabrain, ByteRover, Chroma, Pinecone, Qdrant — all protected. Adversarial content that survives session close and injects into every future session is completely unguarded elsewhere.

**5. Supply chain depth.** T81 catches `.pth` file attacks at the persistence placement moment, before the first Python restart. `aiglos scan-deps` gives an immediate answer to "am I already compromised." REPO_TAKEOVER_CHAIN detects the full attacker-becomes-maintainer sequence.

**6. The only product that produces a compliance artifact at session close.** 80,000 defense contractors need it by June 2026. Nothing else auto-generates it.

**7. aiglos launch is the second front door.** Security is the moat. The setup wizard is the growth vector.

**8. Detection that compounds.** Behavioral baselines, intent prediction, and federated intelligence improve with every session. A forked open-source version stays static. The moat grows.

---

IBM shipped the PC in 1981. Norton launched in 1990. Nine years for the security layer.

We're shipping in week three.

---

<div align="center">

[aiglos.dev](https://aiglos.dev) · [Docs](https://docs.aiglos.dev) · [Discord](https://discord.gg/aiglos) · [Twitter](https://twitter.com/aiglosdev)

</div>
