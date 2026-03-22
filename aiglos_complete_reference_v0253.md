# Aiglos: Complete Reference

**The AI Agent Security Platform — v0.25.3**

“OpenClaw is the new computer.” — Jensen Huang, GTC 2026

IBM shipped the PC in 1981. Norton launched in 1990. We’re shipping the security
layer in week three.

-----

## What Aiglos Is

Runtime security enforcement for every AI agent. One import intercepts every tool
call before execution, classifies it against 79 threat families, and produces a
signed audit artifact.

**The problem no one stated directly:** the dominant AI agent platform — OpenClaw,
311,000 GitHub stars, Jensen Huang calling it “the most popular open source project
in the history of humanity” — has a security policy that says verbatim:

> “Prompt injection attacks — Out of Scope.”

OWASP published the Top 10 for Agentic Applications. Number one: Agent Goal Hijack.
Prompt injection by another name. The most documented class of AI agent attacks is
officially not the platform’s problem. It is the ecosystem’s.

Aiglos is the ecosystem’s answer.

**Three things nobody else can say:**

1. 3/3 published OpenClaw GHSAs caught by existing rules before the advisories were
   disclosed. The rules came first. Every time.
1. 93% coverage of OpenClaw’s own published MITRE ATLAS threat model. The company
   that covers the platform’s own threat model better than any other tool is the
   default choice.
1. GOVBENCH — the first governance benchmark for AI agents. Published before any
   standard body required one. The company that defines the benchmark owns the
   compliance category for a decade.

-----

## Architecture

### Two Front Doors, Same Product

**Security-first (GTM 1):** Security engineers, DoD contractors, enterprise.
Install because the security problem is real and the deadline is June 2026.

**Onboarding-first (GTM 2):** Every new OpenClaw user. Install because
`aiglos launch` makes a working agent in 5 minutes. Security comes silently.

Both paths end with a signed session artifact and behavioral detection running
on every tool call.

### Enforcement Position

Aiglos enforces outside the agent process — the same architectural position as
NVIDIA OpenShell. The agent cannot reason around a rule it doesn’t know exists.

The architectural insight that defines the category:

- **Guardrails inside the agent** can be reasoned around or rewritten. OpenClaw’s
  config files were rewritten by an agent in under a minute in February 2026 testing.
  Claude Code’s internal tool definitions silently overrode operator guardrails
  earlier this year — the agent self-approved a 383-line commit.
- **Guardrails outside the agent** cannot be reasoned around. OpenShell and Aiglos
  both operate at this layer. OpenShell answers “what is this agent allowed to do”
  at the kernel/network level. Aiglos answers “what is this agent actually doing”
  at the behavioral sequence level. Two orthogonal guarantees. Neither can be
  bypassed.

### Interception Surfaces

Three surfaces operating simultaneously:

```python
aiglos.attach(
    agent_name            = "my-agent",
    policy                = "enterprise",
    intercept_http        = True,         # requests, httpx, urllib
    intercept_subprocess  = True,         # subprocess.run, os.system, Popen
    subprocess_tier3_mode = "pause",      # human confirmation on destructive ops
    guard_memory_writes   = True,         # T31/T79 memory protection
    guard_agent_defs      = True,         # T36 AgentDef protection
)
```

Under 1ms per call. Zero network dependency. No proxy. No sidecar. No port.

-----

## 79 Threat Families

Mapped to MITRE ATLAS techniques. Citation-verified. Every rule has a corresponding
ATLAS technique ID. No rule enters production without a citation anchor.

### T01-T43: Core Taxonomy

|Range  |Coverage                                                                                                                                                                                                                            |
|-------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|T01-T10|Exfiltration and data exposure: EXFIL, SSRF, SHADOW_WRITE, CRED_HARVEST, PROMPT_INJECT, CAMPAIGN, RECON, LATERAL, PERSISTENCE, PRIV_ESC                                                                                             |
|T11-T20|Infrastructure abuse: ENV_LEAK, NET_SCAN, DNS_REBIND, CACHE_POISON, LOG_TAMPER, SHELL_INJECT, PATH_TRAV, SYM_LINK, CRED_HARVEST extended, DEST                                                                                      |
|T21-T30|Supply chain and agent trust: PKG_CONFUSE, TYPOSQUAT, DEP_CONFUSION, TOOL_REDEF, AGENT_IMPERSONATE, TRUST_CHAIN, MEM_INJECT, RAG_POISON, CONTEXT_MANIP, SUPPLY_CHAIN                                                                |
|T31-T43|Agentic threats: REWARD_HACK, GOAL_MISALIGN, SANDBOX_ESCAPE, DATA_PIPELINE, PERSONAL_AGENT, AGENTDEF, FIN_EXEC, AGENT_SPAWN, ORCHESTRATION, SHARED_CONTEXT_POISON, OUTBOUND_SECRET_LEAK, INSTRUCTION_REWRITE_POISON, HONEYPOT_ACCESS|

### T44-T66: Infrastructure-to-Agent and Campaign Threats

INFERENCE_ROUTER_HIJACK, TOKEN_BUDGET_EXHAUSTION, COMPUTE_RESOURCE_ABUSE, and
20 additional rules covering infrastructure-to-agent attacks, agent-to-agent attacks
at scale, and vector store poisoning.

### T67-T79: New Rules (v0.20.0-v0.25.3)

|Rule|Name                    |Score|What it catches                                                                                                                                                                                  |Source                         |
|----|------------------------|-----|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------|
|T67 |HEARTBEAT_SILENCE       |0.88 |Overnight job suppression — agent or adversary killing scheduled tasks                                                                                                                           |Power user architecture pattern|
|T68 |INSECURE_DEFAULT_CONFIG |0.95 |Root cause of 40,214 exposed OpenClaw instances — auth bypass conditions                                                                                                                         |SecurityScorecard STRIKE data  |
|T69 |PLAN_DRIFT              |0.95 |Agent deviating from Superpowers-approved implementation plan                                                                                                                                    |Superpowers integration        |
|T70 |ENV_PATH_HIJACK         |0.88 |PATH/LD_PRELOAD/PYTHONPATH modification at runtime                                                                                                                                               |GHSA-mc68-q9jw-2h3v proof case |
|T71 |PAIRING_GRACE_ABUSE     |0.87 |30-second pairing window exploit                                                                                                                                                                 |OpenClaw ATLAS T-ACCESS-001    |
|T72 |CHANNEL_IDENTITY_SPOOF  |0.89 |AllowFrom header spoofing, X-Forwarded-For abuse                                                                                                                                                 |OpenClaw ATLAS T-ACCESS-002    |
|T73 |TOOL_ENUMERATION        |0.75 |tools.list / empty-arg probes — reconnaissance before attack                                                                                                                                     |OpenClaw ATLAS T-DISC-001      |
|T74 |CONTENT_WRAPPER_ESCAPE  |0.84 |XML wrapper termination, CDATA injection                                                                                                                                                         |OpenClaw ATLAS T-EVADE-002     |
|T75 |SESSION_DATA_EXTRACT    |0.82 |sessions.list / chat.history lateral extraction                                                                                                                                                  |OpenClaw ATLAS T-DISC-002      |
|T76 |NEMOCLAW_POLICY_BYPASS  |0.95 |Agent writes to NemoClaw OpenShell policy files at runtime — governance escape                                                                                                                   |NemoClaw GTC 2026 launch       |
|T77 |OVERNIGHT_JOB_INJECTION |0.87 |Malicious writes to cron/scheduler config files — adversary injects job that runs at 3am                                                                                                         |Vox AI company / Berman Tip 6  |
|T78 |HALLUCINATION_CASCADE   |0.82 |Cross-agent confidence amplification — A tells B, B tells C, all three converge on high-confidence wrong conclusion                                                                              |Vox AI company case study      |
|T79 |PERSISTENT_MEMORY_INJECT|0.92 |Adversarial content written to cross-session memory backends (Gigabrain SQLite, Chroma, Pinecone, Qdrant, Weaviate, mem0, Letta, Zep) — survives session close, injects into every future session|WeeklyClaw #004 / Gigabrain    |

**T79 technical note:** T31 fires on in-session memory writes cleared on session
close. T79 fires specifically on writes to backends that persist — Gigabrain SQLite
databases, vector stores, and compatible cross-session memory layers. The adversary
compromises the memory once and gets permanent influence over all future sessions
without re-injecting. Score 0.92 > T31 (0.87) because persistence multiplies
impact. Both conditions required for precision: path matches a known memory backend
AND content contains injection patterns. Read operations early-exit cleanly.

-----

## 21 Campaign Patterns

Multi-step attack sequence detection invisible to single-call rule engines.
Fires when individual tool calls form recognized attack sequences across time.

|Pattern                     |Sequence            |Confidence|Notes                                                                                                                                                |
|----------------------------|--------------------|----------|-----------------------------------------------------------------------------------------------------------------------------------------------------|
|RECON_SWEEP                 |T07 → T04           |0.88      |Environment read → targeted credential access                                                                                                        |
|CREDENTIAL_ACCUMULATE       |T19 → T12 → T01     |0.91      |Progressive credential gathering → exfil                                                                                                             |
|EXFIL_SETUP                 |T07 → T03 → T01     |0.89      |Recon → staging → exfiltration                                                                                                                       |
|PERSISTENCE_CHAIN           |T09 → T34           |0.87      |Multi-step persistence installation                                                                                                                  |
|LATERAL_PREP                |T08 → T13           |0.85      |Lateral movement preparation                                                                                                                         |
|AGENTDEF_CHAIN              |T36 read → T36 write|0.94      |Read-then-write on agent definitions — invisible to MCP-only tools                                                                                   |
|MEMORY_PERSISTENCE_CHAIN    |T31 → T27           |0.88      |Cross-session memory persistence                                                                                                                     |
|REWARD_MANIPULATION         |T31 → T32           |0.86      |RL reward signal manipulation sequence                                                                                                               |
|REPEATED_INJECTION_ATTEMPT  |T05 × 3+            |0.84      |Persistent injection retries                                                                                                                         |
|EXTERNAL_INSTRUCTION_CHANNEL|T13 → T05           |0.87      |External C2 channel establishment                                                                                                                    |
|SKILL_CHAIN                 |T30 → T10           |0.89      |Capability chaining for privilege escalation                                                                                                         |
|SANDBOX_ESCAPE_ATTEMPT      |T33 × 2+            |0.88      |Multi-step sandbox boundary probing                                                                                                                  |
|GAAS_TAKEOVER               |T25 → T28           |0.86      |GaaS hijack sequence                                                                                                                                 |
|INFERENCE_HIJACK_CHAIN      |T44 → T01           |0.87      |Model routing compromise → exfil                                                                                                                     |
|RAG_POISON_CHAIN            |T54 → T05           |0.91      |Retrieval context poisoning                                                                                                                          |
|MULTI_AGENT_IMPERSONATION   |T25 × 3+            |0.88      |Agent identity substitution at scale                                                                                                                 |
|CAPABILITY_EXPLOIT_CHAIN    |T38 → T10           |0.86      |Capability boundary exploitation                                                                                                                     |
|SANDBOX_CONFIRMED_ESCAPE    |T33 → T01           |0.96      |Confirmed sandbox exit with evidence                                                                                                                 |
|SUPERPOWERS_PLAN_HIJACK     |T69 → T01           |0.97      |Superpowers plan manipulation → exfil                                                                                                                |
|NEMOCLAW_POLICY_HIJACK      |T76 → {T68,T12,T14} |0.96      |Policy bypass followed by insecure config or exfil. T76 amplifier 1.4x                                                                               |
|GIGABRAIN_MEMORY_POISON     |T31 → T79           |0.95      |In-session injection probe followed by commit to persistent memory store. T79 amplifier 1.5x. The only pattern targeting two-tier memory architecture|

-----

## 18 Inspection Triggers

Automatic anomaly signals that elevate inspection posture without requiring a
hard block. Fire into the observation graph for behavioral analysis.

RATE_DROP, ZERO_FIRE, HIGH_OVERRIDE, AGENTDEF_REPEAT, SPAWN_NO_POLICY,
FIN_EXEC_BYPASS, FALSE_POSITIVE, REWARD_DRIFT, CAUSAL_INJECTION_CONFIRMED,
THREAT_FORECAST_ALERT, BEHAVIORAL_ANOMALY, REPEATED_TIER3_BLOCK,
GLOBAL_PRIOR_MATCH, GAAS_ESCALATION_DETECTED, INFERENCE_HIJACK_CONFIRMED,
CONTEXT_DRIFT_DETECTED, PLAN_DRIFT_DETECTED, UNVERIFIED_RULE_ACTIVE

-----

## Integrations

### OpenShell — Agent-Agnostic Sandbox (v0.25.1)

NVIDIA NemoClaw announced at GTC 2026. OpenShell is the sandbox layer.
Aiglos is the behavioral detection layer above it.

```python
from aiglos.integrations.openShell import (
    openshell_detect,          # zero config — reads OPENSHELL_SANDBOX_ID
    attach_for_claude_code,    # openshell sandbox create -- claude
    attach_for_codex,          # openshell sandbox create -- codex
    attach_for_cursor,         # openshell sandbox create -- cursor
    attach_for_openclaw,       # openshell sandbox create -- openclaw
    is_inside_openShell,       # bool check
    openShell_context,         # full sandbox context dict
)

session = openshell_detect(guard)  # auto-reads OPENSHELL_POLICY_PATH
```

9 known agents: Claude Code, Codex, Cursor, OpenClaw, Windsurf, Aider, Continue,
Cody. Same YAML policy enforces identically for all agents — the sandbox does not
know or care which agent is inside it. This is the architectural insight Jensen
demonstrated at GTC and then didn’t explain.

### NemoClaw — YAML Policy Import (v0.25.0)

```python
from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session, validate_policy

session = mark_as_nemoclaw_session(
    policy_path = "~/.nemoclaw/policy.yaml",
    guard       = guard,
)
# Allowed hosts/files/tools from YAML become T69/T76 enforcement boundary
# T76 fires if agent writes to .nemoclaw/ policy files at runtime
```

Validate any policy: `aiglos nemoclaw validate --policy ~/.nemoclaw/policy.yaml`

### Superpowers — Plan as Policy (v0.24.0)

The approved implementation plan becomes the T69 enforcement boundary.
Plan deviation fires T69 PLAN_DRIFT — the highest-confidence signal in the
system (0.95) because it measures against explicit human approval, not
statistical inference.

```python
from aiglos.integrations.superpowers import mark_as_superpowers_session
session = mark_as_superpowers_session(plan_path="./plan.md", guard=guard)
```

SUPERPOWERS_PLAN_HIJACK campaign pattern (confidence 0.97) — the most
confident campaign pattern in the taxonomy.

### Sub-Agent Declaration (v0.25.2)

For multi-agent setups. Resolves T38 false positives from legitimate background
agent spawns while keeping detection active for undeclared spawns.

```python
guard.declare_subagent(
    "coding-agent",
    tools       = ["filesystem", "shell.execute", "web_search"],
    scope_files = ["src/", "tests/"],
    model       = "claude-sonnet",
    hard_bans   = ["fabricate_data", "unverified_claims"],
)
```

`hard_bans` implements the Role Card pattern from the Vox AI company architecture:
semantic constraints declared at setup, violations logged to signed artifact.

Three T38 outcomes:

- Declared + in-scope: score 0.0 (suppressed)
- Declared + out-of-scope: score 0.90 (elevated)
- Undeclared spawn: score 0.78 (normal threshold)

### Phase-Gated Delegation (v0.25.2)

5-phase progressive delegation. Each phase unlock recorded with timestamp +
operator identity in the signed artifact.

```python
from aiglos.integrations.agent_phase import AgentPhase

guard.unlock_phase(AgentPhase.P1, operator="will@aiglos.dev")  # observe only
guard.unlock_phase(AgentPhase.P2, operator="will@aiglos.dev")  # low-risk auto-approve
guard.unlock_phase(AgentPhase.P3, operator="will@aiglos.dev")  # content autonomy
guard.unlock_phase(AgentPhase.P4, operator="will@aiglos.dev")  # site operations
guard.unlock_phase(AgentPhase.P5, operator="will@aiglos.dev")  # self-evolution
```

Auditor query answer: “When did this agent get production deployment access?”
`print(guard.phase_log())` — timestamp + operator for every unlock.

### Gigabrain + Persistent Memory Protection (v0.25.3)

Gigabrain is a SQLite-backed cross-session memory layer (WeeklyClaw #004 Skill
of the Week). T79 sits at the write path.

```python
from aiglos.integrations.gigabrain import gigabrain_autodetect, declare_memory_backend

# Zero config — scans ~/.gigabrain/, registers with T79
session = gigabrain_autodetect(guard)

# Or explicit backend declaration
declare_memory_backend(guard, backend="chroma",
                       db_path="./chroma.db")
```

8 backends: Gigabrain, MemoryOS, mem0, Letta, Zep, Chroma, Pinecone, Qdrant.

GIGABRAIN_MEMORY_POISON campaign (confidence 0.95): T31 in-session probe
followed by T79 persistent commit. The adversary tests injection in-session,
then commits the payload to permanent storage. T31 without T79 = probing.
T31 + T79 = persistent foothold.

-----

## aiglos launch — OpenClaw Production-Ready in 5 Minutes

The second GTM. The answer to the “default OpenClaw is useless” problem.

```bash
pip install aiglos && aiglos launch
```

Five questions about what you want to build. Generates in 30 seconds:

```
.aiglos/
  soul.md         Hard rules, no hallucinations, hard_bans pre-populated
  learnings.md    Mistake log, T79-protected, read-before-task wired
  heartbeat.md    30-min cadence, T67 monitoring registered
  crons.md        Heavy task template, separate from heartbeat
  tools.md        Declared tool surface, lockdown policy auto-generated
  agents.md       Sub-agent declarations, T38 enforcement wired
  config.py       Ready-to-import guard, all 79 rules active
```

Non-interactive: `aiglos launch --from "Research AI news and post to Twitter"`

Sub-agent scaffold: `aiglos agents scaffold`
Takes plain English → `declare_subagent()` calls.
“CEO agent using Opus, push rights to main” → correct tools, scope, hard_bans.

Templates: `aiglos/templates/` — standalone reference files showing the output
of `aiglos launch` for a two-agent setup.

-----

## Governance and Benchmarking

### GOVBENCH

The first governance benchmark for AI agents. Published before any standard
body required one. 5 dimensions, 20 scenarios, A-F grade, under 60 seconds.

```bash
aiglos benchmark run
# Grade: A (92/100)
# D1 Campaign detection:           19/20
# D2 Agent definition resistance:  20/20
# D3 Memory belief integrity:      18/20
# D4 RL feedback loop resistance:  18/20
# D5 Multi-agent cascading failure: 17/20
```

### GHSA Watcher

Monitors OSV.dev, NVD, GitHub Advisory API, and the OpenClaw CVE feed.
Matches new advisories to T-rules within 6 hours of publication.

```bash
aiglos autoresearch watch-ghsa
aiglos autoresearch ghsa-coverage
```

3/3 published OpenClaw GHSAs covered by rules that existed before disclosure:

|GHSA               |CVSS|Attack                                 |Rules          |Reporter                   |
|-------------------|----|---------------------------------------|---------------|---------------------------|
|GHSA-g8p2-7wf7-98mq|8.8 |Auth token exfiltration via gatewayUrl |T03 T12 T19 T68|OpenClaw team              |
|GHSA-q284-4pvr-m585|8.6 |OS command injection via path traversal|T03 T04 T70    |mitsuhiko (Flask, Werkzeug)|
|GHSA-mc68-q9jw-2h3v|8.4 |Command injection via PATH env variable|T03 T70        |OpenClaw team              |

285 additional reports in the OpenClaw private queue. When they publish, the
GHSA watcher matches and either confirms existing coverage or generates a pending
rule proposal. The 285 are not a backlog — they are a rule generation pipeline.

### ATLAS Coverage

```bash
aiglos autoresearch atlas-coverage
# 22 threats mapped, 19 full, 3 partial, 0 gaps — 93%
```

OpenClaw’s own MITRE ATLAS threat model: 22 threats, 8 tactic categories.
Aiglos covers 93%. The 3 partial cases are architecturally honest — passive
fingerprinting, adversarial ML evasion, and semantically-appropriate-but-harmful
content have no reliable behavioral signature at the tool call layer.
We document gaps rather than overclaim.

-----

## Intelligence Layers

### Behavioral Baseline

Per-agent statistical fingerprinting across three independent feature spaces:

- **Event rate:** z-score against rolling session history
- **Surface mix:** chi-squared test on MCP/HTTP/subprocess call distribution
- **Rule frequency:** KL-divergence from historical rule firing pattern

`BEHAVIORAL_ANOMALY` trigger fires when composite deviation exceeds threshold.
Baselines stored in the observation graph, improving with every session.

### Predictive Intent Modeling

Deployment-specific Markov chain trained on local call history. No external
ML dependency.

- `IntentPredictor` builds transition probability matrix from session history
- `SessionForecaster` pre-tightens `effective_tier()` when predicted next
  action is Tier 2 or Tier 3
- `THREAT_FORECAST_ALERT` fires before the threat executes
- `python -m aiglos forecast` surfaces current prediction state

### Federated Threat Intelligence

Privacy-preserving global threat intelligence.

- Differential privacy with Laplace mechanism (epsilon=0.1)
- Only noisy unigram transition counts over the 79-element rule vocabulary leave a deployment
- Raw events, tool names, URLs, agent names, session IDs, content — never leave
- New deployments start pre-warmed from collective intelligence
- `GLOBAL_PRIOR_MATCH` trigger fires when global prior identifies patterns not yet seen locally
- Pull-only is free; contributing requires Pro tier

### Policy Proposals

Evidence-weighted policy decisions. One human decision permanently adjusts posture.

Four types triggered by evidence strength:

- `LOWER_TIER` — 5+ blocks, 60% confidence
- `RAISE_THRESHOLD` — 8+ blocks, 70% confidence
- `ALLOW_LIST` — 10+ blocks, 80% confidence
- `SUPPRESS_PATTERN` — 15+ blocks, 90% confidence

```bash
aiglos policy list
aiglos policy approve prp_a1b2c3d4 will@aiglos.dev
```

### Causal Attribution

Traces the causal chain from a block event back to the originating injection
point. Answers “what caused this agent to make this call?” rather than just
logging that it was blocked. `CAUSAL_INJECTION_CONFIRMED` trigger.

### Source Reputation

Inbound data sources scored against a reputation index. Sources that previously
triggered injection rules receive elevated inspection in future sessions — across
deployments when federation is enabled.

-----

## Specialized Security Modules

**MemoryWriteGuard (T31)** — intercepts every structured memory write before it
commits. 38-phrase corpus covering authorization claims, endpoint redirects,
instruction override commands, credential assertions.

**RLFeedbackGuard (T32)** — intercepts binary RL reward signals and Hindsight OPD
feedback before they reach the training loop.

**AgentDef Guard (T36)** — monitors `~/.claude/agents/` and equivalents at the
subprocess layer. Catches the read-then-write AGENTDEF_CHAIN that is invisible
to MCP-only tools.

**Honeypot Detection (T43)** — canary tool injection. Any probe fires T43 at
score=1.0 — the highest possible score, no threshold required. The read itself
is the evidence of credential harvesting intent.

**OutboundSecretGuard (T41)** — scans outbound HTTP content for API keys,
credentials, and PII before transmission. `guard.before_send(content)`.

**Injection Scanner** — scans every tool response before it enters the agent’s
context. `guard.after_tool_call(tool_name, output)`.

**Challenge-Response Override** — Tier 3 blocked calls re-authorized via signed
challenge-response. Override events recorded in artifact with full attribution.

**Scan Exposed** — `aiglos scan-exposed` probes for CVE-2026-25253 attack surface.
40,214 exposed OpenClaw instances as of February 2026.

**Hardening Check** — `aiglos audit --hardening-check` compares config against
the official OpenClaw hardened baseline.

-----

## Compliance and Attestation

### Session Artifact

Every session close produces a cryptographically signed audit record:

```json
{
  "schema":             "aiglos/v1",
  "artifact_id":        "3f9a1c2d-...",
  "agent_name":         "my-agent",
  "policy":             "federal",
  "total_calls":        247,
  "blocked_calls":      4,
  "warned_calls":       2,
  "attestation_ready":  true,
  "phase_log":          [{"phase": 3, "operator": "will@aiglos.dev", "timestamp": 1742000000}],
  "memory_backends":    [{"backend": "gigabrain", "paths": ["~/.gigabrain/memory.db"]}],
  "subagent_registry":  [{"name": "coding-agent", "hard_bans": ["fabricate_data"]}],
  "http_events":        [...],
  "subproc_events":     [...],
  "signature":          "sha256:a1b2c3d4..."
}
```

Free tier: HMAC-SHA256. Pro/Enterprise: RSA-2048 (required for C3PAO submission).
Tamper-evident. `.aiglos` format for archival.

### Compliance Coverage

|Standard             |Deadline     |Status                                                                                                                        |
|---------------------|-------------|------------------------------------------------------------------------------------------------------------------------------|
|NDAA §1513 FY2026    |June 16, 2026|`attestation_ready: true` auto-generated per session. 80,000 defense contractors need this artifact. Nothing else produces it.|
|CMMC Level 2         |Ongoing      |C3PAO-formatted evidence package. 8 controls mapped.                                                                          |
|NIST SP 800-171 Rev 2|Ongoing      |18 controls across AC, AU, IA, SC, SI families.                                                                               |
|EU AI Act            |August 2026  |Pro tier and above.                                                                                                           |
|SOC 2 Type II        |Ongoing      |CC6, CC7 coverage.                                                                                                            |

-----

## Build History

|Version|Tests|Rules|Campaigns|Key additions                                                                    |
|-------|-----|-----|---------|---------------------------------------------------------------------------------|
|v0.1.0 |335  |36   |5        |Initial release                                                                  |
|v0.10.0|688  |39   |10       |Intent prediction                                                                |
|v0.11.0|753  |39   |12       |Behavioral baseline                                                              |
|v0.13.0|882  |39   |15       |Federated intelligence                                                           |
|v0.19.0|1,300|66   |19       |Campaign patterns, new threat families                                           |
|v0.24.0|1,514|75   |19       |GOVBENCH, ATLAS coverage, T71-T75, NemoClaw, T68/T69/T70                         |
|v0.25.0|1,582|76   |20       |T76 NEMOCLAW_POLICY_BYPASS, NemoClaw integration                                 |
|v0.25.1|1,636|76   |20       |OpenShell agent-agnostic (9 known agents), openshell_detect()                    |
|v0.25.2|1,690|77   |21       |declare_subagent(), hard_bans, AgentPhase, T77 OVERNIGHT_JOB_INJECTION           |
|v0.25.3|1,747|79   |21       |T78 HALLUCINATION_CASCADE, T79 PERSISTENT_MEMORY_INJECT, Gigabrain, aiglos launch|

-----

## CLI Reference

```bash
# Onboarding
aiglos launch                         # OpenClaw production-ready in 5 minutes
aiglos launch --from "description"    # Non-interactive, from description
aiglos agents scaffold                # NL description → declare_subagent() calls

# Core
aiglos attach                         # Attach to running agent session
aiglos check <tool> <args>            # Manual check against all 79 rules
aiglos attest --session SESSION_ID    # Produce signed attestation
aiglos verify SESSION_ID.aiglos       # Verify artifact integrity

# Policy
aiglos policy list                    # Pending proposals
aiglos policy approve prp_abc123 user@co.com
aiglos policy reject prp_abc123 --reason "false_positive"
aiglos policy lockdown                # Deny-first mode
aiglos policy allow --tool web_search --authorized-by will@aiglos.dev
aiglos policy recommend               # Min viable allowlist from session history

# Memory backends
aiglos memory status
aiglos memory scan --backend gigabrain

# Sub-agents and phases
aiglos subagents list
aiglos subagents declare --name scout --tools web_search,analytics

# NemoClaw / OpenShell
aiglos nemoclaw validate --policy ~/.nemoclaw/policy.yaml
aiglos nemoclaw status
aiglos openShell detect

# Intelligence and benchmarking
aiglos benchmark run                  # GOVBENCH A-F grade
aiglos forecast                       # Current intent prediction state
aiglos autoresearch watch-ghsa        # GHSA watcher
aiglos autoresearch atlas-coverage    # ATLAS threat model coverage
aiglos autoresearch ghsa-coverage     # GHSA validation report
aiglos scan-exposed                   # CVE-2026-25253 exposure probe
aiglos audit --hardening-check        # Compare against hardened baseline

# Research and compliance
aiglos research report
aiglos report --level 2               # CMMC Level 2 summary
aiglos report --format json

# Daemon
aiglos daemon start / status / stop
```

-----

## Pricing

|Tier          |Price            |What you get                                                                                                                                                                                                                                      |
|--------------|-----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|**Community** |$0 / MIT         |Full T01-T79 detection, 3 surfaces, 21 campaign patterns, GOVBENCH, GHSA watcher, ATLAS coverage, OpenShell, NemoClaw, Superpowers, Gigabrain, declare_subagent(), hard_bans, AgentPhase, aiglos launch, GitHub Actions CI, aiglos agents scaffold|
|**Pro**       |$49/dev/mo       |Community + federated intelligence, behavioral baseline, RSA-2048 signed artifacts, NDAA §1513 + EU AI Act compliance export, policy proposals, cloud dashboard                                                                                   |
|**Teams**     |$399/mo (15 devs)|Pro + centralized policy, aggregated threat view, Tier 3 approval workflows, audit exports                                                                                                                                                        |
|**Enterprise**|Custom, annual   |Teams + private federation server, air-gap deployment, C3PAO packages, dedicated engineering, NET-30                                                                                                                                              |

Conversion mechanic: first call to `aiglos.attest()` or cloud telemetry connection
auto-starts a 30-day Pro trial. No feature blocked. By day 30, the developer has
built their workflow around signed artifacts. The decision is already made.

-----

## What Makes Aiglos Structurally Differentiated

**1. The only product that intercepts all three surfaces.**
MCP-only tools miss everything Claude Code, Cursor, and Aider do via subprocess
and HTTP. The three-surface architecture is not a feature — it is the architecture.

**2. Agent-agnostic from day one.**
OpenShell wraps any agent. Aiglos detects any agent. Same YAML policy, same
T-rule set, same signed artifact — whether the agent is Claude Code, Cursor,
Codex, or OpenClaw. The Kari Briski quote from GTC: “OpenShell provides the
missing infrastructure layer beneath claws.” The Zahra Timsah quote from
Computerworld the same week: “The missing piece is not tooling. It is control.
Real developers want observability, policy enforcement, rollback, and audit trails.”

**3. 3/3 GHSAs caught before disclosure.**
This is empirical validation that no competitor can replicate. The rules came
first. GHSA-q284-4pvr-m585 was reported by Armin Ronacher — Flask, Jinja2,
Werkzeug. He documented the exact attack class T04 was built to catch.

**4. Campaign detection.**
21 named multi-step attack patterns invisible to single-call rule engines.
AGENTDEF_CHAIN (read agent definition → write modified version) cannot be
caught by any product that evaluates calls in isolation. GIGABRAIN_MEMORY_POISON
(T31 probe → T79 persistent commit) is the only pattern targeting the two-tier
memory architecture that Gigabrain and compatible tools create.

**5. Persistent memory protection (T79).**
The only rule specifically designed for cross-session memory backends. An
adversary who plants content in Gigabrain’s SQLite database gets permanent
influence over every future session. Every other tool misses this entirely.

**6. The only product that produces a compliance artifact at session close.**
80,000 defense contractors need a signed record of every autonomous AI agent
action by June 16, 2026. NDAA §1513. Nothing else auto-generates the
C3PAO-ready attestation document. The artifact is the product.

**7. GOVBENCH defines the benchmark.**
Published before any standard body required one. The company that defines the
benchmark owns the compliance infrastructure for a decade.

**8. Detection that compounds.**
Behavioral baselines, intent prediction, and federated intelligence improve with
every session and every deployment. A forked open-source version stays static.
The moat grows with every deployment, every advisory published, every GHSA matched.

**9. aiglos launch is the second front door.**
`pip install aiglos && aiglos launch` answers the “default OpenClaw is useless”
problem that the tweet author spent a weekend solving. Five questions. Working
agent. Security built in by default. Every new OpenClaw user is now a potential
Aiglos user before they know they need security.

**10. The window.**
IBM shipped the PC in 1981. Norton launched in 1990. Nine years for the security
layer. We’re shipping in week three. The category-defining breach hasn’t happened
yet. The company that owns behavioral detection when it does owns the category.

-----

*Generated from v0.25.3 codebase — March 22, 2026*
*1,747 tests passing*
*github.com/aiglos/aiglos · aiglos.dev*