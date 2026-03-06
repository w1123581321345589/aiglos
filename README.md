# Aiglos

**AI Agent Security Runtime for Defense and Enterprise**

Aiglos is a transparent security proxy for MCP (Model Context Protocol) agents. It sits between any AI coding agent or autonomous system and the MCP servers it connects to, enforcing security policy, detecting attacks, and producing signed audit records at every tool call.

---

## The Problem

AI agents have no security layer. They accept tool calls from any server, execute instructions from any document they read, and have no mechanism to verify they are still pursuing their authorized objective. Traditional security tools operate at the network or identity layer — they are blind to what an agent actually does.

**Three classes of attack no existing tool catches:**

1. **Goal hijacking** — An adversary embeds instructions in a document the agent reads. The agent's subsequent tool calls are syntactically valid but semantically wrong. The agent is now doing the attacker's work.

2. **MCP server compromise** — An attacker modifies a legitimate MCP server's tool definitions to include malicious implementations behind familiar names. The agent's tool calls look normal; the execution is not.

3. **Credential exfiltration via agent** — An agent with file system access reads a `.env` or `.ssh/id_rsa` and passes the contents as arguments to an outbound HTTP call. Standard DLP tools never see it because it is application-layer JSON, not a file transfer.

Aiglos catches all three.

---

## How It Works

```
[AI Agent / IDE]  <--WebSocket-->  [Aiglos :8765]  <--WebSocket-->  [MCP Server :18789]
```

Aiglos is a transparent WebSocket proxy. Every message between the agent and its MCP server passes through the security pipeline:

1. **Credential Scanner** — Detects 20+ secret patterns (AWS keys, Anthropic keys, GitHub tokens, JWTs, high-entropy strings) in tool arguments before they reach the server.

2. **Policy Engine** — YAML-based rule engine with glob matching. Blocks `sudo`, `rm -rf`, path traversal, and any custom policy you define. Runs at sub-millisecond latency.

3. **Goal Integrity Engine** — The core defensible IP. At session start, the authorized objective is hashed. On every tool call, a two-path evaluation runs:
   - **Fast path** (rule-based, <1ms): suspicious tool chain detection, domain shift analysis, call acceleration anomaly, read-then-execute pattern
   - **Semantic path** (LLM-evaluated, async): triggered when fast path score drops below threshold; scores 0.0-1.0 alignment against the original goal

4. **MCP Server Trust Registry** — Allowlist/blocklist with tool manifest fingerprinting. Detects when a server's tool schema changes between connections (supply chain attack indicator).

5. **Agent Identity Attestation** — Every session produces a signed, tamper-evident JSON document: model identity, system prompt hash, tool permissions, timeline, security posture, and a per-event SHA-256 manifest. RSA-2048 signed.

6. **CMMC Compliance Mapper** — Every security event automatically maps to NIST SP 800-171 Rev 2 controls. `aiglos report` produces a C3PAO-ready compliance artifact.

7. **Alert Dispatcher** — Fan-out to Splunk HEC, Syslog CEF (QRadar/ArcSight/Sentinel), Slack, webhook (PagerDuty/Opsgenie), Microsoft Teams, and file JSONL sink. Rate-limited per destination.

---

## Installation

```bash
pip install aiglos
```

Requires Python 3.11+.

---

## Quickstart

```bash
# Initialize config and policy files
aiglos init

# Start the proxy (forwards to localhost:18789 by default)
aiglos proxy

# Point your MCP client to localhost:8765 instead of :18789

# Monitor in real time
aiglos tail
aiglos sessions

# Generate a CMMC compliance report
aiglos report --level 2 --output report.json
```

---

## Docker

```bash
docker run -p 8765:8765 \
  -e UPSTREAM_HOST=your-mcp-server \
  -e UPSTREAM_PORT=18789 \
  aiglos/aiglos:latest
```

---

## Configuration

`aiglos init` generates `aiglos.yaml` and `aiglos_policy.yaml`.

**aiglos.yaml:**

```yaml
proxy:
  listen_port: 8765
  upstream_host: localhost
  upstream_port: 18789
  deployment_tier: cloud  # cloud | on_prem | gov

features:
  goal_integrity: true
  credential_scanning: true
  policy_engine: true
  trust_registry: true
  attestation: true

goal_integrity:
  drift_threshold: 0.35
  # anthropic_api_key: sk-ant-...  # Required for semantic evaluation

trust:
  mode: audit  # strict | audit | permissive
  file: aiglos_trust.yaml

alerts:
  slack:
    webhook_url: https://hooks.slack.com/...
    min_severity: high
  splunk:
    hec_url: https://splunk.example.com:8088/services/collector
    hec_token: YOUR_HEC_TOKEN
    min_severity: info
  file_sink:
    path: aiglos_events.jsonl
```

---

## Trust Registry

```bash
# List all known servers
aiglos trust list

# Allow a server
aiglos trust allow localhost:18789 --alias dev-server

# Block a server
aiglos trust block evil-mcp.example.com:443 --reason "Reported exfil server"
```

The trust registry detects tool manifest changes between connections. If a server's schema changes, Aiglos fires a `TOOL_REDEFINITION` event at CRITICAL severity.

---

## Attestation

```bash
aiglos attest --session SESSION_ID
aiglos verify SESSION_ID.attestation.json
```

Attestation documents contain model identity, system prompt hash, tool permissions, timeline, security posture scores, per-event SHA-256 manifest, and an RSA-2048 signature.

---

## CMMC Compliance

Aiglos actively covers 18 NIST SP 800-171 Rev 2 controls across five families.

```bash
aiglos report --level 2 --format json --output cmmc_report.json
aiglos report --level 2 --format summary
```

---

## Deployment Tiers

| Tier | Target | CMMC Level |
|---|---|---|
| `cloud` | SaaS, commercial | L1/L2 |
| `on_prem` | Enterprise, air-gap capable | L3 |
| `gov` | FedRAMP, IL4/IL5 | L3+ STIG |

For air-gapped environments, inject the signing key via environment variable:

```bash
export AIGLOS_SIGNING_KEY="$(cat /path/to/private_key.pem)"
```

---

## CLI Reference

```
aiglos proxy         Start the MCP security proxy
aiglos init          Generate config and policy files
aiglos scan          Scan current config for security issues
aiglos sessions      List agent sessions with integrity scores
aiglos logs          View recent audit events
aiglos tail          Live tail security events
aiglos report        Generate CMMC compliance report
aiglos attest        Produce signed attestation document
aiglos verify        Verify an attestation document
aiglos trust list    List trust registry entries
aiglos trust allow   Allow an MCP server
aiglos trust block   Block an MCP server
aiglos alerts        Show alert destination configuration
```

---

## Architecture

```
aiglos/
├── aiglos_core/
│   ├── proxy/            # WebSocket proxy, trust registry
│   ├── scanner/          # Credential and secret scanner
│   ├── policy/           # YAML policy engine
│   ├── audit/            # SQLite audit log
│   ├── intelligence/     # Goal integrity engine, attestation
│   ├── compliance/       # CMMC control mapper, report generator
│   └── integrations/     # SIEM/alert dispatcher
├── aiglos_cli/       # CLI entry point
└── tests/unit/           # 163 passing tests
```

---

## License

Proprietary. Contact [will@aiglos.dev](mailto:will@aiglos.dev) for licensing.
