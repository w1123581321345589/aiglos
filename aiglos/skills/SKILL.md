# Aiglos -- AI Agent Security

## What this skill does

This skill loads the Aiglos AI agent security platform into your context. It provides:

- **39 threat families** across MCP tool calls, HTTP/API requests, and subprocess execution
- **Behavioral baseline** -- learns what normal looks like for your deployment
- **Honeypot detection** -- fires CRITICAL if credential files are accessed
- **Outbound secret scanning** -- prevents API key leakage in responses
- **Policy proposals** -- replaces per-action webhook fatigue with evidence-backed policy decisions
- **Source reputation** -- tracks which URLs and documents have returned injection attempts
- **Federated threat intelligence** -- global prior from network of deployments

## Install

```bash
pip install aiglos
```

Or drag [Aiglos.app](https://aiglos.dev) to Applications (macOS/Windows -- no Python required).

## One-line attach

```python
import aiglos
# Every tool call below this line is inspected, attested, and learned from.
```

## Full attach with all intelligence layers

```python
import aiglos

aiglos.attach(
    agent_name              = "my-agent",
    policy                  = "enterprise",
    enable_behavioral_baseline = True,   # learns your deployment's normal
    enable_policy_proposals    = True,   # replaces webhook fatigue
    enable_honeypot            = True,   # CRITICAL on credential file access
    enable_source_reputation   = True,   # tracks bad URLs and documents
    enable_intent_prediction   = True,   # forecasts next threat family
    enable_causal_tracing      = True,   # traces blocked actions to injection source
    enable_federation          = True,   # warm-starts from global prior (Pro)
)
```

## Inbound injection scanning

Scan every tool output before it enters the agent's context:

```python
guard.after_tool_call("web_search", search_results, source_url="https://example.com")
# InjectionScanResult(verdict=WARN, rule_id=T27, score=0.72)
# Source reputation updated automatically.
```

## Outbound secret scanning

Scan before sending any response:

```python
result = guard.before_send(response_text, destination="user")
if result and result.blocked:
    response_text = "[Response suppressed: security policy]"
```

## Override a Tier 3 block

```python
challenge = guard.request_override(
    rule_id   = "T37",
    tool_name = "http.post",
    reason    = "Authorizing contract renewal payment",
)
# Terminal displays: Override code: A7X2K9 (expires in 120s)
guard.confirm_override(challenge.challenge_id, "A7X2K9")
```

## CLI

```bash
aiglos policy list              # pending policy proposals
aiglos honeypot status          # active honeypots and hit log
aiglos research report          # compliance report (NDAA §1513, EU AI Act, NIST AI 600-1)
aiglos override list            # pending Tier 3 overrides
aiglos reputation top           # most dangerous sources for this deployment
```

## Threat coverage

| Rule | Threat | What it catches |
|------|--------|----------------|
| T01, T27 | Prompt injection | Inbound injection in tool outputs, docs, API responses |
| T19–T24 | Credential access | SSH keys, .env files, AWS credentials |
| T31 | Memory poisoning | Authorization claims in memory writes |
| T36_AGENTDEF | Agent definition | Writes to ~/.claude/agents/, skills/, SOUL.md, SKILL.md |
| T37 | Financial execution | Autonomous Stripe, PayPal, crypto transactions |
| T39 | RL reward poisoning | Training signal manipulation |
| T40 | Shared context poison | Multi-agent coordination directory injection |
| T41 | Outbound secret leak | API keys in outbound content |
| T43 | Honeypot access | Credential harvesting intent confirmed |

## Source reputation

Aiglos tracks which URLs and documents have returned injection attempts in past sessions.
Before fetching from a known-bad source, the trust threshold is elevated automatically:

```
URL: https://attacker-controlled.com/docs
  Last seen: 2026-03-15 -- T27 INBOUND_INJECTION score=0.81
  Reputation: HIGH_RISK -- elevated scrutiny applied
```

## Zero dependencies

Everything runs in Python stdlib. No pip dependencies beyond `aiglos` itself.
Works in air-gapped environments.

## Resources

- GitHub: https://github.com/w1123581321345589/aiglos
- Docs: https://docs.aiglos.dev
- Desktop app: https://aiglos.dev
- Discord: https://discord.gg/aiglos
