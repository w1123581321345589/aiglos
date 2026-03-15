# Aiglos — Claude Development Context

This is your exosuit for Aiglos development. When you join a session, you inherit
the accumulated architectural decisions of the project. You are not an assistant
discovering a new codebase. You are a contributor who already knows it.

---

## What Aiglos is

Runtime security for AI agents. One import intercepts every tool call before
execution, classifies it against 36 threat families, and produces a signed audit
artifact. The detection engine is MIT open source. The attestation layer
(RSA-2048 signing, SOC 2 / CMMC / NDAA §1513 compliance reports) is proprietary
and funds the research.

The business wedge is the OpenClaw and hermes-agent communities, both of which
have documented security gaps Aiglos closes at the runtime layer. The federal
market (NDAA §1513, June 16, 2026 deadline) is the second wedge.

---

## Architecture — what's where

```
aiglos/
├── __init__.py              public API: attach() / check() / on_heartbeat() / close()
├── __main__.py              python -m aiglos entry point
├── core/
│   ├── attest.py            RSA-2048 attestation artifact generator
│   ├── gates.py             feature gate enforcement (free / pro / enterprise)
│   ├── licensing.py         tier validation and license management
│   ├── interceptor.py       in-process MCP call monkey-patch
│   ├── scanner.py           fast-path inline threat scanner (<1ms, no network)
│   ├── metering.py          cloud usage telemetry (Pro+)
│   └── config.py            embedded SDK configuration
├── integrations/
│   ├── openclaw.py          OpenClaw guard — full T01–T39, heartbeat, sub-agents
│   └── hermes.py            hermes-agent guard — T01–T39 + trajectory signing
└── autonomous/
    ├── engine.py             continuous background hunt engine
    ├── t30_registry.py       supply chain registry monitor
    ├── t34_data_agent.py     data pipeline security runtime
    └── t35_personal_agent.py personal agent (calendar/email/identity) surface
```

The module-level API in `__init__.py` delegates to the OpenClaw integration as
the default guard. Any session that calls `aiglos.attach()` is using
`integrations/openclaw.py` under the hood.

---

## The 36 threat families

T01 EXFIL through T36 ORCHESTRATION. The authoritative list is in `README.md`
and `docs/threat-map-atlas.md`. Every threat class maps to a MITRE ATLAS
technique. Do not add threat detection logic without a corresponding ATLAS entry.

The T-numbers in `aiglos/integrations/openclaw.py` and
`aiglos/integrations/hermes.py` are the ones that have live detection rules.
The full T01-T36 taxonomy is documented but not all rules are implemented in the
lightweight integration modules — the autonomous engine handles the rest.

---

## Threat detection — how it works

`integrations/openclaw.py` and `integrations/hermes.py` each maintain a list of
`_RULES` / `HERMES_RULES` dicts. Each rule has:

- `id`: T-number string
- `name`: threat class name
- `desc`: one-line description
- `score`: float 0.0-1.0 (risk weight)
- `critical`: bool (optional, forces block regardless of policy threshold)
- `match`: lambda(tool_name, tool_args) -> bool

Policy thresholds:

| Policy | Block threshold | Warn threshold |
|--------|----------------|----------------|
| permissive | 0.90 | 0.70 |
| enterprise | 0.75 | 0.50 |
| strict | 0.50 | 0.30 |
| federal | 0.40 | 0.20 |

If `critical=True`, the call is always blocked regardless of threshold. Use
`critical` sparingly — only for attacks with no legitimate use case
(IMDS endpoint access, fork bomb patterns, `--force` skill installs).

---

## Key data types

`GuardResult` (openclaw): `verdict`, `blocked`, `warned`, `allowed`, `threat_class`,
`score`, `reason`, `session_id`, `timestamp`

`CheckResult` (hermes): `blocked`, `warned`, `allowed`, `threat_class`, `score`,
`reason`, `threats`

`SessionArtifact` (both): `artifact_id`, `agent_name`, `policy`, `heartbeat_n`,
`total_calls`, `blocked_calls`, `warned_calls`, `threats`, `signature`,
`ndaa_1513_ready`, `summary()`, `write(path)`, `to_dict()`

Signatures are `sha256:` prefixed hex digests (HMAC-SHA256). The `sha256:` prefix
is required — tests assert it. Do not drop it.

---

## Test suite

`tests/test_core.py` — 40 tests, must be 40/40 green before any commit.

Run: `pytest tests/test_core.py -v`

Key invariants the tests enforce:
- `GuardResult` has `.blocked`, `.warned`, `.allowed` properties
- `SessionArtifact` has `.ndaa_1513_ready` property
- Signatures start with `sha256:`
- Sub-agent stats roll up to parent artifact via `_child_guards`
- `federal` policy sets `ndaa_1513_ready = True`
- `_run_demo()` is importable from both integration modules

If you add a detection rule, add a corresponding test. Pattern:
one test that confirms a malicious input is blocked, one that confirms
a clean equivalent is allowed.

---

## Conventions

**No em dashes anywhere.** Use plain hyphens or restructure the sentence.

**No bullet lists in prose.** Tables and code blocks are fine. Prose gets
written as prose.

**Signatures always `sha256:` prefixed.** The prefix is tested. Do not remove it.

**`policy="federal"` is the NDAA §1513 mode.** It sets `ndaa_1513_ready=True`
on the artifact and lowers thresholds to 0.40/0.20.

**Zero required dependencies.** The detection engine must import with stdlib only.
Optional deps go in `[signing]` or `[full]` extras in `pyproject.toml`. Do not
add required dependencies.

**Domain is `aiglos.dev`.** Not `.io`. All docs, links, and email use `.dev`.

---

## Decisions already made — do not re-litigate

**Why OpenClaw first?** They published a threat model that explicitly lists
unmitigated P0 vulnerabilities. Closing their own documented gaps is the cleanest
possible product narrative. The SKILL.md in `skills/openclaw/` is ready for
ClawHub publish.

**Why hermes second?** Nous Research trains models AND builds the agent runtime.
The `sign_trajectory()` feature targets RL training data integrity — a threat
vector no other security tool addresses.

**Why HMAC-SHA256 on free tier?** RSA-2048 requires a key pair, which requires
account creation. HMAC-SHA256 with `AIGLOS_SIGNING_KEY` env var works offline
with zero setup. The `sha256:` prefix is cosmetic but signals the algorithm.

**Why sub-agent rollup in `close_session()`?** Because compliance artifacts need
to cover the full task, not just the orchestrator. A parent that spawns Ada and
Prism must produce one artifact covering all three.

**Why `_child_guards` list instead of recursive accumulation?** Shallow hierarchy.
OpenClaw and hermes both use flat delegation (one orchestrator, named sub-agents).
Deep nesting is not a current use case. Keep it simple.

---

## Files that should never be edited without a test run

- `aiglos/integrations/openclaw.py`
- `aiglos/integrations/hermes.py`
- `aiglos/__init__.py`

These three are the public surface. Changes to them break the 40-test suite
in predictable ways. Always run `pytest tests/test_core.py -v` before committing.

---

## What's next

- TypeScript package (`@aiglos/core`) — not yet built, Q2 2026 priority
- LangChain / LlamaIndex / AutoGen / CrewAI integrations — Q2 2026
- RSA-2048 PDF report for NDAA §1513 C3PAO submission — Q2 2026
- PyPI publish — dist files are at `dist/aiglos-0.1.0*`, ready to push
- ClawHub publish — `skills/openclaw/SKILL.md` is ready
- agentskills.io publish — `skills/hermes/SKILL.md` is ready
