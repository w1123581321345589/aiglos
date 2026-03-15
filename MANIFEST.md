# Aiglos Repository Manifest — v0.10.0

## Package — `aiglos/`

### Public API
| File | Description |
|------|-------------|
| `aiglos/__init__.py` | `attach()` / `check()` / `close()` / `on_heartbeat()` — protocol-agnostic attach with `enable_causal_tracing` and `enable_intent_prediction` kwargs |
| `aiglos/__main__.py` | `python -m aiglos` CLI entry point |
| `aiglos/cli.py` | CLI commands: `stats`, `sessions`, `inspect`, `run`, `amend`, `policy`, `autoresearch`, `scan-skill`, `scan-message`, `trace`, `forecast` |

### Core
| File | Description |
|------|-------------|
| `aiglos/core/__init__.py` | Core package init |
| `aiglos/core/attest.py` | RSA-2048 attestation artifact generator (Pro+) |
| `aiglos/core/causal_tracer.py` | Session-level causal attribution — `CausalTracer`, `CausalChain`, `AttributionResult` (v0.9.0) |
| `aiglos/core/config.py` | SDK configuration |
| `aiglos/core/gates.py` | Feature gate enforcement (free/pro/enterprise) |
| `aiglos/core/intent_predictor.py` | Predictive intent modeling — deployment-specific Markov chain, `IntentPredictor`, `PredictionResult` (v0.10.0) |
| `aiglos/core/interceptor.py` | In-process MCP call interceptor (monkey-patch) |
| `aiglos/core/licensing.py` | License management and tier validation |
| `aiglos/core/metering.py` | Usage metering client (cloud telemetry, Pro+) |
| `aiglos/core/scanner.py` | Fast-path inline threat scanner (<1ms, stdlib only) |
| `aiglos/core/threat_forecast.py` | Session-scoped threshold elevation — `SessionForecaster`, `ForecastAdjustment` (v0.10.0) |

### Integrations
| File | Description |
|------|-------------|
| `aiglos/integrations/__init__.py` | Integrations package init |
| `aiglos/integrations/hermes.py` | Hermes-agent guard — T01-T39 + trajectory signing |
| `aiglos/integrations/http_intercept.py` | HTTP/API surface interceptor — T10-T14, T19, T22, T25, T37 |
| `aiglos/integrations/injection_scanner.py` | Inbound injection scanner — tiered phrase corpus + encoding anomaly detection, `InjectionScanner`, `scan_tool_output` (v0.8.0) |
| `aiglos/integrations/memory_guard.py` | Structured memory write guard — T31, 38-phrase corpus, `MemoryWriteGuard`, `MemoryProvenanceGraph` (v0.5.0) |
| `aiglos/integrations/multi_agent.py` | Multi-agent spawn registry — T38, `AgentDefGuard`, `MultiAgentRegistry`, parent-verified `register_spawn` |
| `aiglos/integrations/openclaw.py` | OpenClaw guard — T01-T39 detection, `enable_causal_tracing`, `enable_intent_prediction`, `ArtifactExtensions` |
| `aiglos/integrations/rl_guard.py` | RL training security — T39, `RLFeedbackGuard`, `SecurityAwareReward` (v0.6.0) |
| `aiglos/integrations/subprocess_intercept.py` | Subprocess/CLI surface interceptor — T07-T08, T11, T19, T38, three-tier blast radius |

### Adaptive layer
| File | Description |
|------|-------------|
| `aiglos/adaptive/__init__.py` | `AdaptiveEngine` — observe → inspect → amend → evaluate loop |
| `aiglos/adaptive/amend.py` | Amendment proposal engine — human-approved rule changes |
| `aiglos/adaptive/campaign.py` | Campaign-mode T06 — 10 multi-step attack patterns including `REPEATED_INJECTION_ATTEMPT`, `EXTERNAL_INSTRUCTION_CHANNEL` |
| `aiglos/adaptive/inspect.py` | 10 inspection triggers — `REWARD_DRIFT`, `CAUSAL_INJECTION_CONFIRMED`, `THREAT_FORECAST_ALERT` |
| `aiglos/adaptive/memory.py` | `MemoryProvenanceGraph` — cross-session belief chain tracking, drift detection |
| `aiglos/adaptive/observation.py` | `ObservationGraph` — SQLite WAL, thread-safe writes, `causal_chains` table, `ingest_causal_result` |
| `aiglos/adaptive/policy.py` | `SessionPolicy` derivation from observation history |

### Autoresearch
| File | Description |
|------|-------------|
| `aiglos/autoresearch/__init__.py` | Autoresearch package — two-loop self-improving detection |
| `aiglos/autoresearch/corpus.py` | Detection corpus management and labeling |
| `aiglos/autoresearch/coupling.py` | `SecurityAwareReward` — wires Aiglos verdicts into RL reward functions |
| `aiglos/autoresearch/loop.py` | Research + adversarial co-evolution loops; run logs are compliance audit evidence |

### Autonomous
| File | Description |
|------|-------------|
| `aiglos/autonomous/__init__.py` | Autonomous package init |
| `aiglos/autonomous/engine.py` | Autonomous hunt engine — continuous background scan |
| `aiglos/autonomous/t30_registry.py` | T30 registry monitor — abstract `RegistryAdapter` (ABC), `NpmAdapter`, `PypiAdapter` |
| `aiglos/autonomous/t34_data_agent.py` | T34 data agent monitor |
| `aiglos/autonomous/t35_personal_agent.py` | T35 personal agent monitor |
| `aiglos/scan_skill.py` | Skill scanner — `scan-skill` CLI surface |

---

## Tests — `tests/` (688 passing)
| File | Tests | Coverage |
|------|-------|----------|
| `tests/test_adaptive.py` | 65 | ObservationGraph, InspectionEngine, CampaignAnalyzer, AdaptiveEngine |
| `tests/test_autoresearch.py` | 21 | Autoresearch loop, SecurityAwareReward |
| `tests/test_byterover.py` | 75 | MemoryWriteGuard — T31, 38-phrase corpus, provenance graph |
| `tests/test_campaign.py` | 25 | All 10 campaign patterns |
| `tests/test_causal_tracer.py` | 48 | CausalTracer, attribution, CAUSAL_INJECTION_CONFIRMED trigger |
| `tests/test_core.py` | 40 | OpenClawGuard, HermesGuard, module API, attach/check/close cycle |
| `tests/test_e2e.py` | 23 | End-to-end scenarios: recon sweep, causal chain, forecast, memory poison, artifact completeness, registry integrity, false positive regression, thread safety, version |
| `tests/test_external_channel.py` | 26 | EXTERNAL_INSTRUCTION_CHANNEL pattern, v0.7.0 scan-message |
| `tests/test_http_intercept.py` | 43 | HTTP surface T10-T14, T19, T22, T25, T37 |
| `tests/test_injection_scanner.py` | 58 | InjectionScanner — tiered corpus, encoding anomaly, false positive regression |
| `tests/test_intent_predictor.py` | 44 | IntentPredictor, MarkovTransitionModel, SessionForecaster, THREAT_FORECAST_ALERT |
| `tests/test_rl_guard.py` | 73 | RLFeedbackGuard, SecurityAwareReward, REWARD_MANIPULATION campaign |
| `tests/test_subprocess_intercept.py` | 76 | Subprocess surface T07-T08, T11, T19, T38, three-tier blast radius |
| `tests/test_v030.py` | 71 | Multi-agent registry, session identity chain, agent def guard |
| `tests/test_licensing.py` | — | License tier validation (excluded from main run) |
| `tests/test_t34.py` | — | T34 heartbeat tamper (excluded from main run) |
| `tests/test_t35.py` | — | T35 personal agent (excluded from main run) |
| `tests/test_t36.py` | — | T36 memory poisoning (excluded from main run) |

---

## Website — `website/`
| File | Description |
|------|-------------|
| `index.html` | Main landing page — "Every surface. Every session. Every belief." |
| `pricing.html` | Pricing tiers (Free / Pro $39 / Enterprise) |
| `defense.html` | Enterprise air-gap deployment page |
| `scan.html` | Skill scanner live demo |
| `docs.html` | Documentation |
| `threats.html` | T01-T39 threat class browser |
| `changelog.html` | Public changelog |
| `demo.html` | Interactive pitch demo |
| `coding-agents.html` | Coding agent (Cursor / Claude Code / Copilot) integration page |

---

## SDK — `sdk/`
| File | Description |
|------|-------------|
| `sdk/typescript/src/index.ts` | TypeScript SDK v0.10.0 — `attach()`, `check()`, `close()`, T01-T39 |

---

## Docs — `docs/`
| File | Description |
|------|-------------|
| `docs/threat-map-atlas.md` | Full MITRE ATLAS cross-reference (T01-T39) |
| `docs/autoresearch-applications.md` | Autoresearch deployment guide |
| `docs/api-cli-interception-spec.md` | HTTP + subprocess interception specification |

---

## Operations
| File | Description |
|------|-------------|
| `pyproject.toml` | Package metadata — version `0.10.0`, zero required dependencies |
| `CHANGELOG.md` | Internal development changelog |
| `SECURITY.md` | Security disclosure policy |
| `CONTRIBUTING.md` | Contribution guide |
| `DEPLOY.md` | Netlify + Stripe deployment checklist |
| `PUSH.md` | GitHub push instructions |

---

## Threat Coverage Summary

| Surface | Rules | Status |
|---------|-------|--------|
| MCP tool calls | T01-T36, T38-T39 | ✓ Intercepted before execution |
| HTTP / API | T10-T14, T19, T22, T25, T37 | ✓ Patched at requests/httpx/aiohttp |
| Subprocess / CLI | T07-T08, T11, T19, T38 | ✓ Three-tier blast radius |
| Inbound content | T27 (extended) | ✓ InjectionScanner on all tool outputs |
| Memory writes | T31 | ✓ MemoryWriteGuard semantic scoring |
| RL training | T39 | ✓ RLFeedbackGuard + SecurityAwareReward |
| Agent definitions | T36_AGENTDEF | ✓ AgentDefGuard semantic scoring |
| Multi-agent spawns | T38 | ✓ Registry with parent verification |

**Campaign patterns (10):** RECON_SWEEP, CREDENTIAL_ACCUMULATE, EXFIL_SETUP, PERSISTENCE_CHAIN, LATERAL_PREP, AGENTDEF_CHAIN, MEMORY_PERSISTENCE_CHAIN, REWARD_MANIPULATION, EXTERNAL_INSTRUCTION_CHANNEL, REPEATED_INJECTION_ATTEMPT

**Inspection triggers (10):** RATE_DROP, ZERO_FIRE, HIGH_OVERRIDE, AGENTDEF_REPEAT, SPAWN_NO_POLICY, FIN_EXEC_BYPASS, FALSE_POSITIVE, REWARD_DRIFT, CAUSAL_INJECTION_CONFIRMED, THREAT_FORECAST_ALERT
