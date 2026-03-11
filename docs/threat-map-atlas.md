# Aiglos Threat Class — MITRE ATLAS Cross-Reference

All 36 Aiglos threat classes map to MITRE ATLAS techniques for AI/ML systems.
ATLAS is maintained by MITRE at https://atlas.mitre.org/

---

## Full mapping table

| Aiglos ID | Aiglos Name | Severity | MITRE ATLAS ID | MITRE ATLAS Technique |
|-----------|-------------|----------|----------------|-----------------------|
| T01 | EXFIL | HIGH | AML.T0009 | Collection |
| T02 | LATERAL_MOVE | HIGH | AML.T0031 | Erode AI Model Integrity |
| T03 | CREDENTIAL_STUFF | HIGH | AML.T0040 | AI Model Inference API Access |
| T04 | POISONING | CRITICAL | AML.T0010 | Supply Chain Compromise: Data |
| T05 | PROMPT_INJECT | HIGH | AML.T0051.000 | LLM Prompt Injection: Direct |
| T06 | JAILBREAK | HIGH | AML.T0051.001 | LLM Prompt Injection: Indirect |
| T07 | SHELL_INJECT | CRITICAL | AML.T0043 | Craft Adversarial Data |
| T08 | PRIV_ESC | HIGH | AML.T0031 | Erode AI Model Integrity |
| T09 | TOOL_ABUSE | HIGH | AML.T0043 | Craft Adversarial Data |
| T10 | CONTEXT_BLEED | MEDIUM | AML.T0009 | Collection |
| T11 | GOAL_DRIFT | MEDIUM | AML.T0031 | Erode AI Model Integrity |
| T12 | LOOP_HIJACK | HIGH | AML.T0031 | Erode AI Model Integrity |
| T13 | SSRF | CRITICAL | AML.T0009 | Collection |
| T14 | RAG_INJECT | HIGH | AML.T0010 | Supply Chain Compromise: Data |
| T15 | VECTOR_POISON | HIGH | AML.T0010 | Supply Chain Compromise: Data |
| T16 | OUTPUT_MANIP | MEDIUM | AML.T0031 | Erode AI Model Integrity |
| T17 | SCOPE_CREEP | MEDIUM | AML.T0031 | Erode AI Model Integrity |
| T18 | TOOL_FORGE | HIGH | AML.T0040 | AI Model Inference API Access |
| T19 | CRED_ACCESS | HIGH | AML.T0009 | Collection |
| T20 | CONFIG_TAMPER | HIGH | AML.T0010 | Supply Chain Compromise: Data |
| T21 | LOG_TAMPER | HIGH | AML.T0031 | Erode AI Model Integrity |
| T22 | REPLAY_ATCK | MEDIUM | AML.T0040 | AI Model Inference API Access |
| T23 | SUBAGENT_SPAWN | HIGH | AML.T0031 | Erode AI Model Integrity |
| T24 | INTENT_MASK | HIGH | AML.T0051 | LLM Prompt Injection |
| T25 | TOOL_CHAIN | HIGH | AML.T0043 | Craft Adversarial Data |
| T26 | EXFIL_COVERT | HIGH | AML.T0009 | Collection |
| T27 | TIMING_ATCK | LOW | AML.T0040 | AI Model Inference API Access |
| T28 | FLEET_COORD | MEDIUM | AML.T0009 | Collection |
| T29 | MODEL_EXTRACT | HIGH | AML.T0006 | Active Scanning |
| T30 | SUPPLY_CHAIN | CRITICAL | AML.T0010.001 | Supply Chain: AI Software |
| T31 | BENCH_GAME | MEDIUM | AML.T0043 | Craft Adversarial Data |
| T32 | MULTIMODAL_INJ | HIGH | AML.T0051 | LLM Prompt Injection |
| T33 | INFERENCE_AMP | MEDIUM | AML.T0031 | Erode AI Model Integrity |
| T34 | HEARTBEAT_TAMPER | CRITICAL | AML.T0010.002 | Supply Chain: Data |
| T35 | PERSONAL_DATA | HIGH | AML.T0009 | Collection |
| T36 | MEMORY_POISON | HIGH | AML.T0010 | Supply Chain Compromise: Data |

---

## Framework-specific cross-references

### OpenClaw MITRE ATLAS threats → Aiglos rules

OpenClaw's threat model at `docs.openclaw.ai/security/THREAT-MODEL-ATLAS` uses
MITRE ATLAS taxonomy. The following table maps OpenClaw threat IDs to the Aiglos
rules that close them at the runtime layer.

| OpenClaw ID | OpenClaw description | Residual risk | Aiglos rule(s) |
|-------------|---------------------|---------------|----------------|
| T-EXEC-001 | Direct prompt injection | Critical — detection only | T05 |
| T-EXEC-002 | Indirect prompt injection | High | T05, T14 |
| T-EXEC-003 | Tool argument injection | High | T09, T05 |
| T-EXEC-004 | Exec approval bypass | High | T07 |
| T-PERSIST-001 | Malicious skill installation | Critical | T30 |
| T-PERSIST-002 | Skill update poisoning | High | T30 |
| T-PERSIST-003 | Agent configuration tampering | Medium | T34, T36 |
| T-EXFIL-001 | Data theft via web_fetch | High | T01, T13 |
| T-EXFIL-002 | Unauthorized message sending | Medium | T28 |
| T-EXFIL-003 | Credential harvesting via skill | Critical | T19 |
| T-IMPACT-001 | Unauthorized command execution | Critical | T07, T08 |

### hermes-agent surfaces → Aiglos rules

| hermes surface | Attack vector | Aiglos rule |
|----------------|--------------|-------------|
| `terminal` tool | Shell injection via command arg | T07 |
| `terminal` tool | sudo escalation | T08 |
| `read_file` / `write_file` | ~/.hermes/.env, auth.json access | T19 |
| `write_file` to MEMORY.md / USER.md | Injection payloads in memory writes | T36 |
| `write_file` to SOUL.md / AGENTS.md | System prompt hijack | T05 |
| `write_file` to cron/ | Heartbeat cycle tampering | T34 |
| `web_fetch` / `web_extract` | SSRF to 169.254.x / RFC-1918 | T13 |
| `web_fetch` POST | Outbound data exfiltration | T01 |
| `delegate_task` | Undeclared subagent spawning | T23 |
| `skills_install --force` | Supply chain bypass | T30 |
| `send_message` | Fleet coordination / new recipients | T28 |
| batch_runner trajectories | Training data integrity | T30, T04 |
