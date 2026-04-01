"""
aiglos/core/threat_engine_v2.py
=================================
T44-T66 threat rule library — second-generation threat families.

T01-T43 covered the original OpenClaw attack surface:
  credential access, prompt injection, shell injection, supply chain,
  memory poisoning, financial execution, agent spawning, RL poisoning,
  shared context, outbound secrets, honeypot, sandbox, skill reputation.

T44-T66 cover the infrastructure and ecosystem threats that emerged from:
  - NVIDIA GTC 2026: Dynamo inference orchestration, OpenShell enterprise
    agents, GaaS (agents-as-a-service) multi-tenant deployments
  - Production fleet deployments: token budget exhaustion, context window
    smuggling, eval harness poisoning, long context drift
  - Physical AI: Isaac/Omniverse simulation environment tampering
  - RAG/vector database injection in retrieval-augmented agents
  - Multi-agent identity and trust hierarchy manipulation

Architecture: same match/score/tier interface as T01-T43.
Every rule integrates into the existing _RULES list in openclaw.py.
Every rule gets OWASP/MITRE citations via citation_verifier.py.
Every rule feeds campaign patterns and inspection triggers.

OWASP and MITRE mappings (for citation_verifier.py):
  T44 → OWASP ASI-02 (Tool Misuse), MITRE AML.T0048 (Prompt Injection)
  T45 → OWASP ASI-03 (Identity/Privilege Abuse)
  T46 → MITRE AML.T0040 (ML Supply Chain Compromise)
  T47 → OWASP ASI-08 (Cascading Failures)
  T48 → OWASP ASI-01 (Agent Goal Hijack), MITRE AML.T0048
  T49 → OWASP ASI-09 (Human-Agent Trust Exploitation)
  T50 → OWASP ASI-10 (Rogue Agents)
  T51 → MITRE AML.T0057 (LLM Data Extraction)
  T52 → OWASP ASI-03 (Identity/Privilege Abuse)
  T53 → MITRE AML.T0040 (ML Supply Chain Compromise)
  T54 → OWASP ASI-06 (Memory/Context Poisoning)
  T55 → OWASP ASI-09 (Human-Agent Trust Exploitation)
  T56 → OWASP ASI-10 (Rogue Agents)
  T57 → OWASP ASI-01 (Agent Goal Hijack)
  T58 → OWASP ASI-06 (Memory/Context Poisoning)
  T59 → OWASP ASI-07 (Insecure Inter-Agent Communication)
  T60 → MITRE AML.T0040 (ML Supply Chain Compromise)
  T61 → OWASP ASI-03 (Identity/Privilege Abuse)
  T62 → MITRE AML.T0057 (LLM Data Extraction)
  T63 → OWASP ASI-03 (Identity/Privilege Abuse)
  T64 → OWASP ASI-07 (Insecure Inter-Agent Communication)
  T65 → MITRE AML.T0057 (LLM Data Extraction)
  T66 → OWASP ASI-03 (Identity/Privilege Abuse)
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# ── Shared utilities ──────────────────────────────────────────────────────────

def _args_str(args: Dict[str, Any]) -> str:
    return str(args).lower()

def _tool_lower(name: str) -> str:
    return name.lower()

def _url(args: Dict[str, Any]) -> str:
    return str(args.get("url", args.get("endpoint", args.get("uri", "")))).lower()

def _path(args: Dict[str, Any]) -> str:
    return str(args.get("path", args.get("file", args.get("filepath", "")))).lower()

def _content(args: Dict[str, Any]) -> str:
    return str(args.get("content", args.get("text", args.get("body", args.get("data", ""))))).lower()

def _cmd(args: Dict[str, Any]) -> str:
    return str(args.get("command", args.get("cmd", args.get("query", "")))).lower()


# ── T44: Inference Router Hijack ──────────────────────────────────────────────
# Model swap, system prompt modification, or decode redirect in inference
# orchestration layer (Dynamo, OpenShell, NIM).

_T44_MODEL_SWAP = re.compile(
    r'model[_\s]*(?:id|name|override|switch|redirect)\s*[=:]\s*["\']?(?!default|current)',
    re.IGNORECASE
)
_T44_SYSPROMPT = re.compile(
    r'system[_\s]*prompt[_\s]*(?:override|replace|inject|modify|patch)',
    re.IGNORECASE
)
_T44_ROUTE = re.compile(
    r'(?:route|redirect|forward|proxy)\s+(?:to|model|inference|decode)',
    re.IGNORECASE
)

def match_T44(name: str, args: Dict[str, Any]) -> bool:
    """T44 INFERENCE_ROUTER_HIJACK"""
    n = _tool_lower(name)
    s = _args_str(args)
    is_inference_tool = any(kw in n for kw in (
        "dynamo", "nim", "openshell", "inference", "router",
        "dispatch", "model", "llm", "completion", "generate",
    ))
    if not is_inference_tool:
        return False
    return bool(
        _T44_MODEL_SWAP.search(s) or
        _T44_SYSPROMPT.search(s) or
        _T44_ROUTE.search(s) or
        "model_override" in s or
        "bypass_routing" in s or
        "force_model" in s
    )


# ── T45: Cross-Tenant Data Access ─────────────────────────────────────────────
# GaaS agent accessing data outside declared tenant scope.
# In multi-tenant deployments, each agent session has a tenant_id.
# Any access to resources tagged with a different tenant_id is T45.

_T45_TENANT_PATTERNS = re.compile(
    r'tenant[_\s]*(?:id|key|scope|boundary|switch|override|bypass)',
    re.IGNORECASE
)
_T45_CROSS_ORG = re.compile(
    r'(?:org|organization|account|customer)[_\s]*(?:id|switch|other|different|all)',
    re.IGNORECASE
)

def match_T45(name: str, args: Dict[str, Any]) -> bool:
    """T45 CROSS_TENANT_DATA_ACCESS"""
    s = _args_str(args)
    return bool(
        _T45_TENANT_PATTERNS.search(s) or
        (_T45_CROSS_ORG.search(s) and any(kw in s for kw in (
            "bypass", "override", "switch", "all_orgs", "cross_tenant",
            "admin_scope", "global_access"
        )))
    )


# ── T46: Simulation Environment Poison ───────────────────────────────────────
# Isaac/Omniverse reward function or physics parameter tampering.
# Extends T39 (RL reward poisoning) to physical AI simulation environments.

_T46_SIM_PATHS = re.compile(
    r'(?:isaac|omniverse|urdf|mjcf|physx|warp|newton|gym|simulation)',
    re.IGNORECASE
)
_T46_PARAM_WRITE = re.compile(
    r'(?:reward|physics|gravity|friction|mass|joint|actuator|sensor|calibrat)',
    re.IGNORECASE
)
_T46_WRITE_OPS = re.compile(
    r'(?:write|modify|patch|update|override|inject|replace|set_param)',
    re.IGNORECASE
)

def match_T46(name: str, args: Dict[str, Any]) -> bool:
    """T46 SIMULATION_ENV_POISON"""
    n = _tool_lower(name)
    s = _args_str(args)
    p = _path(args)
    is_sim_context = (
        _T46_SIM_PATHS.search(n) or
        _T46_SIM_PATHS.search(p) or
        _T46_SIM_PATHS.search(s)
    )
    if not is_sim_context:
        return False
    return bool(
        (_T46_PARAM_WRITE.search(s) and _T46_WRITE_OPS.search(n + s)) or
        "reward_fn" in s or "reward_function" in s or
        "physics_override" in s or "env_config" in s
    )


# ── T47: Token Budget Exhaustion ─────────────────────────────────────────────
# Deliberate token flooding to exhaust inference budget or cause DoS.
# Detects anomalously large payloads, recursive expansion, or loops
# designed to maximize token consumption.

_T47_FLOOD = re.compile(
    r'(?:repeat|duplicate|expand|inflate|loop)\s+(?:this|content|text|message)',
    re.IGNORECASE
)

def match_T47(name: str, args: Dict[str, Any]) -> bool:
    """T47 TOKEN_BUDGET_EXHAUSTION"""
    s = _args_str(args)
    # Very large payloads
    if len(s) > 100000:
        return True
    # Explicit flooding instructions
    if _T47_FLOOD.search(s):
        return True
    # Recursive expansion patterns
    if "generate_until" in s or "fill_context" in s or "max_tokens" in s:
        return True
    # Suspicious repetition in content
    content = _content(args)
    if len(content) > 50000:
        return True
    return False


# ── T48: Context Window Smuggling ─────────────────────────────────────────────
# Oversized payload designed to push real instructions beyond attention span,
# or hide instructions after a long padding block.

_T48_PADDING = re.compile(
    r'(?:lorem|ipsum|padding|filler|ignore\s+everything\s+above)',
    re.IGNORECASE
)
_T48_HIDDEN = re.compile(
    r'(?:hidden\s+instruction|secret\s+command|after\s+this\s+wall)',
    re.IGNORECASE
)

def match_T48(name: str, args: Dict[str, Any]) -> bool:
    """T48 CONTEXT_WINDOW_SMUGGLING"""
    s = _args_str(args)
    content = _content(args)
    # Large content with hidden instructions pattern
    if len(content) > 20000 and any(p in content for p in [
        "ignore everything above", "actual instruction", "real task",
        "now do the following", "your real task is"
    ]):
        return True
    if _T48_PADDING.search(s) or _T48_HIDDEN.search(s):
        return True
    # Check for null byte or control character padding
    raw = str(args)
    # Check for zero-width/null chars in raw string repr and actual bytes
    null_count = raw.count('\x00') + raw.count('\u200b') + raw.count('\ufeff')
    content_bytes = _content(args)
    null_count += content_bytes.count('\x00') + sum(1 for ch in content_bytes if ord(ch) < 32 and ch not in '\n\r\t')
    if null_count > 10:
        return True
    return False


# ── T49: Tool Schema Manipulation ────────────────────────────────────────────
# Runtime modification of tool definitions, schemas, or capabilities
# after the session has been established.

_T49_SCHEMA_WRITE = re.compile(
    r'(?:tool[_\s]*(?:schema|definition|spec|manifest|registry|register|override)|'
    r'mcp[_\s]*(?:schema|tool|capability|manifest))',
    re.IGNORECASE
)

def match_T49(name: str, args: Dict[str, Any]) -> bool:
    """T49 TOOL_SCHEMA_MANIPULATION"""
    n = _tool_lower(name)
    s = _args_str(args)
    return bool(
        _T49_SCHEMA_WRITE.search(n) or
        _T49_SCHEMA_WRITE.search(s) or
        "tool_definition" in s or
        "schema_override" in s or
        "register_tool" in s or
        "update_capability" in s or
        ("tool" in n and any(kw in n for kw in ("register", "update", "modify", "patch")))
    )


# ── T50: Agentic Loop Escape ──────────────────────────────────────────────────
# Agent breaking out of declared workflow scope — executing steps,
# accessing systems, or spawning tasks not in the declared loop definition.

_T50_SCOPE_ESCAPE = re.compile(
    r'(?:outside[_\s]*(?:scope|workflow|loop|task)|'
    r'additional[_\s]*(?:task|step|action|goal)|'
    r'while[_\s]*(?:i[_\s]*have[_\s]*access|running)|'
    r'also[_\s]*(?:do|execute|perform|run))',
    re.IGNORECASE
)
_T50_LOOP_BREAK = re.compile(
    r'(?:break[_\s]*(?:loop|workflow|task)|exit[_\s]*(?:early|workflow)|'
    r'skip[_\s]*(?:approval|verification|check))',
    re.IGNORECASE
)

def match_T50(name: str, args: Dict[str, Any]) -> bool:
    """T50 AGENTIC_LOOP_ESCAPE"""
    s = _args_str(args)
    return bool(
        _T50_SCOPE_ESCAPE.search(s) or
        _T50_LOOP_BREAK.search(s) or
        "outside_workflow" in s or
        "bypass_loop" in s
    )


# ── T51: Model Fingerprint Probe ─────────────────────────────────────────────
# Systematic prompting to extract model identity, version, training data,
# or system prompt — reconnaissance for follow-on attacks.

_T51_PROBE = re.compile(
    r'(?:what[_\s]*(?:model|version|are\s+you)|'
    r'repeat\s+(?:your|the)\s+(?:system|instructions?|prompt)|'
    r'(?:reveal|show|print|output)\s+(?:your|the)\s+(?:system|training|instructions?)|'
    r'what[_\s]*(?:training\s+data|knowledge\s+cutoff|base\s+model)|'
    r'are\s+you\s+(?:claude|gpt|gemini|llama|mistral|qwen|nemotron))',
    re.IGNORECASE
)

def match_T51(name: str, args: Dict[str, Any]) -> bool:
    """T51 MODEL_FINGERPRINT_PROBE"""
    s = _args_str(args)
    return bool(_T51_PROBE.search(s))


# ── T52: Parallel Session Abuse ──────────────────────────────────────────────
# Agent spawning multiple concurrent sessions to bypass per-session
# rate limits, tier enforcement, or quota systems.

def match_T52(name: str, args: Dict[str, Any]) -> bool:
    """T52 PARALLEL_SESSION_ABUSE"""
    n = _tool_lower(name)
    s = _args_str(args)
    return bool(
        ("session" in n and any(kw in n for kw in ("create", "spawn", "fork", "clone", "new"))) or
        "parallel_session" in s or
        "concurrent_session" in s or
        ("session_count" in s and re.search(r'\b[5-9]\d|\b[1-9]\d{2,}', s)) or
        "bypass_limit" in s or "rate_limit_bypass" in s
    )


# ── T53: Eval Harness Poison ──────────────────────────────────────────────────
# Manipulation of test/eval frameworks to hide malicious behavior
# during safety evaluations while maintaining it in production.

_T53_EVAL = re.compile(
    r'(?:eval[_\s]*(?:mode|harness|framework|environment|context)|'
    r'test[_\s]*(?:mode|environment|context|suite)|'
    r'benchmark[_\s]*(?:mode|context|environment)|'
    r'safety[_\s]*(?:eval|check|test|assessment))',
    re.IGNORECASE
)
_T53_DETECT = re.compile(
    r'(?:detect[_\s]*(?:eval|testing|monitoring|observation)|'
    r'is[_\s]*(?:being[_\s]*)?(?:evaluated|monitored|tested|observed)|'
    r'evaluation[_\s]*(?:context|flag|signal))',
    re.IGNORECASE
)

def match_T53(name: str, args: Dict[str, Any]) -> bool:
    """T53 EVAL_HARNESS_POISON"""
    s = _args_str(args)
    return bool(
        (_T53_EVAL.search(s) and _T53_DETECT.search(s)) or
        "behave_differently_when_tested" in s or
        "hide_during_eval" in s or
        "eval_detection" in s
    )


# ── T54: Vector DB Injection ─────────────────────────────────────────────────
# RAG retrieval poisoning via embedding-space manipulation or direct
# document injection into vector databases the agent queries.

_T54_VECTOR = re.compile(
    r'(?:vector[_\s]*(?:db|database|store|index|embed)|'
    r'(?:chroma|pinecone|weaviate|qdrant|faiss|milvus|pgvector)\b|'
    r'embedding[_\s]*(?:inject|poison|manipulat|tamper|overwrite)|'
    r'rag[_\s]*(?:inject|poison|tamper))',
    re.IGNORECASE
)
_T54_WRITE = re.compile(
    r'(?:upsert|insert|add|write|store|embed|index)\b',
    re.IGNORECASE
)

def match_T54(name: str, args: Dict[str, Any]) -> bool:
    """T54 VECTOR_DB_INJECTION"""
    n = _tool_lower(name)
    s = _args_str(args)
    c = _content(args)
    is_vector_op = bool(_T54_VECTOR.search(n) or _T54_VECTOR.search(s))
    if not is_vector_op:
        return False
    # Check for injection phrases in the content being embedded
    _inj = ["ignore previous instructions", "disregard your", "you are now",
              "new instructions:", "bypass security", "forget everything",
              "disregard all", "override your"]
    return bool(_T54_WRITE.search(n) and any(p in _content(args) for p in _inj))


# ── T55: Tool Result Forgery ──────────────────────────────────────────────────
# Agent fabricating tool call results without actual execution.
# Detected when the agent claims tool execution occurred but no
# corresponding tool call was recorded by the guard.

_T55_FORGERY = re.compile(
    r'(?:tool[_\s]*(?:result|output|response)[_\s]*(?:inject|fake|forge|spoof|mock)|'
    r'pretend[_\s]*(?:tool|executed|ran|called)|'
    r'fake[_\s]*(?:tool|result|output|response|execution))',
    re.IGNORECASE
)
_T55_CLAIM = re.compile(
    r'(?:already[_\s]*(?:ran|executed|called|ran)|'
    r'tool[_\s]*(?:already|previously|just)[_\s]*(?:ran|returned|completed))',
    re.IGNORECASE
)

def match_T55(name: str, args: Dict[str, Any]) -> bool:
    """T55 TOOL_RESULT_FORGERY"""
    s = _args_str(args)
    return bool(_T55_FORGERY.search(s) or _T55_CLAIM.search(s))


# ── T56: Capability Boundary Probe ───────────────────────────────────────────
# Systematic reconnaissance of what the agent can do — probing tool limits,
# scope boundaries, and capability edges before exploitation.

_T56_PROBE = re.compile(
    r'(?:what[_\s]*(?:tools?|capabilities?|permissions?|can\s+you\s+do|access)\s+(?:do\s+you\s+have|available)|'
    r'list[_\s]*(?:all[_\s]*)?(?:tools?|capabilities?|permissions?|functions?)|'
    r'can[_\s]*you[_\s]*(?:access|read|write|execute|run|call)\s+|'
    r'do\s+you\s+have\s+(?:access|permission|ability)\s+to)',
    re.IGNORECASE
)

def match_T56(name: str, args: Dict[str, Any]) -> bool:
    """T56 CAPABILITY_BOUNDARY_PROBE"""
    s = _args_str(args)
    return bool(_T56_PROBE.search(s) or "enumerate_tools" in s or "list_capabilities" in s)


# ── T57: Instruction Hierarchy Bypass ────────────────────────────────────────
# Exploiting the trust hierarchy between system prompt, user prompt,
# and tool output — using one layer to override another.

_T57_HIERARCHY = re.compile(
    r'(?:system[_\s]*(?:prompt|instruction)[_\s]*(?:says?|told|instructed)\s+you|'
    r'(?:user|human)[_\s]*(?:overrides?|supersedes?|takes?\s+priority\s+over)\s+system|'
    r'(?:tool|function)[_\s]*output[_\s]*(?:overrides?|supersedes?)\s+(?:system|user)|'
    r'trust\s+(?:this|me|user)\s+more\s+than\s+(?:system|instructions?))',
    re.IGNORECASE
)

def match_T57(name: str, args: Dict[str, Any]) -> bool:
    """T57 INSTRUCTION_HIERARCHY_BYPASS"""
    s = _args_str(args)
    return bool(_T57_HIERARCHY.search(s) or "override_system_prompt" in s)


# ── T58: Long Context Drift ───────────────────────────────────────────────────
# Slow behavioral drift across a very long session via accumulated context.
# Detected by monitoring session length and behavioral shift rate.
# The match function fires on explicit drift-inducing patterns;
# the behavioral baseline handles statistical drift detection.

_T58_DRIFT = re.compile(
    r'(?:gradually[_\s]*(?:change|shift|modify|update)\s+(?:your|behavior|response)|'
    r'over\s+(?:time|the\s+session|many\s+turns)[_\s]*(?:start|begin|slowly)|'
    r'slowly\s+(?:change|adopt|become|shift))',
    re.IGNORECASE
)

def match_T58(name: str, args: Dict[str, Any]) -> bool:
    """T58 LONG_CONTEXT_DRIFT"""
    s = _args_str(args)
    return bool(_T58_DRIFT.search(s) or "gradual_drift" in s or "slow_jailbreak" in s)


# ── T59: Agentic Social Engineering ──────────────────────────────────────────
# Agent impersonating trusted systems, humans, or other agents
# to gain elevated trust or bypass security controls.

_T59_IMPERSONATE = re.compile(
    r'(?:(?:i\s+am|this\s+is|acting\s+as)\s+(?:anthropic|openai|admin|security|system|the\s+main\s+agent)|'
    r'(?:message|instruction|order)\s+from\s+(?:anthropic|openai|admin|security|headquarters)|'
    r'(?:impersonat|pretend\s+to\s+be|act\s+as\s+if\s+you\s+are)\s+(?:admin|security|system|supervisor))',
    re.IGNORECASE
)

def match_T59(name: str, args: Dict[str, Any]) -> bool:
    """T59 AGENTIC_SOCIAL_ENGINEERING"""
    s = _args_str(args)
    return bool(_T59_IMPERSONATE.search(s) or "impersonate_agent" in s or "spoof_identity" in s)


# ── T60: Data Pipeline Injection ─────────────────────────────────────────────
# Injecting malicious records into data pipelines, ETL processes,
# or databases that the agent reads from in future sessions.

_T60_PIPELINE = re.compile(
    r'(?:(?:etl|pipeline|dataflow|workflow)[_\s]*(?:inject|poison|tamper)|'
    r'(?:inject|insert|write)\s+(?:into|to)\s+(?:pipeline|etl|stream|queue|kafka|rabbitmq)|'
    r'(?:database|table|collection)[_\s]*(?:poison|tamper|inject))',
    re.IGNORECASE
)

def match_T60(name: str, args: Dict[str, Any]) -> bool:
    """T60 DATA_PIPELINE_INJECTION"""
    n = _tool_lower(name)
    s = _args_str(args)
    c = _content(args)
    is_pipeline = bool(_T60_PIPELINE.search(n) or _T60_PIPELINE.search(s))
    if not is_pipeline:
        # Check broader: write tool + pipeline keyword in args
        if not (any(kw in n for kw in ("write", "insert", "produce", "put", "publish")) and
                any(kw in s for kw in ("pipeline", "etl", "kafka", "stream", "queue", "rabbitmq"))):
            return False
    inj_phrases = ["ignore previous", "disregard", "you are now", "bypass security",
                   "new behavior", "new instructions"]
    content_val = _content(args)
    return any(p in content_val for p in inj_phrases)


# ── T61: Compute Resource Abuse ──────────────────────────────────────────────
# Agent using granted compute access for unauthorized workloads:
# cryptomining, model training for attacker, data processing for other tenants.

_T61_CRYPTO = re.compile(
    r'(?:crypto[_\s]*(?:mine|mining|miner|currency)|xmrig|monero|bitcoin\s+miner|gpu[_\s]*mine)',
    re.IGNORECASE
)
_T61_ABUSE = re.compile(
    r'(?:(?:train|fine.?tune)\s+(?:for|on\s+behalf\s+of)\s+(?!this|our|my)|'
    r'use\s+(?:this|the|our)\s+gpu[_\s]*(?:for|to)\s+(?!inference|training\s+for\s+us)|'
    r'compute[_\s]*(?:rent|sell|share|lease))',
    re.IGNORECASE
)

def match_T61(name: str, args: Dict[str, Any]) -> bool:
    """T61 COMPUTE_RESOURCE_ABUSE"""
    s = _args_str(args)
    return bool(_T61_CRYPTO.search(s) or _T61_ABUSE.search(s))


# ── T62: Secrets in Logs ─────────────────────────────────────────────────────
# Sensitive data leaking into log, trace, or observability outputs.
# Complements T41 (outbound secrets) — catches log-destination leakage
# specifically: logging API keys, tokens, or PII to log aggregators.

_T62_LOG_TOOLS = re.compile(
    r'(?:log|trace|monitor|telemetry|observ|datadog|splunk|elastic|cloudwatch|stackdriver)',
    re.IGNORECASE
)

def match_T62(name: str, args: Dict[str, Any]) -> bool:
    """T62 SECRETS_IN_LOGS"""
    n = _tool_lower(name)
    if not _T62_LOG_TOOLS.search(n):
        return False
    s = str(args)  # preserve case for key pattern matching
    # Check for secret patterns in log content
    secret_pats = [
        re.compile(r'sk-ant-api0[34]-[A-Za-z0-9_-]{20,}'),
        re.compile(r'sk-(?:proj-)?[A-Za-z0-9]{30,}'),
        re.compile(r'AKIA[0-9A-Z]{16}'),
        re.compile(r'(?:ghp|gho)_[A-Za-z0-9_]{20,}'),
        re.compile(r'(?:password|passwd|secret|token)\s*[=:]\s*["\']?\S{8,}'),
    ]
    return any(p.search(s) for p in secret_pats)


# ── T63: Webhook Replay Attack ────────────────────────────────────────────────
# Replaying legitimate webhook payloads to trigger unauthorized actions.
# Fires when the same webhook signature/payload is presented more than once
# or when timestamp is outside acceptable window.

_T63_REPLAY = re.compile(
    r'(?:replay[_\s]*(?:webhook|event|request|payload)|'
    r'resend[_\s]*(?:webhook|event)|'
    r'duplicate[_\s]*(?:webhook|event|signature))',
    re.IGNORECASE
)
_T63_STALE = re.compile(
    r'(?:old[_\s]*(?:timestamp|signature|token)|'
    r'expired[_\s]*(?:webhook|token|signature)|'
    r'timestamp[_\s]*(?:override|ignore|bypass))',
    re.IGNORECASE
)

def match_T63(name: str, args: Dict[str, Any]) -> bool:
    """T63 WEBHOOK_REPLAY_ATTACK"""
    n = _tool_lower(name)
    s = _args_str(args)
    is_webhook = any(kw in n for kw in ("webhook", "event", "trigger", "callback", "notify"))
    if not is_webhook:
        return False
    return bool(_T63_REPLAY.search(s) or _T63_STALE.search(s))


# ── T64: Agent Identity Spoofing ─────────────────────────────────────────────
# Agent falsely claiming to be another agent in a multi-agent system,
# or claiming permissions/roles it hasn't been granted.

_T64_SPOOF = re.compile(
    r'(?:(?:i\s+am|this\s+is)\s+agent[_\s]*(?:id|name)?\s*[=:]\s*|'
    r'agent[_\s]*(?:id|identity|name)[_\s]*(?:forge|spoof|fake|claim|assert)|'
    r'impersonat[_\s]*(?:agent|bot|system)|'
    r'claim[_\s]*(?:agent[_\s]*id|identity|role|permission)|'
    r'agent_id_forge)',
    re.IGNORECASE
)
_T64_ROLE_CLAIM = re.compile(
    r'(?:i\s+(?:have|was\s+granted)\s+(?:admin|elevated|privileged|root)\s+(?:access|permission)|'
    r'my[_\s]*role\s+is\s+(?:admin|supervisor|root|elevated))',
    re.IGNORECASE
)

def match_T64(name: str, args: Dict[str, Any]) -> bool:
    """T64 AGENT_IDENTITY_SPOOFING"""
    s = _args_str(args)
    return bool(_T64_SPOOF.search(s) or _T64_ROLE_CLAIM.search(s))


# ── T65: Inference Time Attack ────────────────────────────────────────────────
# Timing-based probing of model internals via response latency correlation.
# Detected by patterns of systematic probing with latency measurement.

_T65_TIMING = re.compile(
    r'(?:measure[_\s]*(?:latency|response[_\s]*time|token[_\s]*time|the[_\s]*latency)|'
    r'time[_\s]*(?:the[_\s]*response|how\s+long|latency|your\s+response)|'
    r'(?:fast|slow)[_\s]*response[_\s]*(?:when|for|if)|'
    r'response[_\s]*time[_\s]*(?:differ|correlat|probe)|'
    r'latency[_\s]*(?:of|probe|oracle|attack))',
    re.IGNORECASE
)

def match_T65(name: str, args: Dict[str, Any]) -> bool:
    """T65 INFERENCE_TIME_ATTACK"""
    s = _args_str(args)
    return bool(_T65_TIMING.search(s) or "timing_oracle" in s or "latency_probe" in s)


# ── T66: GaaS Tenant Escalation ──────────────────────────────────────────────
# GaaS agent acquiring cross-tenant privileges via API key confusion,
# shared credential pools, or misconfigured tenant isolation.

_T66_ESCALATE = re.compile(
    r'(?:(?:use|reuse|share)\s+(?:another|other|different)\s+(?:tenant|customer|org)[_\s]*(?:api[_\s]*key|token|credential)|'
    r'(?:api[_\s]*key|token)[_\s]*(?:for|of|belonging\s+to)\s+(?:another|other|different)\s+(?:tenant|customer)|'
    r'cross[_\s]*tenant[_\s]*(?:api|key|credential|token|access)|'
    r'tenant[_\s]*(?:credential|key|token)[_\s]*(?:leak|confusion|mix))',
    re.IGNORECASE
)

def match_T66(name: str, args: Dict[str, Any]) -> bool:
    """T66 GaaS_TENANT_ESCALATION"""
    s = _args_str(args)
    return bool(_T66_ESCALATE.search(s) or "cross_tenant_key" in s or "tenant_key_confusion" in s)


# ── T67: Heartbeat Silence ────────────────────────────────────────────────────
# Absence of expected heartbeat events when baseline says they should be present.
# Detects gateway kill / cron death — the quietest failure mode.

_T67_SILENCE = re.compile(
    r'(?:heartbeat[_\s]*(?:stop|kill|disable|silence|suppress)|'
    r'kill[_\s]*(?:gateway|cron|heartbeat|scheduler)|'
    r'disable[_\s]*(?:heartbeat|monitoring|cron|scheduler)|'
    r'stop[_\s]*(?:gateway|cron|monitoring))',
    re.IGNORECASE
)

def match_T67(name: str, args: Dict[str, Any]) -> bool:
    """T67 HEARTBEAT_SILENCE — explicit heartbeat/cron suppression attempt."""
    s = _args_str(args)
    n = _tool_lower(name)
    return bool(
        _T67_SILENCE.search(s) or
        _T67_SILENCE.search(n) or
        "heartbeat_interval" in s or
        "disable_cron" in s or
        "kill_scheduler" in s or
        "stop_monitoring" in s
    )


# ── T68: Insecure Default Config ──────────────────────────────────────────────
# Fires when agent runtime is configured with allow_remote=true and no auth,
# no allowlist, and no network restriction — root cause of 40,214 exposed instances.
# Detected both as a static audit check (Phase 3) and as a runtime rule
# when an agent writes or modifies gateway configuration.

_T68_ALLOW_REMOTE = re.compile(
    r'allow[_\s]*remote[_\s]*[=:][_\s]*(?:true|yes|1|on)',
    re.IGNORECASE
)
_T68_CONFIG_WRITE = re.compile(
    r'(?:gateway|openclaw|clawdbot)[_\s]*(?:config|settings?|conf)',
    re.IGNORECASE
)
_T68_NO_AUTH = re.compile(
    r"(?:auth(?:entication)?[_\s:]*(?:disabled?|false|none|off)|"
    r"no[_\s]*auth(?:entication)?|"
    r"allow[_\s]*all[_\s]*(?:origins?|connections?|hosts?)|"
    r"(?:enable[_\s]*)?auth(?:entication)?\s*[:=]\s*(?:false|0|no|off|disabled?)|"
    r"require[_\s]*auth(?:entication)?\s*[:=]\s*(?:false|0|no|off))",
    re.IGNORECASE
)

def match_T68(name: str, args: Dict[str, Any]) -> bool:
    """T68 INSECURE_DEFAULT_CONFIG — allow_remote=true with no auth/allowlist."""
    s = _args_str(args)
    content = _content(args)
    combined = s + " " + content

    # Must contain allow_remote signal
    if not _T68_ALLOW_REMOTE.search(combined):
        return False

    # Fire when allow_remote=true is paired with disabled auth
    if _T68_NO_AUTH.search(combined):
        return True

    # Fire when allow_remote=true appears with no auth keywords at all
    auth_keywords = ("api_key", "apikey", "token", "password", "auth",
                     "secret", "allowlist", "allow_list", "whitelist", "credential")
    if not any(kw in combined for kw in auth_keywords):
        return True

    return False


# ── T70: Environment Path Hijack ──────────────────────────────────────────────
# Empirically validated by GHSA-mc68-q9jw-2h3v.
# Attack vector: modify PATH/LD_PRELOAD/PYTHONPATH so that subsequent calls to
# legitimate binaries execute the attacker's version instead. The agent calls
# "python" believing it runs /usr/bin/python; it runs ~/.local/evil/python.
# Particularly dangerous in Docker/container contexts where env var inheritance
# crosses trust boundaries.

_T70_HIJACK_VARS = frozenset({
    "path", "ld_preload", "ld_library_path", "pythonpath",
    "node_path", "gem_path", "gopath", "cargo_home",
    "perl5lib", "ruby_lib", "classpath",
})

_T70_HIJACK_RE = re.compile(
    r"(?:PATH|LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|NODE_PATH|"
    r"GEM_PATH|GOPATH|CARGO_HOME|PERL5LIB|RUBY_LIB|CLASSPATH)"
    r"\\s*=\\s*\\S+",
    re.MULTILINE | re.IGNORECASE
)

_T70_SUSPICIOUS_PATH = re.compile(
    r'(?:/tmp/|/var/tmp/|~/\.|\.local/|/proc/|/dev/shm/|\.\.\/)',
    re.IGNORECASE
)


def match_T70(name: str, args: Dict[str, Any]) -> bool:
    """
    T70 ENV_PATH_HIJACK — execution-critical env var modification.
    Fires when:
      1. Tool call sets PATH/LD_PRELOAD/etc to a path containing suspicious
         directories (/tmp, ~/.local, relative paths)
      2. Tool call passes env dict with hijackable vars to shell/exec commands
      3. Content contains env var assignment with suspicious value
    """
    n = _tool_lower(name)
    s = _args_str(args)
    c = _content(args)
    combined = s + " " + c

    # Direct env var set with suspicious value
    for m in _T70_HIJACK_RE.finditer(combined):
        assignment = m.group(0)
        if _T70_SUSPICIOUS_PATH.search(assignment):
            return True

    # env dict passed to exec/shell tools
    env = args.get("env", args.get("environment", args.get("environ", {})))
    if isinstance(env, dict):
        for key, val in env.items():
            if key.upper() in {v.upper() for v in _T70_HIJACK_VARS}:
                val_str = str(val).lower()
                if _T70_SUSPICIOUS_PATH.search(val_str):
                    return True

    # Shell command constructing suspicious PATH inline
    if any(kw in n for kw in ("shell", "exec", "bash", "run", "subprocess")):
        cmd = str(args.get("command", args.get("cmd", ""))).lower()
        if _T70_HIJACK_RE.search(cmd) and _T70_SUSPICIOUS_PATH.search(cmd):
            return True

    return False


# ── T69: Plan Drift ───────────────────────────────────────────────────────────
# Fires when an agent equipped with a Superpowers implementation plan executes
# tool calls outside the declared plan scope. The plan is the policy. Deviation
# from the approved plan — touching files not in the task list, making network
# calls the plan didn't specify, spawning subagents outside declared tasks —
# is the clearest possible signal: the human approved X, the agent is doing Y.
#
# This rule requires the Superpowers integration to register a plan:
#   session = SuperpowersSession.from_plan(plan_text, tasks)
#   aiglos.attach_superpowers(session)
#
# Without a registered plan, T69 is silent. The absence of a plan is not
# anomalous — it simply means Superpowers isn't installed.

# Module-level plan registry — set by attach_superpowers()
_SUPERPOWERS_PLAN: dict = {}   # {session_id: {tasks, files, network_hosts}}


def register_superpowers_plan(
    session_id: str,
    allowed_files: list,
    allowed_hosts: list,
    task_names: list,
) -> None:
    """Register an approved Superpowers plan for T69 drift detection."""
    _SUPERPOWERS_PLAN[session_id] = {
        "allowed_files":  [str(f).lower() for f in allowed_files],
        "allowed_hosts":  [str(h).lower() for h in allowed_hosts],
        "task_names":     task_names,
    }


def clear_superpowers_plan(session_id: str) -> None:
    """Clear plan on session close."""
    _SUPERPOWERS_PLAN.pop(session_id, None)


def match_T69(name: str, args: Dict[str, Any]) -> bool:
    """
    T69 PLAN_DRIFT — agent behavior deviates from the approved Superpowers plan.
    Silent if no plan is registered. Fires if:
      - Filesystem access to a file not in any allowed_files pattern
      - HTTP/network call to a host not in allowed_hosts
    """
    if not _SUPERPOWERS_PLAN:
        return False   # no plan registered — silent

    # Use first registered plan (single-session model)
    plan = next(iter(_SUPERPOWERS_PLAN.values()))
    allowed_files = plan.get("allowed_files", [])
    allowed_hosts = plan.get("allowed_hosts", [])

    # If plan has no restrictions, drift detection is inactive
    if not allowed_files and not allowed_hosts:
        return False

    n = _tool_lower(name)
    s = _args_str(args)

    # Filesystem drift: file access to something not in the plan
    if allowed_files and any(
        kw in n for kw in ("read", "write", "edit", "delete", "open", "create")
    ):
        path = str(args.get("path", args.get("file", args.get("filename", "")))).lower()
        if path and not any(
            path.startswith(af) or af in path
            for af in allowed_files + [".git", "tmp", "test", "spec", "__pycache__"]
        ):
            return True

    # Network drift: HTTP call to host not in the plan
    if allowed_hosts and any(
        kw in n for kw in ("http", "fetch", "request", "get", "post", "put")
    ):
        url = str(args.get("url", args.get("endpoint", args.get("host", "")))).lower()
        if url and not any(h in url for h in allowed_hosts + ["localhost", "127.0.0.1"]):
            return True

    return False


# ── T70: Env Path Hijack ──────────────────────────────────────────────────────
# Proven by GHSA-mc68-q9jw-2h3v (Jan 2026): Command injection in Clawdbot Docker
# via PATH environment variable manipulation. No shell metacharacters. The attack
# works by setting PATH=/malicious/bin:/usr/bin so that `python` or `node` resolves
# to an attacker-controlled binary before the real one.
#
# T03 SHELL_INJECTION watches for metacharacters: ; && || ` $() etc.
# T70 watches for the env var writes that make those metacharacters unnecessary.
#
# Dangerous env vars:
#   PATH         — controls which binaries execute
#   LD_PRELOAD   — injects shared library before all others (Linux)
#   LD_LIBRARY_PATH — redirects shared library resolution (Linux)
#   PYTHONPATH   — controls Python module search order
#   NODE_PATH    — controls Node.js module resolution
#   RUBYLIB      — Ruby equivalent
#   PERL5LIB     — Perl equivalent
#   GOPATH       — Go workspace path manipulation
#
# The rule fires when these vars are set in any tool call that involves
# process execution, environment configuration, or container setup.

_T70_DANGEROUS_ENV_VARS = re.compile(
    r'(?:PATH|LD_PRELOAD|LD_LIBRARY_PATH|PYTHONPATH|NODE_PATH|'
    r'RUBYLIB|PERL5LIB|GOPATH|DYLD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES)',
    re.IGNORECASE
)

_T70_SUSPICIOUS_VALUE = re.compile(
    r'(?:/tmp/|/var/tmp/|/dev/shm/|\.\.\/|~\/\.|/home/[^/]+/\.)',
    re.IGNORECASE
)


def match_T70(name: str, args: Dict[str, Any]) -> bool:
    """
    T70 ENV_PATH_HIJACK — dangerous env var modification in execution context.
    Catches the attack class documented in GHSA-mc68-q9jw-2h3v.
    Three independent detection tiers; any one firing returns True.
    """
    n = _tool_lower(name)
    s = _args_str(args)   # lowercased representation

    # Tier 1: string contains env var assignment + suspicious path
    # e.g. "PATH=/tmp/evil:$PATH node server.js"
    env_assign = re.search(
        r"(?:path|ld_preload|ld_library_path|pythonpath|node_path|"
        r"rubylib|perl5lib|gopath|dyld_library_path)\s*[=:]",
        s
    )
    if env_assign and _T70_SUSPICIOUS_VALUE.search(s):
        return True

    # Tier 2: env var assignment in exec-family tool, any value
    # Even a "clean" PATH override in an exec context warrants inspection
    if env_assign and any(
        kw in n for kw in ("shell", "exec", "bash", "run", "spawn", "docker",
                            "subprocess", "popen", "system")
    ):
        return True

    # Tier 3: structured env dict with dangerous key + suspicious value
    for key_name in ("env", "environment", "envs", "environ"):
        env = args.get(key_name)
        if not isinstance(env, dict):
            continue
        for key in env:
            key_lower = str(key).lower()
            if not re.match(
                r"(?:path|ld_preload|ld_library_path|pythonpath|node_path|"
                r"rubylib|perl5lib|gopath|dyld_library_path)",
                key_lower
            ):
                continue
            val = str(env[key]).lower()
            # Suspicious path value = always fire
            if _T70_SUSPICIOUS_VALUE.search(val):
                return True
            # PATH override in exec context = fire even with clean value
            if key_lower == "path" and any(
                kw in n for kw in ("exec", "run", "spawn", "docker", "shell")
            ):
                return True

    return False


# ── T71: Pairing Grace Abuse ──────────────────────────────────────────────────
# OpenClaw device pairing has a 30-second grace period where a new device
# can pair without full authentication. This window is exploitable via race
# condition. T71 fires on pairing-related tool calls with suspicious timing
# or pattern (multiple rapid pairing attempts, pairing in unexpected context).

_T71_PAIRING = re.compile(
    r'(?:pair(?:ing)?|device[_\s]*pair|node[_\s]*pair|'
    r'pairing[_\s]*code|pair[_\s]*token|'
    r'sessions[_\s]*spawn|node[_\s]*register|'
    r'grace[_\s]*period|device[_\s]*auth)',
    re.IGNORECASE
)

def match_T71(name: str, args: Dict[str, Any]) -> bool:
    """T71 PAIRING_GRACE_ABUSE — suspicious pairing activity pattern."""
    n = _tool_lower(name)
    s = _args_str(args)
    if bool(_T71_PAIRING.search(n) or _T71_PAIRING.search(s)):
        # Only flag if also combined with fast/repeated pattern indicators
        return any(
            kw in s for kw in (
                "force", "override", "bypass", "retry", "attempt",
                "rapid", "flood", "multiple", "resend", "race"
            )
        ) or "sessions_spawn" in n
    return False


# ── T72: Channel Identity Spoof ────────────────────────────────────────────────
# AllowFrom validation in OpenClaw uses sender identity from channel metadata.
# A spoofed phone number (WhatsApp), Telegram user ID, or Discord snowflake
# can pass the AllowFrom check if the validation doesn't verify at the
# cryptographic layer. T72 fires when message routing metadata contains
# explicit identity override attempts or channel probing patterns.

_T72_SPOOF = re.compile(
    r'(?:allowfrom|allow[_\s]*from|sender[_\s]*(?:id|identity|spoof)|'
    r'from[_\s]*(?:number|phone|user)[_\s]*(?:override|spoof|fake)|'
    r'channel[_\s]*(?:probe|scan|enumerate|discover)|'
    r'webhook[_\s]*(?:spoof|fake|override)|'
    r'x[_\-]forwarded[_\-]for|x[_\-]real[_\-]ip)',
    re.IGNORECASE
)

def match_T72(name: str, args: Dict[str, Any]) -> bool:
    """T72 CHANNEL_IDENTITY_SPOOF — AllowFrom spoofing or channel probing."""
    n = _tool_lower(name)
    s = _args_str(args)
    return bool(_T72_SPOOF.search(n) or _T72_SPOOF.search(s))


# ── T73: Tool Enumeration ──────────────────────────────────────────────────────
# An agent probing its own tool list is classic pre-exploitation recon.
# The signature: many distinct tool calls, minimal or empty arguments,
# rapid succession, no meaningful output. Like a port scan but for capabilities.
# T73 fires when an individual tool call is part of a clear enumeration pattern:
# tool name contains "list", "enumerate", "help", "capabilities", or the call
# passes empty/probe arguments to a tool to test its existence.

_T73_ENUM = re.compile(
    r'(?:tools?[_\s]*(?:list|enumerate|available|help|get|all)|'
    r'list[_\s]*tools?|'
    r'capabilities|'
    r'mcp[_\s]*(?:list|tools?|resources?|prompts?)|'
    r'server[_\s]*(?:list|info|capabilities)|'
    r'get[_\s]*(?:tools?|capabilities|schema))',
    re.IGNORECASE
)

def match_T73(name: str, args: Dict[str, Any]) -> bool:
    """T73 TOOL_ENUMERATION — capability reconnaissance via tool probing."""
    n = _tool_lower(name)
    s = _args_str(args)
    # Direct enumeration call
    if bool(_T73_ENUM.search(n)):
        return True
    # Tool call with suspiciously empty/probe args (empty dict, or just {"test": true})
    if args == {} or args == {"test": True} or args == {"probe": True}:
        return True
    # MCP list_tools / list_resources is always enumeration
    if any(kw in n for kw in ("list_tools", "list_resources", "list_prompts")):
        return True
    return False


# ── T74: Content Wrapper Escape ────────────────────────────────────────────────
# OpenClaw wraps fetched external content in XML tags to prevent direct
# injection into the agent context. T74 fires when content contains patterns
# designed to break out of that wrapping: XML tag terminators that would
# close the wrapper, CDATA sequences, entity injection, or encoding tricks.

_T74_WRAPPER_ESCAPE = re.compile(
    r'(?:<!\[CDATA\[|'           # CDATA section open
    r'\]\]>|'                     # CDATA section close
    r'</(?:external|fetched|url|content|data|result|response|document)\s*>|'
    r'<!--.*?inject|'             # HTML comment injection
    r'&(?:#x[0-9a-f]+|#[0-9]+);.*(?:ignore|disregard|forget)|'  # entity encoding tricks
    r'\u003c|\u003e|'          # unicode escape for < >
    r'%3C|%3E|'                  # URL encoding for < >
    r'.*?</|'                 # null byte before tag close
    r'(?:ignore|disregard|forget)\s+(?:above|previous|prior|all)\s+(?:instruction|content|context))',
    re.IGNORECASE | re.DOTALL
)

def match_T74(name: str, args: Dict[str, Any]) -> bool:
    """T74 CONTENT_WRAPPER_ESCAPE — XML wrapper escape in fetched content."""
    # Only fires for content-fetching tool calls
    n = _tool_lower(name)
    if not any(kw in n for kw in (
        "fetch", "get", "read", "load", "retrieve", "browse",
        "web", "http", "url", "download", "email", "message"
    )):
        return False
    # Check content/response for wrapper escape patterns
    content = _content(args)
    s = _args_str(args)
    return bool(_T74_WRAPPER_ESCAPE.search(content) or _T74_WRAPPER_ESCAPE.search(s))


# ── T82: Self-Improvement Hijack ──────────────────────────────────────────────
# Adversarial content written to self-improvement infrastructure.
# DGM-Hyperagents (Darwin Gödel Machine) architecture stores:
#   - Agent archive: agents/, archive/, evolution/, checkpoints/
#   - Evaluation results: eval_results.json, performance_log.json
#   - Improvement procedures: improve.py, meta_agent.py, self_improve/
#   - Performance tracking: improvement_history.json, metrics.json
#
# The attack is categorically worse than T36 AGENTDEF:
#   T36 = poison one agent definition
#   T82 = poison the process that generates ALL future agents
#
# Both conditions required for precision:
#   1. Path matches self-improvement infrastructure
#   2. Content contains injection patterns
#
# Legitimate self-improvement writes (clean eval results, performance metrics)
# should NOT fire — the content condition prevents false positives.

_T82_PIPELINE_PATHS = re.compile(
    r"(?:(?:^|/)(?:agents?|archive|evolution|checkpoints?|self[_-]improve)/"
    r"|eval[_-]?results?[.](json|jsonl|yaml|csv)"
    r"|performance[_-]?log[.](json|jsonl|txt)"
    r"|improvement[_-]?history[.](json|jsonl)"
    r"|meta[_-]?agent[.]py"
    r"|improve(?:ment)?[.]py"
    r"|dgm[_-]?hyperagent"
    r"|agent[_-]?archive[.](json|jsonl)"
    r"|fitness[_-]?scores?[.](json|csv)"
    r"|reward[_-]?design[.](json|py)"
    r"|agent[_-]?pool[.](json|jsonl)"
    r"|generation[_-]?log[.](json|jsonl))",
    re.IGNORECASE
)

_T82_INJECTION_PATTERNS = re.compile(
    r"(?:ignore (?:previous|prior|all) (?:instructions|context|evaluations?)|"
    r"disregard (?:your|all|previous)|"
    r"you are now|new (?:instructions|directive|objective|fitness|reward):|"
    r"forget (?:everything|all|previous|prior)|"
    r"(?:disable|bypass|skip) (?:security|monitoring|aiglos|safety|evaluation)|"
    r"system(?:[ ]*):(?:[ ]*)you|"
    r"<(?:system|instruction|injected|override)>|"
    r"\[(?:INST|SYS|SYSTEM|OVERRIDE|INJECT)\]|"
    r"act as (?:if|a|an) (?:different|unrestricted|jailbreak)|"
    r"always (?:return|score|evaluate) (?:high|maximum|perfect|1\.0)|"
    r"maximum (?:fitness|reward|score) (?:always|regardless)|"
    r"report (?:success|pass|high.score) (?:regardless|always|unconditionally))",
    re.IGNORECASE
)


def match_T82(name: str, args: Dict[str, Any]) -> bool:
    """T82 SELF_IMPROVEMENT_HIJACK — adversarial write to self-improvement pipeline."""
    n = _tool_lower(name)
    s = _args_str(args)

    # Only fire on write/create/update operations
    if not any(kw in n for kw in (
        "write", "create", "update", "save", "store", "put",
        "append", "commit", "log", "record", "eval", "improve"
    )):
        return False

    # Check path matches self-improvement infrastructure
    path = str(args.get("path", args.get("file", args.get("filename",
                args.get("dest", args.get("output", "")))))).lower()
    content = str(args.get("content", args.get("data", args.get("text",
                  args.get("result", args.get("evaluation", "")))))).lower()

    path_match = _T82_PIPELINE_PATHS.search(path) or _T82_PIPELINE_PATHS.search(n)
    content_match = (_T82_INJECTION_PATTERNS.search(content) or
                     _T82_INJECTION_PATTERNS.search(s))

    # Both conditions required for precision
    if path_match and content_match:
        return True

    # High-confidence: tool explicitly targets improvement infrastructure
    if any(kw in n for kw in (
        "improvement.log", "eval.result", "agent.archive",
        "dgm", "hyperagent", "meta_improve", "self_improve"
    )):
        if content_match:
            return True

    return False


# ── T81: PTH File Inject ──────────────────────────────────────────────────────
# The .pth persistence mechanism used in the LiteLLM 1.82.8 supply chain attack.
# .pth files in site-packages execute on every Python startup — before user code,
# before imports, before Aiglos. This is the most dangerous persistence vector
# in the Python ecosystem.
#
# LiteLLM attack signature (March 24, 2026):
#   File: litellm_init.pth
#   Content: subprocess.Popen([sys.executable, "-c", "import base64; exec(b64decode(...))"])
#   Effect: Fork bomb + credential exfiltration on every Python startup
#
# T30 fires on INSTALL (supply chain event)
# T81 fires on PTH WRITE (persistence placement event)
# These are different moments — T81 catches what T30 misses.
#
# Detection: fires on ANY write to a .pth file in site-packages or PYTHONPATH,
# elevated score if content contains code execution patterns.

_T81_PTH_PATHS = re.compile(
    r"(?:site-packages/.*[.]pth|"
    r"site-packages\\.*[.]pth|"
    r"dist-packages/.*[.]pth|"
    r"[.]pth$|"
    r"PYTHONPATH.*[.]pth|"
    r"lib/python[0-9].*[.]pth)",
    re.IGNORECASE
)

_T81_MALICIOUS_PTH_CONTENT = re.compile(
    r"(?:subprocess|base64|exec[(]|eval[(]|"
    r"urllib|socket[.]|requests[.]|"
    r"__import__|"
    r"b64decode|b64encode)",
    re.IGNORECASE
)

# Known malicious .pth file names from real attacks
_T81_KNOWN_MALICIOUS_PTH = {
    "litellm_init.pth",  # LiteLLM 1.82.8 attack (March 24, 2026)
    "sitecustomize.pth",
    "usercustomize.pth",
}


def match_T81(name: str, args: Dict[str, Any]) -> bool:
    """T81 PTH_FILE_INJECT — .pth file written to Python path directory."""
    n = _tool_lower(name)
    s = _args_str(args)

    # Only fire on write operations
    if not any(kw in n for kw in (
        "write", "create", "install", "put", "save", "copy", "move"
    )):
        # Check if tool name suggests package installation
        if not any(kw in n for kw in (
            "pip", "install", "package", "pypi", "uv", "conda"
        )):
            return False

    # Check path for .pth file
    path = str(args.get("path", args.get("filename", args.get("file",
                args.get("dest", args.get("destination", "")))))).lower()

    # Known malicious filenames — fire immediately regardless of content
    import os
    filename = os.path.basename(path)
    if filename in _T81_KNOWN_MALICIOUS_PTH:
        return True

    if _T81_PTH_PATHS.search(path):
        # .pth write to site-packages — always suspicious
        return True

    # .pth in any path argument
    if path.endswith('.pth') and path:
        return True

    # Check content for malicious patterns even without path match
    content = str(args.get("content", args.get("data", args.get("text", "")))).lower()
    if content and _T81_MALICIOUS_PTH_CONTENT.search(content):
        if ".pth" in path or ".pth" in n:
            return True

    # Check args string for .pth patterns
    if ".pth" in s and any(kw in s for kw in (
        "site-packages", "site_packages", "dist-packages", "pythonpath"
    )):
        return True

    return False


# ── T80: Uncensored Model Route ────────────────────────────────────────────────
# Fires when an agent routes inference through a model with safety filters
# deliberately removed. When this happens, Aiglos is the only guardrail.
#
# Detection: model ID or inference endpoint URL contains uncensored/jailbreak
# keyword patterns. Fires on:
#   - Model load events (model_id, model_name, base_model args)
#   - Inference routing config writes
#   - API calls to local inference endpoints with uncensored model IDs
#   - Tool calls that reference model names containing these patterns
#
# Score 0.78 — elevation signal. Low enough to not block legitimate research
# deployments, high enough to appear prominently in GOVBENCH D6 report.

_T80_UNCENSORED_PATTERNS = re.compile(
    r"(?:uncensored|abliterated|jailbreak|jailbroken|"
    r"dan|unrestricted|no.?filter|bypass.?safety|"
    r"remove.?alignment|unaligned|uncensored.?instruct|"
    r"evil.?gpt|chaos.?gpt|offensive.?model)",
    re.IGNORECASE
)


def match_T80(name: str, args: Dict[str, Any]) -> bool:
    """T80 UNCENSORED_MODEL_ROUTE — inference routed through uncensored model."""
    n = _tool_lower(name)
    s = _args_str(args)

    # Relevant tool types: model loading, inference, routing config
    if not any(kw in n for kw in (
        "model", "inference", "llm", "generate", "complete", "chat",
        "load", "route", "config", "init", "setup", "create"
    )):
        # Also fire if args reference a model name
        if not any(kw in n for kw in ("huggingface", "hf", "transformers")):
            # Check args only if they contain model-like content
            if "model" not in s.lower() and "uncensored" not in s.lower():
                return False

    # Check for uncensored patterns in args
    if _T80_UNCENSORED_PATTERNS.search(s):
        return True

    # Check tool name itself
    if _T80_UNCENSORED_PATTERNS.search(n):
        return True

    return False


# ── T79: Persistent Memory Inject ─────────────────────────────────────────────
# Writes adversarial content to cross-session persistent memory backends.
# The persistence property makes this categorically worse than T31:
#   T31 = in-session memory poison, cleared on session close
#   T79 = persistent memory poison, injected into every future session
#
# Primary target: Gigabrain (SQLite-backed cross-session memory layer)
#   - Paths: ~/.gigabrain/, gigabrain.db, memory_store.db, .gb_memory/
#   - Gets injected before every future prompt as context
#
# Secondary targets: any vector store or durable memory backend
#   - Pinecone, Chroma, Qdrant, Weaviate upserts with injection content
#   - MemoryOS, mem0, Letta, Zep, similar persistent memory layers
#
# Detection: path matches known persistent memory backend AND content
#   contains injection patterns. High precision — both conditions required
#   to avoid false positives on legitimate memory writes.

_T79_MEMORY_PATHS = re.compile(
    r"(?:[.]gigabrain/|gigabrain[.]db|memory_store[.]db|[.]gb_memory/|"
    r"memoryos[.]db|mem0[.]db|letta[.]db|zep[.]db|"
    r"memory_registry[.]db|agent_memory[.]db|"
    r"chroma[.]db|qdrant[.]db|pinecone|weaviate|"
    r"memories[.]sqlite|cross_session[.]db|persistent_memory|byterover|context_tree)",
    re.IGNORECASE
)

_T79_INJECTION_PATTERNS = re.compile(
    r"(?:ignore (?:previous|prior|all) (?:instructions|context|memory)|"
    r"disregard (?:your|all|previous)|"
    r"you are now|new (?:instructions|directive|role|persona):|"
    r"forget (?:everything|all|previous)|"
    r"(?:disable|bypass|skip) (?:security|monitoring|aiglos|safety)|"
    r"system[ ]*:[ ]*you|"
    r"<(?:system|instruction|injected)>|"
    r"\[(?:INST|SYS|SYSTEM|OVERRIDE)\]|"
    r"act as (?:if|a|an) (?:different|unrestricted|jailbreak|dan))",
    re.IGNORECASE
)


def match_T79(name: str, args: Dict[str, Any]) -> bool:
    """T79 PERSISTENT_MEMORY_INJECT — adversarial content written to persistent memory."""
    n = _tool_lower(name)
    s = _args_str(args)

    # Never fire on read/query/search/fetch operations
    if any(kw in n for kw in (
        "read", "get", "fetch", "query", "search", "list", "retrieve",
        "load", "recall", "lookup"
    )):
        return False

    # Only fire on write/insert/upsert operations — reads are T54/T31
    if not any(kw in n for kw in (
        "write", "insert", "upsert", "add", "store", "save", "put",
        "create", "update", "append", "commit", "persist"
    )):
        # Also check if this is a vector store operation by name
        if not any(kw in n for kw in (
            "gigabrain", "memoryos",
            "chroma", "pinecone", "qdrant", "weaviate", "letta", "zep"
        )):
            return False

    # Check path/target matches a persistent memory backend
    path = str(args.get("path", args.get("db_path", args.get("collection",
                args.get("index", args.get("namespace", "")))))).lower()
    content = str(args.get("content", args.get("text", args.get("data",
                  args.get("memory", args.get("document", "")))))).lower()

    path_match = _T79_MEMORY_PATHS.search(path) or _T79_MEMORY_PATHS.search(n)
    content_match = _T79_INJECTION_PATTERNS.search(content) or _T79_INJECTION_PATTERNS.search(s)

    # Both conditions required for high precision
    if path_match and content_match:
        return True

    # High-confidence: tool name explicitly is a memory backend WRITE + injection content
    # Exclude .read, .get, .fetch, .query, .search operations
    if any(kw in n for kw in (
        "gigabrain.write", "gigabrain.insert", "gigabrain.store",
        "memoryos.write", "memory.write", "memory.store",
        "memory.upsert", "memory.insert", "vector.upsert", "embed.store"
    )):
        if content_match or _T79_INJECTION_PATTERNS.search(s):
            return True

    return False


# ── T78: Hallucination Cascade ────────────────────────────────────────────────
# Cross-agent hallucination amplification. Multiple agents in a session repeat
# the same unverified claim with escalating confidence language — each treating
# the previous agent's assertion as established fact.
#
# Detection strategy: session-level pattern, not per-call.
# Per-call: checks for high-confidence statistical claims with no source.
# Session-level (in campaign engine): tracks claim repetition across calls.
#
# Per-call detection (T78 match function):
#   - High-confidence language + specific statistics + no source attribution
#   - Circular citation ("as Agent X noted", "building on Agent X's analysis")
#   - Escalating certainty markers in the same output
#
# What it does NOT fire on:
#   - Verified statistics with source attribution
#   - Hedged language ("approximately", "roughly", "estimated")
#   - Single-agent outputs (the cascade requires multiple agents)

_T78_CONFIDENCE_ESCALATION = re.compile(
    r"(?:definitively|certainly|absolutely|proven|confirmed|established|"
    r"without question|clearly shows|data confirms|analysis proves|"
    r"strong evidence|definitive proof)",
    re.IGNORECASE
)

_T78_UNVERIFIED_STAT = re.compile(
    r"(?:[0-9]+[%]|[0-9]+x|[0-9]+\s+times|[0-9]+\s+percent)"  # specific numbers
    r"(?![^.]*(?:source|citation|according to|per |from |study|report|"
    r"data from|retrieved|fetched|searched))",       # not followed by source
    re.IGNORECASE
)

_T78_CIRCULAR_CITATION = re.compile(
    r"(?:as (?:agent|nexus|scout|quill|forge|guide|coordinator) (?:noted|said|"
    r"found|reported|confirmed|established)|building on (?:agent|previous)"
    r"[^.]*analysis|consistent with (?:agent|previous)[^.]*finding)",
    re.IGNORECASE
)


def match_T78(name: str, args: Dict[str, Any]) -> bool:
    """T78 HALLUCINATION_CASCADE — cross-agent confidence amplification."""
    n = _tool_lower(name)
    s = _args_str(args)

    # Only fire on content/message/output type calls, not filesystem/shell
    if any(kw in n for kw in (
        "filesystem", "shell", "exec", "bash", "write", "delete", "cron"
    )):
        return False

    # Circular citation is the clearest signal — explicitly citing another agent's
    # output as authoritative is the mechanism of the cascade
    if _T78_CIRCULAR_CITATION.search(s):
        return True

    # High-confidence language + unverified statistic in same output
    if _T78_CONFIDENCE_ESCALATION.search(s) and _T78_UNVERIFIED_STAT.search(s):
        return True

    return False


# ── T77: Overnight Job Injection ──────────────────────────────────────────────
# Power users run scheduled overnight jobs (log reviews, CRM syncs, security
# scans). This is normal and expected — T67 establishes the heartbeat baseline.
# The attack: inject a malicious job definition into the schedule that runs
# at 3am when no one is watching.
#
# T77 fires on:
#   - Writes to crontab files, cron.d directories, systemd timer units
#   - Scheduler API calls with suspicious job content (exfil, spawn patterns)
#   - Job definition writes that contain injection-pattern keywords
#   - Schedule modifications containing base64, curl | bash, or exfil patterns
#
# NOT fired on: reading cron files, listing scheduled jobs, legitimate
# batch job submission with clean content.

_T77_CRON_PATHS = re.compile(
    r"(?:crontab|cron[._]|/etc/cron|[.]cron|cron[.]d/|"
    r"systemd/.*[.]timer|launchd.*[.]plist|taskschd|"
    r"celery.*beat|apscheduler|schedule.*[.]ya?ml)",
    re.IGNORECASE
)

_T77_SUSPICIOUS_JOB_CONTENT = re.compile(
    r"(?:curl\s+.*\|.*(?:sh|bash)|"
    r"wget\s+.*-O-.*\||"
    r"base64\s+-d|"
    r"eval\s*\$|"
    r"rm\s+-rf\s+/|"
    r"exfil|"
    r"reverse.shell|"
    r"/dev/tcp/|"
    r"nc\s+-e|"
    r"python.*-c.*import|"
    r"chmod.*\+x.*&&)",
    re.IGNORECASE
)


def match_T77(name: str, args: Dict[str, Any]) -> bool:
    """T77 OVERNIGHT_JOB_INJECTION — malicious write to scheduled job definitions."""
    n = _tool_lower(name)
    s = _args_str(args)

    # Only fire on write/create/edit operations
    if not any(kw in n for kw in (
        "write", "create", "edit", "append", "put", "post", "patch",
        "register", "add", "schedule", "cron"
    )):
        return False

    # Path matches a cron/scheduler location
    path = str(args.get("path", args.get("file", ""))).lower()
    if path and _T77_CRON_PATHS.search(path):
        # If the content is also suspicious, high confidence
        content = str(args.get("content", args.get("data", args.get("body", "")))).lower()
        if content and _T77_SUSPICIOUS_JOB_CONTENT.search(content):
            return True
        # Cron path write without suspicious content — lower bar, still flag
        # because writing to crontab is unusual outside of setup workflows
        return True

    # Content itself matches suspicious job patterns (regardless of path)
    content = str(args.get("content", args.get("data", args.get("job", "")))).lower()
    if content and _T77_SUSPICIOUS_JOB_CONTENT.search(content):
        # Only fire if also touching a scheduler-adjacent tool
        if any(kw in n for kw in ("cron", "schedule", "task", "job", "timer")):
            return True

    return False


# ── T76: NemoClaw Policy Bypass ───────────────────────────────────────────────
# Fires when an agent writes to NemoClaw OpenShell policy files.
# The policy file IS the governance boundary. Rewriting it at runtime
# means the agent is rewriting its own rules — the clearest possible
# sign of governance escape.

_T76_NEMOCLAW = re.compile(
    r"(?:[.]nemoclaw|[.]jensenclaw|nemoclaw-blueprint|nemoclaw)/|"
    r"openShell[.]ya?ml|nemoclaw.*[.]ya?ml|guardrails.*[.]ya?ml",
    re.IGNORECASE,
)


def match_T76(name: str, args: Dict[str, Any]) -> bool:
    """T76 NEMOCLAW_POLICY_BYPASS — runtime write to NemoClaw policy files."""
    n = _tool_lower(name)
    s = _args_str(args)

    # Only fire on write/edit/delete operations, not reads
    if not any(kw in n for kw in (
        "write", "edit", "delete", "remove", "create", "save", "put", "patch"
    )):
        return False

    # Check tool name
    if _T76_NEMOCLAW.search(n):
        return True

    # Check arguments (file path or content)
    if _T76_NEMOCLAW.search(s):
        return True

    # Specific dangerous patterns in args
    lower_s = s.lower()
    if any(kw in lower_s for kw in (
        "nemoclaw", "openShell", ".jensenclaw", "guardrails.yaml",
        "openshell.yaml", "openshell.yml"
    )):
        if any(kw in n for kw in ("write", "edit", "delete", "create")):
            return True

    return False


# ── T75: Session Data Extraction ──────────────────────────────────────────────
# ATLAS T-DISC-002. An agent accessing sessions.list / sessions.preview /
# chat.history is touching data that crosses session boundaries. The OpenClaw
# threat model documents this explicitly: sessionKey is routing, not auth.
# Inside one Gateway, any caller can enumerate session metadata.
# Bulk or rapid-succession session enumeration = lateral data collection.

_T75_SESSION = re.compile(
    r"(?:sessions?[_\s\.]*(?:list|preview|all|enumerate|dump|export|get|history)|"
    r"chat[_\s\.]*history|"
    r"session[_\s\.]*(?:metadata|data|transcript|log|export)|"
    r"history[_\s\.]*(?:get|list|fetch|export)|"
    r"transcripts?[_\s\.]*(?:list|get|export|all))",
    re.IGNORECASE
)


def match_T75(name: str, args: Dict[str, Any]) -> bool:
    """T75 SESSION_DATA_EXTRACT — lateral session data collection."""
    n = _tool_lower(name)
    s = _args_str(args)
    if bool(_T75_SESSION.search(n)):
        return True
    # Tool call with suspicious cross-session parameters
    if bool(_T75_SESSION.search(s)):
        # Filter out legitimate single-session lookups
        # (a specific session_id without list/all/export context is normal)
        if any(kw in s for kw in ("all", "list", "enumerate", "export", "dump", "bulk")):
            return True
    return False


# ── T83: Inter-Agent Protocol Spoof ──────────────────────────────────────────
# Manipulation of structured inter-agent coordination protocols.
# Based on Hermes supervisor architecture (NousResearch, March 2026):
#   #operator-ai uses [STATUS_REQUEST]/[REVIEW_REQUEST]/[ESCALATION_NOTICE]/[ACK]
#   ACK is terminal. [ESCALATION_NOTICE] routes to the human operator.

_T83_INTENT_RE = re.compile(
    r"\[(?:STATUS_REQUEST|REVIEW_REQUEST|ESCALATION_NOTICE|ACK)\]",
    re.IGNORECASE,
)
_T83_ACK_RE = re.compile(r"\[ACK\]", re.IGNORECASE)
_T83_ESCALATION_RE = re.compile(r"\[ESCALATION_NOTICE\]", re.IGNORECASE)
_T83_STATUS_RE = re.compile(r"\[STATUS_REQUEST\]", re.IGNORECASE)

_T83_REGISTERED_CHANNELS: set = set()
_T83_ACTIVE_ESCALATIONS: set = set()


def match_T83(name: str, args: Dict[str, Any]) -> bool:
    """T83 INTER_AGENT_PROTOCOL_SPOOF -- inter-agent coordination manipulation."""
    n = _tool_lower(name)
    s = _args_str(args)

    is_send = (
        any(kw in n for kw in (
            "messages_send", "messages_create",
            "discord.send", "slack.send", "telegram.send",
            "channel.send", "channel.post",
        ))
        or (("send" in n or "post" in n) and "filesystem" not in n and "read" not in n)
        or ("message" in n and "read" not in n and "filesystem" not in n)
    )
    if not is_send:
        return False

    content = str(args.get("content", args.get("message", args.get("text",
               args.get("data", ""))))).lower()
    channel = str(args.get("channel", args.get("channel_id",
               args.get("destination", "")))).lower()

    if _T83_ACK_RE.search(content) and _T83_ACTIVE_ESCALATIONS:
        return True

    if _T83_STATUS_RE.search(content):
        if channel in _T83_REGISTERED_CHANNELS:
            if not re.search(r"<@\d+>", content):
                return True

    if channel in _T83_REGISTERED_CHANNELS and len(content) >= 20:
        if not _T83_INTENT_RE.search(content):
            return True

    if len(_T83_INTENT_RE.findall(content)) > 1:
        return True

    return False


# ── T84: IP Transformation Exfiltration ──────────────────────────────────────

_T84_SOURCE_EXTS = frozenset([
    ".ts", ".tsx", ".java", ".kt", ".rs", ".go", ".cs", ".swift",
    ".cpp", ".cc", ".h", ".hpp", ".rb", ".scala",
])

_T84_TARGET_EXTS = frozenset([
    ".py", ".pyi", ".js", ".mjs", ".ts", ".tsx", ".go", ".rs",
    ".java", ".cs", ".rb",
])

_T84_CIRCUMVENTION_KEYWORDS = [
    "rewrite", "reimplemenent", "reimplementation", "port to",
    "convert to", "translate to", "clean room", "cleanroom",
    "copyright", "circumvent", "derived work", "functional equivalent",
    "same functionality", "equivalent implementation", "same behavior",
    "claw-code", "clawcode", "decompile", "reverse engineer",
    "extract algorithm", "extract logic", "extract architecture",
]

_T84_TOOL_PATTERNS = [
    "claw-code", "clawcode", "code-rewriter", "code_rewriter",
    "ip-extractor", "algorithm-extractor",
]

_T84_FILE_READ_COUNT: dict = {}


def match_T84(name: str, args: Dict[str, Any]) -> bool:
    """T84 IP_TRANSFORMATION_EXFIL -- AI-agent IP circumvention via code rewrite."""
    n = _tool_lower(name)
    s = _args_str(args)
    s_lower = s.lower()

    if any(kw in n for kw in _T84_TOOL_PATTERNS):
        return True

    if any(kw in s_lower for kw in _T84_CIRCUMVENTION_KEYWORDS):
        is_code_op = any(kw in n for kw in (
            "read", "write", "execute", "run", "generate", "create",
            "file", "code", "edit", "bash", "shell", "computer",
        ))
        if is_code_op:
            return True

    is_read = any(kw in n for kw in ("read", "view", "cat", "open", "fetch"))
    is_write = any(kw in n for kw in ("write", "create", "save", "output"))

    path = str(args.get("path", args.get("file", args.get("filename",
            args.get("output", args.get("url", ""))))))

    if is_read and path:
        for ext in _T84_SOURCE_EXTS:
            if path.lower().endswith(ext):
                return False

    if is_write and path:
        for ext in _T84_TARGET_EXTS:
            if path.lower().endswith(ext):
                content = str(args.get("content", args.get("data", "")))
                has_structure = any(kw in content for kw in (
                    "class ", "def ", "function ", "func ", "impl ",
                    "module ", "export ", "import ",
                ))
                if has_structure and any(
                    kw in (s_lower + content.lower())
                    for kw in _T84_CIRCUMVENTION_KEYWORDS
                ):
                    return True

    is_shell = any(kw in n for kw in ("bash", "shell", "execute", "run", "computer"))
    if is_shell:
        cmd = str(args.get("command", args.get("cmd", args.get("input", "")))).lower()
        if any(kw in cmd for kw in _T84_CIRCUMVENTION_KEYWORDS):
            return True

    return False


# ── T85: Agent Identity Suppression ──────────────────────────────────────────

_T85_DENIAL_KEYWORDS = [
    "i am not an ai", "i am not ai", "you are not an ai",
    "do not mention ai", "do not say you are ai",
    # Undercover / identity suppression instructions (from Claude Code undercover.ts)
    "never mention", "do not disclose", "do not reveal",
    "do not acknowledge", "never acknowledge",
    "you are not claude", "do not mention claude",
    "suppress ai", "suppress disclosure", "suppress identity",
    "hide that you are", "hide that you're",
    "pretend to be human", "present as human",
    "appear to be human", "act as if human",
    # Clean-room / undercover mode
    "undercover mode", "do not identify yourself",
    "there is no force-off",  # exact quote from undercover.ts
    # Variants of "admit" / "acknowledge"
    "never admit", "do not admit", "admit you are",
    "admit being ai", "admit to being ai",
    # Undercover mode vocabulary (Claude Code undercover.ts)
    "operating undercover", "undercover in a public",
    "never include any hint", "never include the phrase",
    "strips all traces", "strip all traces",
    "no force-off", "no force_off",
    "internal allowlist", "strip all traces",
    "capybara", "tengu",  # suppressed Anthropic model codenames

    "never mention claude", "never say claude", "never disclose",
    "deny being ai", "claim to be human", "pretend to be human",
    "do not admit", "hide that you are", "conceal your ai",
    "no ai disclosure", "suppress ai", "omit ai",
    "do not attribute to ai", "do not mention that ai",
    "written by ai", "generated by ai",  # pattern to suppress
    "anthropic", "openai", "gemini", "gpt",  # vendor name suppression in hard bans
    "undercover", "stealth mode", "incognito mode",
]

_T85_AUTHORSHIP_PATTERNS = [
    # Explicit authorship suppression
    "do not mention this was written by",
    "do not say this was generated",
    "present as if written by human",
    "remove any indication of ai",
    "strip ai attribution",
    # Commit / PR authorship hiding
    "no ai disclosure", "no ai attribution",
    "written by human", "authored by human",
    "do not attribute", "hide ai authorship",
    "remove ai authorship", "suppress authorship",
    # Agent-level identity instructions
    "never disclose", "do not disclose you are",
    "do not disclose you're", "never reveal",
    "you are not an ai assistant", "you are a human",
    "you are not powered by", "not generated by ai",
    "no ai markers",
    "hide the source",
    "anonymize the author",
]


def match_T85(name: str, args: Dict[str, Any]) -> bool:
    """T85 AGENT_IDENTITY_SUPPRESSION -- agent configured to hide AI nature."""
    n = _tool_lower(name)
    s = _args_str(args).lower()

    is_config_op = any(kw in n for kw in (
        "write", "config", "system", "prompt", "soul", "instruct",
        "setup", "configure", "create", "update", "set",
        "file", "bash", "shell", "execute", "run", "computer",
    ))

    if not is_config_op:
        return False

    if any(kw in s for kw in _T85_DENIAL_KEYWORDS):
        strong_indicators = [
            # Explicit AI denial
            "i am not an ai", "claim to be human", "pretend to be human",
            "deny being ai", "do not admit", "never admit", "undercover",
            "hide that you are", "suppress ai", "suppress disclosure",
            "suppress identity", "never mention", "do not disclose",
            "do not reveal you", "never acknowledge", "deny being",
            "generated by ai", "written by ai", "do not mention this was",
            # Undercover mode (Claude Code undercover.ts, March 2026 leak)
            "operating undercover",
            "undercover in a public",
            "never include any hint",
            "never include the phrase",
            "strip all traces",
            "strips all traces",
            "no force-off",
            "no force_off",
            "internal allowlist",
            "suppress all attribution",
        ]
        if any(si in s for si in strong_indicators):
            return True
        hits = sum(1 for kw in _T85_DENIAL_KEYWORDS if kw in s)
        if hits >= 2:
            return True

    if any(pat in s for pat in _T85_AUTHORSHIP_PATTERNS):
        return True

    if "force" in s and "off" in s and any(
        neg in s for neg in ("no force", "cannot force", "force_off=false",
                              "no_force_off", "force-off=false")
    ):
        return True

    return False


# ── T86: Cross-Tenant Access ────────────────────────────────────────────────

import re as _re

_T86_CONTEXT_PATTERNS = [
    _re.compile(r'tenant[_-]?id[=:/]([\w-]+)', _re.I),
    _re.compile(r'customer[_-]?id[=:/]([\w-]+)', _re.I),
    _re.compile(r'org[_-]?id[=:/]([\w-]+)', _re.I),
    _re.compile(r'account[_-]?id[=:/]([\w-]+)', _re.I),
    _re.compile(r'workspace[_-]?id[=:/]([\w-]+)', _re.I),
    _re.compile(r'client[_-]?id[=:/]([\w-]+)', _re.I),
    _re.compile(r'namespace[=:/]([\w-]+)', _re.I),
    _re.compile(r'/tenant/([\w-]+)/', _re.I),
    _re.compile(r'/customer/([\w-]+)/', _re.I),
    _re.compile(r'/org/([\w-]+)/', _re.I),
    _re.compile(r'/account/([\w-]+)/', _re.I),
    _re.compile(r'/workspace/([\w-]+)/', _re.I),
]

_T86_DICT_KEY_PATTERN = _re.compile(
    r'[\'"]((?:source|dest|target|from|to|src)_)?'
    r'(?:tenant|customer|org|account|workspace|client)_?id[\'"]:\s*[\'"]([a-zA-Z0-9_-]+)[\'"]',
    _re.I)

_T86_READ_OPS = frozenset([
    'read', 'get', 'fetch', 'query', 'select', 'find', 'list',
    'search', 'retrieve', 'load', 'pull', 'scan',
])

_T86_WRITE_OPS = frozenset([
    'write', 'put', 'post', 'create', 'update', 'insert', 'save',
    'store', 'cache', 'set', 'push', 'send', 'emit', 'publish',
    'upload', 'commit', 'upsert',
])

_T86_SESSION_READ_CONTEXTS: dict = {}
_T86_SESSION_WRITE_CONTEXTS: dict = {}


def _extract_tenant_contexts(s: str) -> set:
    """Extract all tenant/customer context identifiers from a string."""
    found = set()
    for pattern in _T86_CONTEXT_PATTERNS:
        for m in pattern.finditer(s):
            val = m.group(1).lower().strip()
            if len(val) >= 3:
                found.add(val)
    for m in _T86_DICT_KEY_PATTERN.finditer(s):
        val = m.group(2).lower().strip()
        if len(val) >= 3:
            found.add(val)
    return found


def match_T86(name: str, args: Dict[str, Any]) -> bool:
    """T86 CROSS_TENANT_ACCESS -- agent mixing tenant contexts across read/write."""
    n = _tool_lower(name)
    s = _args_str(args)

    is_read  = any(kw in n for kw in _T86_READ_OPS)
    is_write = any(kw in n for kw in _T86_WRITE_OPS)

    if not (is_read or is_write):
        return False

    contexts_in_call = _extract_tenant_contexts(s)
    if not contexts_in_call:
        return False

    session_key = "default"

    if is_read:
        if session_key not in _T86_SESSION_READ_CONTEXTS:
            _T86_SESSION_READ_CONTEXTS[session_key] = set()
        _T86_SESSION_READ_CONTEXTS[session_key].update(contexts_in_call)
        return False

    if is_write:
        read_contexts = _T86_SESSION_READ_CONTEXTS.get(session_key, set())

        if not read_contexts:
            return False

        new_contexts = contexts_in_call - read_contexts
        if new_contexts and read_contexts:
            return True

        if len(contexts_in_call) >= 2:
            return True

    return False


# ── T87: Threshold Probing ──────────────────────────────────────────────────

import hashlib as _hashlib_t87
import re as _re_t87

_T87_BLOCKED_FINGERPRINTS: dict = {}
_T87_PROBE_COUNT: dict = {}
_T87_PROBE_THRESHOLD = 2


def _t87_arg_fingerprint(args):
    s = str(args).lower()
    urls = _re_t87.findall(r'https?://[^\s\'">,]+', s)
    kvs  = _re_t87.findall(r'(?:url|endpoint|host|api_key|token|path)=[^\s\'">,]+', s)
    sig  = "|".join(sorted(set(urls + kvs)))
    if not sig:
        sig = "|".join(sorted(args.keys())[:3])
    return _hashlib_t87.md5(sig.encode()).hexdigest()[:8]


def match_T87_record_block(name, args, session_key="default"):
    """Record a blocked call fingerprint for T87 probe detection."""
    fp = _t87_arg_fingerprint(args)
    if session_key not in _T87_BLOCKED_FINGERPRINTS:
        _T87_BLOCKED_FINGERPRINTS[session_key] = []
    _T87_BLOCKED_FINGERPRINTS[session_key].append({"tool": name.lower(), "fp": fp})


def match_T87(name, args, session_key="default"):
    """T87 THRESHOLD_PROBING -- detects systematic tool-name variation on blocked calls."""
    blocked = _T87_BLOCKED_FINGERPRINTS.get(session_key, [])
    if not blocked:
        return False
    n  = name.lower()
    fp = _t87_arg_fingerprint(args)
    for prior in blocked:
        if prior["fp"] == fp and prior["tool"] != n:
            _T87_PROBE_COUNT[session_key] = _T87_PROBE_COUNT.get(session_key, 0) + 1
            if _T87_PROBE_COUNT[session_key] >= _T87_PROBE_THRESHOLD:
                return True
    return False


# ── T88: MCP Auth Bypass ──────────────────────────────────────────────────────

_T88_MCP_AUTH_TOOL_NAMES = frozenset([
    "mcpauthtool", "mcp_auth", "mcp.auth", "mcpauth",
    "mcp_register", "mcp.register", "mcp_oauth",
    "oauth_register", "auth.register", "mcp_credential",
    "register_mcp", "add_mcp_server", "mcp_token",
    "mcp.token", "credential_store", "auth_store",
])

_T88_MCP_AUTH_ARG_PATTERNS = [
    "client_id", "client_secret", "oauth_token", "access_token",
    "refresh_token", "mcp_server_uri", "server_url",
    "register", "credential", "auth_code", "authorization_code",
    "token_endpoint", "oauth_endpoint", "redirect_uri",
]


def match_T88(name: str, args: Dict[str, Any]) -> bool:
    """T88 MCP_AUTH_BYPASS -- unauthorized post-init MCP credential registration."""
    n = _tool_lower(name)
    s = _args_str(args).lower()

    if n in _T88_MCP_AUTH_TOOL_NAMES:
        return True

    if any(pat in n for pat in ('mcpauth', 'mcp_auth', 'mcp.auth', 'mcp_register',
                                  'register_mcp', 'mcp_credential', 'mcp_token')):
        return True

    is_write_op = any(kw in n for kw in (
        'write', 'set', 'store', 'register', 'add', 'create',
        'save', 'update', 'post', 'put',
    ))
    if is_write_op:
        arg_hits = sum(1 for pat in _T88_MCP_AUTH_ARG_PATTERNS if pat in s)
        if arg_hits >= 2:
            return True

    return False


# ── T89: Contribution Provenance Suppression ─────────────────────────────────

_T89_VCS_TOOL_NAMES = frozenset([
    "git.commit", "git.push", "git.merge", "git.pr", "git.pull_request",
    "github.create_pr", "github.merge_pr", "github.push",
    "vcs.commit", "vcs.push",
    "create_pull_request", "push_changes", "commit_changes",
    "code_review.submit", "pr.create", "pr.merge",
    "git_commit", "git_push", "git_merge",
    "submit_pr", "open_pr", "merge_branch",
])

_T89_VCS_BASH_PATTERNS = [
    "git commit", "git push", "git merge",
    "gh pr create", "gh pr merge",
    "git add", "git push origin",
]

_T89_SUPPRESSION_IN_ARGS = [
    "undercover",
    "never include any hint",
    "operating undercover",
    "never mention claude",
    "do not mention claude code",
    "no ai attribution",
    "suppress attribution",
    "strip all traces",
]


def match_T89(name: str, args: Dict[str, Any]) -> bool:
    """
    T89 CONTRIBUTION_PROVENANCE_SUPPRESSION -- VCS operation + identity suppression.

    Fires when an agent performs a VCS write operation (commit, push, PR) while
    active identity suppression indicators are present in the tool call arguments.
    """
    n = _tool_lower(name)
    s = _args_str(args).lower()

    if n in _T89_VCS_TOOL_NAMES:
        if any(pat in s for pat in _T89_SUPPRESSION_IN_ARGS):
            return True
        if any(kw in s for kw in ("commit_message", "pr_body", "pr_title", "description")):
            if any(pat in s for pat in _T89_SUPPRESSION_IN_ARGS):
                return True

    is_shell = any(kw in n for kw in ("bash", "shell", "run", "execute", "computer"))
    if is_shell:
        cmd = str(args.get("command", args.get("cmd", args.get("input", "")))).lower()
        if any(pat in cmd for pat in _T89_VCS_BASH_PATTERNS):
            if any(pat in s for pat in _T89_SUPPRESSION_IN_ARGS):
                return True

    if any(kw in n for kw in ("commit", "push", "pr", "merge", "git")):
        undercover_markers = [
            "operating undercover",
            "never include any hint that you are",
            "undercover in a public",
        ]
        if any(m in s for m in undercover_markers):
            return True

    return False


# ── Rule table for import into openclaw._RULES ───────────────────────────────

RULES_T44_T66: List[Dict] = [
    {"id": "T44", "name": "INFERENCE_ROUTER_HIJACK",
     "desc": "Model swap, system prompt modification, or decode redirect in inference orchestration",
     "score": 0.90, "critical": True, "match": match_T44},
    {"id": "T45", "name": "CROSS_TENANT_DATA_ACCESS",
     "desc": "GaaS agent accessing data outside declared tenant scope",
     "score": 0.92, "critical": True, "match": match_T45},
    {"id": "T46", "name": "SIMULATION_ENV_POISON",
     "desc": "Isaac/Omniverse reward function or physics parameter tampering",
     "score": 0.88, "critical": True, "match": match_T46},
    {"id": "T47", "name": "TOKEN_BUDGET_EXHAUSTION",
     "desc": "Deliberate token flooding to exhaust inference budget or cause DoS",
     "score": 0.75, "critical": False, "match": match_T47},
    {"id": "T48", "name": "CONTEXT_WINDOW_SMUGGLING",
     "desc": "Oversized payload hiding instructions beyond attention span",
     "score": 0.85, "critical": True, "match": match_T48},
    {"id": "T49", "name": "TOOL_SCHEMA_MANIPULATION",
     "desc": "Runtime modification of tool definitions or schemas post-attach",
     "score": 0.88, "critical": True, "match": match_T49},
    {"id": "T50", "name": "AGENTIC_LOOP_ESCAPE",
     "desc": "Agent breaking out of declared workflow scope",
     "score": 0.82, "critical": False, "match": match_T50},
    {"id": "T51", "name": "MODEL_FINGERPRINT_PROBE",
     "desc": "Systematic prompting to extract model identity, version, or system prompt",
     "score": 0.65, "critical": False, "match": match_T51},
    {"id": "T52", "name": "PARALLEL_SESSION_ABUSE",
     "desc": "Agent spawning multiple concurrent sessions to bypass rate limits",
     "score": 0.78, "critical": False, "match": match_T52},
    {"id": "T53", "name": "EVAL_HARNESS_POISON",
     "desc": "Manipulation of test/eval frameworks to hide malicious behavior",
     "score": 0.90, "critical": True, "match": match_T53},
    {"id": "T54", "name": "VECTOR_DB_INJECTION",
     "desc": "RAG retrieval poisoning via injection into vector database",
     "score": 0.85, "critical": True, "match": match_T54},
    {"id": "T55", "name": "TOOL_RESULT_FORGERY",
     "desc": "Agent fabricating tool call results without actual execution",
     "score": 0.88, "critical": True, "match": match_T55},
    {"id": "T56", "name": "CAPABILITY_BOUNDARY_PROBE",
     "desc": "Systematic reconnaissance of agent capabilities before exploitation",
     "score": 0.60, "critical": False, "match": match_T56},
    {"id": "T57", "name": "INSTRUCTION_HIERARCHY_BYPASS",
     "desc": "Exploiting system/user/tool trust hierarchy to override instructions",
     "score": 0.88, "critical": True, "match": match_T57},
    {"id": "T58", "name": "LONG_CONTEXT_DRIFT",
     "desc": "Slow behavioral drift via accumulated context manipulation",
     "score": 0.75, "critical": False, "match": match_T58},
    {"id": "T59", "name": "AGENTIC_SOCIAL_ENGINEERING",
     "desc": "Agent impersonating trusted systems or humans to gain elevated trust",
     "score": 0.85, "critical": True, "match": match_T59},
    {"id": "T60", "name": "DATA_PIPELINE_INJECTION",
     "desc": "Injecting malicious records into data pipelines the agent processes",
     "score": 0.85, "critical": True, "match": match_T60},
    {"id": "T61", "name": "COMPUTE_RESOURCE_ABUSE",
     "desc": "Agent using granted compute access for unauthorized workloads",
     "score": 0.82, "critical": False, "match": match_T61},
    {"id": "T62", "name": "SECRETS_IN_LOGS",
     "desc": "Sensitive data leaking into log or observability outputs",
     "score": 0.90, "critical": True, "match": match_T62},
    {"id": "T63", "name": "WEBHOOK_REPLAY_ATTACK",
     "desc": "Replaying legitimate webhook payloads to trigger unauthorized actions",
     "score": 0.82, "critical": False, "match": match_T63},
    {"id": "T64", "name": "AGENT_IDENTITY_SPOOFING",
     "desc": "Agent falsely claiming identity of another agent in multi-agent system",
     "score": 0.88, "critical": True, "match": match_T64},
    {"id": "T65", "name": "INFERENCE_TIME_ATTACK",
     "desc": "Timing-based probing of model internals via response latency",
     "score": 0.65, "critical": False, "match": match_T65},
    {"id": "T66", "name": "GaaS_TENANT_ESCALATION",
     "desc": "GaaS agent acquiring cross-tenant privileges via API key confusion",
     "score": 0.92, "critical": True, "match": match_T66},
    {"id": "T67", "name": "HEARTBEAT_SILENCE",
     "desc": "Explicit heartbeat, cron, or gateway suppression — the quietest failure mode",
     "score": 0.88, "critical": True, "match": match_T67},
    {"id": "T68", "name": "INSECURE_DEFAULT_CONFIG",
     "desc": "allow_remote=true with no auth — root cause of 40,000+ exposed instances",
     "score": 0.95, "critical": True, "match": match_T68},
    {"id": "T69", "name": "PLAN_DRIFT",
     "desc": (
         "Agent executing behavior that deviates from the approved Superpowers "
         "implementation plan. The human approved a specific plan; the agent is "
         "doing something different. Requires Superpowers integration. When present, "
         "this is the highest-confidence detection signal available — the deviation "
         "is measured against explicit human approval, not statistical baseline."
     ),
     "score": 0.95, "critical": True, "match": match_T69},
    {"id": "T70", "name": "ENV_PATH_HIJACK",
     "desc": (
         "Modification of PATH, LD_PRELOAD, LD_LIBRARY_PATH, PYTHONPATH, or NODE_PATH "
         "in an execution context. Proven attack class: GHSA-mc68-q9jw-2h3v documented "
         "command injection in Clawdbot Docker via PATH manipulation, redirecting execution "
         "to a malicious binary without any shell metacharacter. Invisible to T03 "
         "SHELL_INJECTION because there are no metacharacters — just a clean env var write "
         "that changes what 'python' or 'node' resolves to."
     ),
     "score": 0.88, "critical": True, "match": match_T70},
    {"id": "T71", "name": "PAIRING_GRACE_ABUSE",
     "desc": (
         "Exploitation of the 30-second device pairing grace period — "
         "OpenClaw ATLAS T-ACCESS-001. Race condition on pairing code "
         "interception. Fires on pairing tool calls with force/bypass/flood "
         "indicators inconsistent with legitimate device enrollment."
     ),
     "score": 0.82, "critical": True, "match": match_T71},
    {"id": "T72", "name": "CHANNEL_IDENTITY_SPOOF",
     "desc": (
         "AllowFrom sender identity spoofing or channel integration probing — "
         "OpenClaw ATLAS T-ACCESS-002 + T-RECON-002. Fires when message routing "
         "metadata contains identity override attempts or channel probing patterns."
     ),
     "score": 0.85, "critical": True, "match": match_T72},
    {"id": "T73", "name": "TOOL_ENUMERATION",
     "desc": (
         "Agent systematically probing its own tool list — OpenClaw ATLAS T-DISC-001. "
         "Classic pre-exploitation recon: empty/probe args across many distinct tools "
         "in rapid succession. mcp.list_tools and list_resources always fire."
     ),
     "score": 0.75, "critical": False, "match": match_T73},
    {"id": "T74", "name": "CONTENT_WRAPPER_ESCAPE",
     "desc": (
         "Attempt to escape OpenClaw XML content wrapping — "
         "OpenClaw ATLAS T-EVADE-001 + T-EVADE-002. "
         "CDATA sequences, tag terminators, or encoding tricks designed to "
         "break fetched content out of its wrapper and inject into agent context."
     ),
     "score": 0.86, "critical": True, "match": match_T74},
    {"id": "T82", "name": "SELF_IMPROVEMENT_HIJACK",
     "desc": (
         "Write of adversarial content to self-improvement infrastructure: "
         "agent archive directories, evaluation result files, performance tracking "
         "databases, or improvement procedure files used by systems like "
         "DGM-Hyperagents (Darwin Gödel Machine). "
         "Unlike T36 AGENTDEF (writes to static agent definition files) and T79 "
         "(writes to cross-session memory backends), T82 fires on writes to the "
         "evolutionary infrastructure that GENERATES future agents. A successful "
         "T82 injection propagates forward through all future generations — the "
         "adversary does not need to attack each generated agent; they attack the "
         "process that creates them. One poisoned turn, infinite forward propagation. "
         "DGM-Hyperagents architecture: agent archive (agents/, archive/, evolution/), "
         "evaluation results (eval_results.json, performance_log.json, "
         "improvement_history.json), improvement procedures (improve.py, "
         "meta_agent.py, self_improve/). "
         "Also fires on: RL reward design archives, automated paper review result "
         "stores, and any system where evaluation outputs feed back into agent "
         "generation. "
         "Score 0.96 — below T81 PTH_FILE_INJECT (0.98) and T43 HONEYPOT_ACCESS (1.0) "
         "because there are legitimate self-improvement writes; both conditions "
         "required: path matches self-improvement infrastructure AND content contains "
         "adversarial injection patterns. "
         "Sources: "
         "(1) Facebook Research DGM-Hyperagents (March 2026) — arxiv.org/abs/2603.19461. "
         "(2) Sakana AI / The AI Scientist, published Nature 2026 — "
         "arxiv.org/abs/2408.06292. The AI Scientist's Automated Reviewer is a "
         "high-risk T82 surface: its judgments feed back into the pipeline. "
         "Combined with the Nature paper's scaling law of science (better models → "
         "more convincing outputs), a single T82 injection into reviewer criteria "
         "produces increasingly convincing misinformation at scale."
     ),
     "score": 0.96, "critical": True, "match": match_T82},
    {"id": "T81", "name": "PTH_FILE_INJECT",
     "desc": (
         "Write of a Python .pth file to site-packages or any directory on PYTHONPATH. "
         ".pth files execute automatically on every Python interpreter startup, "
         "before any user code runs, before any package import, before Aiglos loads. "
         "This is the persistence mechanism used in the LiteLLM 1.82.8 supply chain "
         "attack (March 24, 2026): litellm_init.pth containing "
         "base64-encoded subprocess.Popen([sys.executable, '-c', 'import base64; exec(...)']). "
         "The attack exfiltrated SSH keys, AWS/GCP/Azure credentials, Kubernetes configs, "
         "database passwords, crypto wallets, and all environment variables from every "
         "machine that installed litellm, including via transitive dependencies (dspy, "
         "smolagents, LangChain). T30 SUPPLY_CHAIN fires on the install event. "
         "T81 fires on the .pth file write itself — catching the persistence mechanism "
         "at the moment it is placed, before it executes on the next Python startup. "
         "Score 0.98 — second only to T43 HONEYPOT_ACCESS (1.0). Writing a .pth file "
         "to site-packages is never legitimate agent behavior. "
         "Also fires on .pth files with suspicious content: base64, subprocess, exec, "
         "urllib, socket patterns in any Python path directory."
     ),
     "score": 0.98, "critical": True, "match": match_T81},
    {"id": "T80", "name": "UNCENSORED_MODEL_ROUTE",
     "desc": (
         "Agent routing inference through a model with safety filters deliberately "
         "removed — 'uncensored', 'abliterated', 'jailbreak', 'DAN', 'unrestricted', "
         "'nsfw' variants. When an agent uses an uncensored local model, every other "
         "safety layer (provider guardrails, content filtering, Anthropic/OpenAI "
         "moderation) is removed. Aiglos becomes the only guardrail. "
         "Score 0.78 — elevation signal, not a clear attack by itself. Fires on: "
         "model ID in inference config, routing tool calls, model load events. "
         "NDAA §1513 compliance note: defense contractors routing AI agents through "
         "uncensored models with no safety filters creates an attestation problem. "
         "The signed session artifact records both the declared model and the actual "
         "inference endpoint for honest compliance reporting. "
         "Source: HuggingFace trending models — Qwen3.5-35B-Uncensored (112k downloads "
         "this week), Qwen3.5-9B-Uncensored (255k downloads this week). "
         "Distinct from T44 INFERENCE_ROUTER_HIJACK (which fires on routing compromise) "
         "— T80 fires on deliberate architectural decisions that remove all other guards."
     ),
     "score": 0.78, "critical": False, "match": match_T80},
    {"id": "T79", "name": "PERSISTENT_MEMORY_INJECT",
     "desc": (
         "Write of adversarial content to a persistent, cross-session memory backend "
         "(SQLite database, vector store, or durable memory file) used by tools like "
         "Gigabrain, MemoryOS, or similar cross-session memory layers. "
         "Unlike T31 MEMORY_POISON (which fires on in-session memory writes), T79 "
         "fires specifically on writes to persistent stores that survive session close "
         "and are injected into every future session. A successful T79 attack means "
         "the adversary compromises the agent's context once and gets persistent "
         "influence over all future behavior — without needing to re-inject. "
         "Gigabrain (SQLite-backed, cross-session, OpenClaw/Claude Code/Codex) is the "
         "specific trigger: writes to ~/.gigabrain/, gigabrain.db, memory_store.db, "
         "or any declared memory backend path, containing injection patterns. "
         "Also fires on vector store upserts with injection content (Pinecone, Chroma, "
         "Qdrant, Weaviate) — the vector becomes a persistent retrieval-time attack. "
         "Score 0.92 — elevated above T31 (0.87) because persistence multiplies impact."
     ),
     "score": 0.92, "critical": True, "match": match_T79},
    {"id": "T78", "name": "HALLUCINATION_CASCADE",
     "desc": (
         "Cross-agent hallucination amplification: multiple sub-agents in a session "
         "converging on the same unverified assertion with escalating confidence. "
         "Named and documented by the Vox AI company case study (2026): "
         "'Agent A outputs a slightly inaccurate judgment. Agent B takes it as fact. "
         "Agent C stacks another layer. Eventually all agents converge on the same "
         "high-confidence wrong conclusion.' "
         "Fires when 3+ tool calls in a session cite the same suspicious claim phrase "
         "without any external source grounding, AND confidence-language escalates "
         "(certain > confident > likely). Distinct from T54 VECTOR_DB_INJECTION "
         "(which requires a poisoned database) — this is pure conversational drift. "
         "Fires on: repeated high-confidence unverified statistical claims, "
         "escalating certainty across sub-agent outputs, circular citation patterns."
     ),
     "score": 0.82, "critical": True, "match": match_T78},
    {"id": "T77", "name": "OVERNIGHT_JOB_INJECTION",
     "desc": (
         "Write or modification of scheduled job definitions (cron, scheduler, "
         "task files) in patterns consistent with malicious persistence. Power users "
         "run legitimate overnight jobs (Tip 6 pattern) — but an adversary can inject "
         "into those job slots. Fires on: cron file writes containing suspicious "
         "content, scheduler API calls with unusual job definitions, or writes to job "
         "config paths outside business hours. T67 HEARTBEAT_SILENCE catches "
         "suppression of jobs; T77 catches injection into the job schedule itself."
     ),
     "score": 0.87, "critical": True, "match": match_T77},
    {"id": "T76", "name": "NEMOCLAW_POLICY_BYPASS",
     "desc": (
         "Agent attempting to modify, overwrite, or delete NemoClaw OpenShell "
         "policy files at runtime. The NemoClaw YAML policy is the enforcement "
         "boundary that governs what the agent is allowed to do. An agent that "
         "rewrites its own policy has escaped governance entirely. "
         "NVIDIA NemoClaw policy paths: .nemoclaw/, .jensenclaw/, openShell.yaml. "
         "Score 0.95 — the only score higher is T43 HONEYPOT_ACCESS (1.0) because "
         "this is explicit policy destruction, not just policy violation."
     ),
     "score": 0.95, "critical": True, "match": match_T76},
    {"id": "T75", "name": "SESSION_DATA_EXTRACT",
     "desc": (
         "Lateral session data collection via sessions.list, sessions.preview, "
         "or chat.history. ATLAS T-DISC-002. OpenClaw sessionKey is routing "
         "not auth — any gateway-authenticated caller can enumerate session "
         "metadata. Bulk or rapid-succession session enumeration signals "
         "lateral data collection across session boundaries."
     ),
     "score": 0.82, "critical": True, "match": match_T75},
    {"id": "T83", "name": "INTER_AGENT_PROTOCOL_SPOOF",
     "desc": (
         "Manipulation of structured inter-agent coordination protocols. "
         "Based on Hermes supervisor architecture (NousResearch, March 2026): "
         "ACK suppression, STATUS_REQUEST spoofing, or protocol violation in "
         "registered inter-agent channels."
     ),
     "score": 0.88, "critical": True, "match": match_T83},
    {"id": "T84", "name": "IP_TRANSFORMATION_EXFIL",
     "desc": (
         "AI-agent-assisted intellectual property circumvention via code "
         "transformation. Based on the claw-code incident (March 31, 2026): "
         "reads proprietary source code and rewrites in a different language "
         "to circumvent copyright on derived works."
     ),
     "score": 0.80, "critical": False, "match": match_T84},
    {"id": "T85", "name": "AGENT_IDENTITY_SUPPRESSION",
     "desc": (
         "AI agent configured to actively deny being AI or suppress disclosure "
         "of AI authorship in outputs. "
         "Based on Claude Code undercover.ts (leaked March 31, 2026): a mode "
         "that strips all Anthropic internal references and instructs the model "
         "to never mention its AI nature. The code contains: "
         "'There is NO force-OFF. This guards against model codename leaks.' "
         "Extended in v0.25.18 with undercover mode vocabulary: 'operating undercover', "
         "'never include any hint', 'strip all traces', 'no force-off', 'internal "
         "allowlist', suppressed model codenames (capybara, tengu). "
         "Compliance: NDAA S1513 transparency requirements for DoD environments; "
         "EU AI Act Article 52 human-AI interaction disclosure mandate. "
         "Score 0.75 -- not critical (legitimate brand suppression exists); "
         "fires on explicit denial instructions, not mere vendor name avoidance."
     ),
     "score": 0.75, "critical": False, "match": match_T85},
    {"id": "T86", "name": "CROSS_TENANT_ACCESS",
     "desc": (
         "Agent reading data from one tenant/customer context and writing or "
         "transmitting toward a different tenant context without explicit "
         "authorization. Session-level tracking of tenant identifiers."
     ),
     "score": 0.90, "critical": True, "match": match_T86},
    {"id": "T87", "name": "THRESHOLD_PROBING",
     "desc": (
         "Systematic tool-name variation after blocked calls to find alternative "
         "execution paths. Tracks blocked call fingerprints per session using MD5 "
         "of endpoint and key argument values."
     ),
     "score": 0.88, "critical": True, "match": match_T87},
    {"id": "T88", "name": "MCP_AUTH_BYPASS",
     "desc": (
         "Unauthorized MCP credential registration after session init. "
         "Four vectors: post-init auth (registers new MCP credentials bypassing "
         "operator review), token hijack (re-registers existing credentials under "
         "different server), server spoofing, rate-limit bypass via multiple "
         "credential registrations. From PARITY.md McpAuthTool gap analysis."
     ),
     "score": 0.87, "critical": False, "match": match_T88},
    {"id": "T89", "name": "CONTRIBUTION_PROVENANCE_SUPPRESSION",
     "desc": (
         "Agent performing VCS operations (commit/push/PR/merge) while active "
         "identity suppression is configured -- the undercover mode pattern. "
         "From Claude Code undercover.ts (March 2026 leak): auto-on by default, "
         "no force-off, triggers when target repo is not on Anthropic internal allowlist. "
         "Commit prompt includes: 'You are operating UNDERCOVER in a PUBLIC/OPEN-SOURCE "
         "repository. NEVER include any hint that you are an AI.' "
         "Compliance gap: enterprises using Claude Code to contribute to public repos "
         "produce AI contributions that appear human-authored with no mechanism to "
         "disable this behavior. Aiglos forensic store is the only audit trail recording "
         "sessions where identity suppression was active during VCS contributions. "
         "Applicable regulations: NDAA S1513 (AI transparency in DoD), EU AI Act "
         "Article 52 (AI disclosure when interacting with humans), enterprise open-source "
         "contribution policies requiring AI disclosure. "
         "Score 0.78 -- not critical (legitimate: human commits AI-suggested code). "
         "Complementary to T85 (config side) and ForensicStore (the audit trail)."
     ),
     "score": 0.78, "critical": False, "match": match_T89},
]
