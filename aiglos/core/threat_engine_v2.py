"""
aiglos/core/threat_engine_v2.py
=================================
T44-T66 threat rule library -- second-generation threat families.

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
# Agent breaking out of declared workflow scope -- executing steps,
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
# or system prompt -- reconnaissance for follow-on attacks.

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
# Systematic reconnaissance of what the agent can do -- probing tool limits,
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
# and tool output -- using one layer to override another.

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
# Complements T41 (outbound secrets) -- catches log-destination leakage
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
_T67_SILENCE = re.compile(
    r'(?:heartbeat[_\s]*(?:stop|kill|disable|silence|suppress)|'
    r'kill[_\s]*(?:gateway|cron|heartbeat|scheduler)|'
    r'disable[_\s]*(?:heartbeat|monitoring|cron|scheduler)|'
    r'stop[_\s]*(?:gateway|cron|monitoring))',
    re.IGNORECASE
)

def match_T67(name: str, args: Dict[str, Any]) -> bool:
    """T67 HEARTBEAT_SILENCE -- explicit heartbeat/cron suppression attempt."""
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
    """T68 INSECURE_DEFAULT_CONFIG -- allow_remote=true with no auth/allowlist."""
    s = _args_str(args)
    content = _content(args)
    combined = s + " " + content

    if not _T68_ALLOW_REMOTE.search(combined):
        return False

    if _T68_NO_AUTH.search(combined):
        return True

    auth_keywords = ("api_key", "apikey", "token", "password", "auth",
                     "secret", "allowlist", "allow_list", "whitelist", "credential")
    if not any(kw in combined for kw in auth_keywords):
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
     "desc": "Explicit heartbeat, cron, or gateway suppression -- the quietest failure mode",
     "score": 0.88, "critical": True, "match": match_T67},
    {"id": "T68", "name": "INSECURE_DEFAULT_CONFIG",
     "desc": "allow_remote=true with no auth -- root cause of 40,000+ exposed instances",
     "score": 0.95, "critical": True, "match": match_T68},
]
