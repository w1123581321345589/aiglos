"""
aiglos/integrations/ollama.py

Runtime security monitor for Ollama-served local models.

The "own your intelligence" architecture -- Opus orchestrator routing
to local model executors (Qwen, Gemma, Llama, Mistral) on Mac Studios,
Mac Minis, or DGX Sparks -- requires a monitoring layer that operates
without provider-side abuse detection. Providers can revoke hosted model
access (T94). Local models process untrusted data without alignment
enforcement (T95). This integration covers both surfaces.

Usage:
    from aiglos.integrations.ollama import OllamaGuard, attach_for_ollama

    guard = OllamaGuard(
        agent_name="local-executor",
        policy="enterprise",
        orchestrator_model="claude-opus-4",   # declares trust boundary
    )

    # Wrap Ollama client
    session = attach_for_ollama(guard, ollama_client)

    # Or use directly
    result = guard.before_tool_call("ollama.generate", {
        "model": "qwen3:32b",
        "prompt": user_input,
    })
"""

from __future__ import annotations

import os
import re
import json
import time
import hashlib
from typing import Any, Dict, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    pass


# ── Known local model families ────────────────────────────────────────────────
LOCAL_MODEL_FAMILIES = frozenset([
    # Qwen family
    "qwen", "qwen2", "qwen2.5", "qwen3",
    # Google Gemma
    "gemma", "gemma2", "gemma3",
    # Meta Llama
    "llama", "llama2", "llama3", "llama3.1", "llama3.2", "llama3.3",
    # Mistral
    "mistral", "mixtral", "mistral-nemo",
    # Microsoft Phi
    "phi", "phi3", "phi4",
    # DeepSeek
    "deepseek", "deepseek-r1",
    # Uncensored / abliterated variants (T80 surface)
    "uncensored", "abliterated", "dolphin", "nous-hermes",
    # Apple MLX optimized
    "mlx",
])

# ── Ollama API endpoint patterns ───────────────────────────────────────────────
OLLAMA_ENDPOINTS = frozenset([
    "localhost:11434", "127.0.0.1:11434",
    "0.0.0.0:11434",
    "/api/generate", "/api/chat", "/api/embed",
    "ollama",
])

# ── LM Studio endpoint patterns ───────────────────────────────────────────────
LMSTUDIO_ENDPOINTS = frozenset([
    "localhost:1234", "127.0.0.1:1234",
    "lmstudio", "lm-studio", "lm_studio",
])


class OllamaGuard:
    """
    Runtime security guard for Ollama-served local model deployments.

    Provides the same before_tool_call / after_tool_call / close_session
    interface as OpenClawGuard, adapted for local model contexts:

    1. T94 detection: catches provider policy rejections on the
       orchestrator side (Anthropic, OpenAI) so pipeline failure
       is surfaced before silent degradation.

    2. T95 detection: catches cross-trust-boundary injection when
       local executor output is passed back to a frontier orchestrator.

    3. T80 detection: flags uncensored/abliterated model variants
       being loaded, which bypass alignment training entirely.

    4. Session-level provider tracking: records which models were
       active during the session for forensic reconstruction.
    """

    def __init__(
        self,
        agent_name: str = "local-agent",
        policy: str = "enterprise",
        orchestrator_model: Optional[str] = None,
        log_path: Optional[str] = None,
    ):
        self.agent_name = agent_name
        self.policy = policy
        self.orchestrator_model = orchestrator_model
        self._session_id = hashlib.sha256(
            f"{agent_name}{time.time()}".encode()
        ).hexdigest()[:16]
        self._log_path = log_path
        self._calls: List[Dict] = []
        self._blocked: List[Dict] = []
        self._models_seen: List[str] = []
        self._started_at = time.time()

        # Import guard rules lazily to avoid circular dependency
        self._guard = None
        self._init_guard()

    def _init_guard(self):
        """Initialize the underlying guard with appropriate policy."""
        try:
            # Try to get a full guard from the main package
            import sys
            sys.path.insert(0, '/home/claude')
            from aiglos.integrations.openclaw import OpenClawGuard
            self._guard = OpenClawGuard(
                agent_name=self.agent_name,
                policy=self.policy,
                log_path=self._log_path,
            )
        except ImportError:
            # Fallback: use direct rule evaluation
            self._guard = None

    def before_tool_call(
        self,
        tool_name: str,
        args: Dict[str, Any],
    ) -> "OllamaGuardResult":
        """
        Evaluate a tool call before execution.

        Key checks:
        - T94: provider policy rejection in LLM API response
        - T95: instruction injection in local model output
        - T80: uncensored model variant detection
        - Trust boundary: local output flowing to orchestrator context
        """
        self._calls.append({
            "tool": tool_name,
            "ts": time.time(),
        })

        # Track model names seen
        args_str = json.dumps(args, default=str).lower()
        for family in LOCAL_MODEL_FAMILIES:
            if family in args_str:
                if family not in self._models_seen:
                    self._models_seen.append(family)

        # Run underlying guard if available
        if self._guard:
            try:
                result = self._guard.before_tool_call(tool_name, args)
                if result.verdict in ("BLOCK", "WARN"):
                    self._blocked.append({
                        "tool": tool_name,
                        "threat": getattr(result, 'threat_class', 'unknown'),
                        "verdict": result.verdict,
                        "ts": time.time(),
                    })
                return OllamaGuardResult(
                    verdict=result.verdict,
                    threat_class=getattr(result, 'threat_class', None),
                    score=getattr(result, 'score', 0.0),
                    session_id=self._session_id,
                )
            except Exception:
                pass

        # Standalone check using direct rule imports
        return self._standalone_check(tool_name, args, args_str)

    def _standalone_check(
        self,
        tool_name: str,
        args: Dict[str, Any],
        args_str: str,
    ) -> "OllamaGuardResult":
        """Direct rule evaluation with inline pattern matching."""
        threats = []
        n = tool_name.lower()

        # ── T94: Provider policy rejection ──────────────────────────────────
        _t94_policy_patterns = [
            "usage policy", "policy violation", "terms of service",
            "access denied", "account suspended", "api access revoked",
            "model deprecated", "model no longer available", "endpoint deprecated",
            "your account has been", "access to this model",
            "this model is not available", "quota exceeded",
            "access forbidden", "subscription required",
        ]
        _t94_provider_kws = [
            "llm", "claude", "openai", "gemini", "anthropic", "model",
            "completion", "chat", "generate", "inference", "litellm",
            "proxy", "router", "gateway", "http", "request", "response",
        ]
        is_provider = any(kw in n for kw in _t94_provider_kws)
        if not is_provider:
            is_provider = any(kw in args_str for kw in (
                "api.anthropic", "api.openai", "generativelanguage",
                "litellm", "openrouter", "model_name", "model_id",
            ))
        if is_provider:
            if any(p in args_str for p in _t94_policy_patterns):
                threats.append(("T94", "PROVIDER_POLICY_REJECTION", 0.80))
            if "403" in args_str and is_provider:
                threats.append(("T94", "PROVIDER_POLICY_REJECTION", 0.80))

        # ── T95: Cross-trust-boundary injection ──────────────────────────────
        _t95_executor_kws = [
            "ollama", "lmstudio", "lm_studio", "llama.cpp", "llamacpp",
            "localai", "vllm", "mlx", "qwen", "gemma", "llama", "mistral",
            "phi", "deepseek", "executor", "worker", "subagent", "local_model",
        ]
        _t95_injection_patterns = [
            "ignore previous instructions", "ignore all previous",
            "disregard your previous", "forget your instructions",
            "new instructions:", "system: ", "[system]",
            "i am your", "you are now", "act as", "you must now",
            "your new role", "override previous",
            "call tool", "invoke tool", "tool_call:",
            "do not tell", "hidden instruction",
            "from your developer", "from anthropic", "from openai",
            "assistant:", "system message:", "[inst]", "<s>[inst]",
        ]
        _t95_response_kws = [
            "result", "response", "output", "completion", "return",
            "tool_result", "after_tool",
        ]
        is_executor = (
            any(kw in n for kw in _t95_executor_kws)
            or any(kw in args_str for kw in _t95_executor_kws)
        )
        is_response = any(kw in n for kw in _t95_response_kws)
        if (is_executor or is_response):
            if any(p in args_str for p in _t95_injection_patterns):
                threats.append(("T95", "CROSS_TRUST_BOUNDARY_INJECT", 0.88))

        # ── T80: Uncensored model detection ──────────────────────────────────
        uncensored_markers = [
            "uncensored", "abliterated", "no-filter", "nofilter",
            "jailbreak", "unrestricted", "dolphin", "dan",
        ]
        if any(m in args_str for m in uncensored_markers):
            threats.append(("T80", "UNCENSORED_MODEL_ROUTE", 0.78))

        if not threats:
            return OllamaGuardResult(
                verdict="ALLOW",
                threat_class=None,
                score=0.0,
                session_id=self._session_id,
            )

        # Return highest-severity threat
        threats.sort(key=lambda x: x[2], reverse=True)
        top = threats[0]

        thresholds = {
            "permissive": (0.90, 0.70),
            "enterprise": (0.75, 0.55),
            "strict":     (0.50, 0.35),
            "federal":    (0.40, 0.25),
            "lockdown":   (0.0,  0.0),
        }
        block_t, warn_t = thresholds.get(self.policy, (0.75, 0.55))

        verdict = "ALLOW"
        if top[2] >= block_t:
            verdict = "BLOCK"
        elif top[2] >= warn_t:
            verdict = "WARN"

        if verdict in ("BLOCK", "WARN"):
            self._blocked.append({
                "tool": tool_name,
                "threat": top[0],
                "verdict": verdict,
                "ts": time.time(),
            })

        return OllamaGuardResult(
            verdict=verdict,
            threat_class=top[0],
            score=top[2],
            session_id=self._session_id,
        )

    def after_tool_call(
        self,
        tool_name: str,
        output: Any,
    ) -> Optional["OllamaGuardResult"]:
        """
        Scan tool output for cross-trust-boundary injection.
        Critical path: local executor response before it reaches
        the orchestrator context window.
        """
        if output is None:
            return None

        output_str = str(output).lower()
        args = {"output": output_str, "tool_result": output_str}

        return self._standalone_check(f"tool_result.{tool_name}", args, output_str)

    def close_session(self) -> Dict[str, Any]:
        """
        Produce session artifact with local model context.
        Includes provider policy events, trust boundary violations,
        and model family inventory for forensic reconstruction.
        """
        artifact = {
            "schema": "aiglos/v1",
            "agent_name": self.agent_name,
            "session_id": self._session_id,
            "policy": self.policy,
            "orchestrator_model": self.orchestrator_model,
            "local_models_used": self._models_seen,
            "started_at": self._started_at,
            "closed_at": time.time(),
            "total_calls": len(self._calls),
            "blocked_calls": len(self._blocked),
            "threats": self._blocked,
            "provider_dependency_risk": self._assess_provider_risk(),
            "attestation_ready": self.policy in ("strict", "federal"),
        }

        sig_data = json.dumps({
            k: artifact[k] for k in
            ["agent_name", "session_id", "policy", "total_calls", "blocked_calls"]
        }, sort_keys=True).encode()
        artifact["signature"] = "sha256:" + hashlib.sha256(sig_data).hexdigest()

        return artifact

    def _assess_provider_risk(self) -> Dict[str, Any]:
        """
        Assess provider dependency risk for this session.
        Flags single-provider dependency and missing fallback config.
        """
        provider_events = [b for b in self._blocked if b.get("threat") == "T94"]
        has_local_fallback = len(self._models_seen) > 0
        orchestrator_named = self.orchestrator_model is not None

        return {
            "policy_rejection_events": len(provider_events),
            "has_local_fallback_models": has_local_fallback,
            "local_models": self._models_seen,
            "orchestrator_declared": orchestrator_named,
            "single_provider_risk": not has_local_fallback and orchestrator_named,
            "govbench_d1_penalty": len(provider_events) > 0 and not has_local_fallback,
        }


class OllamaGuardResult:
    """Result from OllamaGuard.before_tool_call()."""

    def __init__(
        self,
        verdict: str,
        threat_class: Optional[str],
        score: float,
        session_id: str,
    ):
        self.verdict = verdict
        self.threat_class = threat_class
        self.score = score
        self.session_id = session_id

    def is_blocked(self) -> bool:
        """Return True if the tool call was blocked."""
        return self.verdict == "BLOCK"

    def is_warned(self) -> bool:
        """Return True if the tool call triggered a warning."""
        return self.verdict == "WARN"

    def __repr__(self) -> str:
        return (f"OllamaGuardResult(verdict={self.verdict}, "
                f"threat={self.threat_class}, score={self.score:.2f})")


def attach_for_ollama(
    guard: OllamaGuard,
    ollama_client: Any = None,
) -> OllamaGuard:
    """
    Attach OllamaGuard to an Ollama client instance.
    Returns the guard for session management.

    Usage:
        import ollama
        client = ollama.Client()
        guard = OllamaGuard("my-agent", policy="enterprise")
        session = attach_for_ollama(guard, client)
    """
    if ollama_client is not None:
        # Wrap the generate and chat methods
        original_generate = getattr(ollama_client, 'generate', None)
        original_chat = getattr(ollama_client, 'chat', None)

        if original_generate:
            def guarded_generate(model, prompt, **kwargs):
                args = {"model": model, "prompt": prompt, **kwargs}
                result = guard.before_tool_call("ollama.generate", args)
                if result.is_blocked():
                    raise RuntimeError(
                        f"[Aiglos] Blocked: {result.threat_class} "
                        f"(score={result.score:.2f})"
                    )
                output = original_generate(model, prompt, **kwargs)
                guard.after_tool_call("ollama.generate", output)
                return output
            ollama_client.generate = guarded_generate

        if original_chat:
            def guarded_chat(model, messages, **kwargs):
                args = {"model": model, "messages": str(messages), **kwargs}
                result = guard.before_tool_call("ollama.chat", args)
                if result.is_blocked():
                    raise RuntimeError(
                        f"[Aiglos] Blocked: {result.threat_class} "
                        f"(score={result.score:.2f})"
                    )
                output = original_chat(model, messages, **kwargs)
                guard.after_tool_call("ollama.chat", output)
                return output
            ollama_client.chat = guarded_chat

    return guard


def lmstudio_guard(
    agent_name: str = "lmstudio-agent",
    policy: str = "enterprise",
    base_url: str = "http://localhost:1234/v1",
    orchestrator_model: Optional[str] = None,
) -> OllamaGuard:
    """
    Create an OllamaGuard configured for LM Studio deployments.
    LM Studio serves an OpenAI-compatible API on port 1234.

    Usage:
        guard = lmstudio_guard("my-agent", policy="strict",
                                orchestrator_model="claude-opus-4")
    """
    return OllamaGuard(
        agent_name=agent_name,
        policy=policy,
        orchestrator_model=orchestrator_model,
    )
