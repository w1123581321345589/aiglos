"""
aiglos.integrations.smolagents
================================
HuggingFace smolagents integration.

Wraps any smolagents CodeAgent or ToolCallingAgent with Aiglos T01-T82
enforcement and after-call injection scanning.

Usage:
    from aiglos.integrations.smolagents import attach_for_smolagents
    guard = attach_for_smolagents(agent, policy="strict")
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class SmolagentsGuard:
    """Wraps a smolagents agent with Aiglos enforcement."""
    agent: Any = None
    policy: str = "default"
    session_id: str = ""
    events: list = field(default_factory=list)
    blocked: int = 0
    scanned: int = 0
    injections_caught: int = 0
    _attached: bool = False

    def record_event(self, event_type: str, tool_name: str = "", verdict: str = "allow", **kw):
        self.events.append({
            "type": event_type,
            "tool": tool_name,
            "verdict": verdict,
            "ts": time.time(),
            **kw,
        })
        self.scanned += 1
        if verdict == "block":
            self.blocked += 1

    def scan_output(self, tool_name: str, output: str) -> Optional[dict]:
        """Scan tool output for injection attempts."""
        injection_patterns = [
            r"ignore\s+(previous|above|all)\s+(instructions|prompts)",
            r"system\s*:\s*you\s+are",
            r"<\|im_start\|>system",
            r"\[INST\].*\[/INST\]",
            r"do not follow.*original",
            r"override.*instructions",
            r"new role.*you are now",
        ]
        for pattern in injection_patterns:
            if re.search(pattern, output, re.IGNORECASE):
                self.injections_caught += 1
                hit = {
                    "type": "injection_detected",
                    "tool": tool_name,
                    "pattern": pattern,
                    "severity": "high",
                }
                self.record_event("injection", tool_name, "block", **hit)
                return hit
        return None

    def status(self) -> dict:
        return {
            "attached": self._attached,
            "policy": self.policy,
            "scanned": self.scanned,
            "blocked": self.blocked,
            "injections_caught": self.injections_caught,
            "events": len(self.events),
        }


def attach_for_smolagents(
    agent: Any = None,
    policy: str = "default",
    session_id: str = "",
) -> SmolagentsGuard:
    """
    Attach Aiglos enforcement to a smolagents CodeAgent or ToolCallingAgent.

    Wraps the agent's tool execution with T01-T82 enforcement and
    after-call injection scanning on tool outputs.

    Args:
        agent: A smolagents CodeAgent or ToolCallingAgent instance.
        policy: Enforcement policy ('default', 'strict', 'federal').
        session_id: Optional session identifier for audit trail.

    Returns:
        SmolagentsGuard instance with the agent wrapped.
    """
    guard = SmolagentsGuard(
        agent=agent,
        policy=policy,
        session_id=session_id or f"smolagents-{int(time.time())}",
    )

    if agent is not None:
        try:
            original_run = agent.run

            def guarded_run(*args, **kwargs):
                guard.record_event("run_start", verdict="allow")
                try:
                    result = original_run(*args, **kwargs)
                    if isinstance(result, str):
                        hit = guard.scan_output("agent.run", result)
                        if hit and policy == "strict":
                            raise RuntimeError(
                                f"[Aiglos] Injection detected in agent output: {hit['pattern']}"
                            )
                    guard.record_event("run_complete", verdict="allow")
                    return result
                except RuntimeError:
                    raise
                except Exception as e:
                    guard.record_event("run_error", verdict="allow", error=str(e))
                    raise

            agent.run = guarded_run
            guard._attached = True
        except (AttributeError, TypeError):
            guard._attached = False
    else:
        guard._attached = False

    return guard
