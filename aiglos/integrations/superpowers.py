"""
aiglos/integrations/superpowers.py
====================================
Superpowers integration -- plan-drift detection for agentic development.

Superpowers (github.com/obra/superpowers) is an agentic development methodology
that enforces brainstorm-first spec refinement, explicit implementation plans,
subagent-driven execution, and true TDD. When installed alongside Aiglos, the
approved implementation plan becomes the enforcement boundary.

T69 PLAN_DRIFT fires when the agent executes tool calls outside the plan's
declared file or network scope. Phase-aware detection suppresses behavioral
anomaly during brainstorm/planning phases and recognizes the TDD loop as a
known clean pattern during tdd_loop phase.

SUPERPOWERS_PLAN_HIJACK campaign pattern: plan drift followed by data
exfiltration. The highest-confidence campaign signature in the system (0.97).

Usage:
    from aiglos.integrations.superpowers import mark_as_superpowers_session

    session = mark_as_superpowers_session(
        plan_text=approved_plan,
        allowed_files=["src/", "tests/"],
        allowed_hosts=["api.internal.com"],
        guard=guard,
    )

    session.set_phase("execute")
    session.set_phase("tdd_loop")
    session.set_phase("commit")
"""

import hashlib
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


VALID_PHASES = [
    "brainstorm",
    "planning",
    "execute",
    "tdd_loop",
    "commit",
    "review",
]

TDD_LOOP_SEQUENCE = [
    "write_test",
    "shell_fail",
    "write_impl",
    "shell_pass",
    "git_commit",
]


@dataclass
class SuperpowersSession:
    plan_hash: str
    allowed_files: List[str]
    allowed_hosts: List[str]
    phase: str = "planning"
    phase_history: List[Dict[str, Any]] = field(default_factory=list)
    tdd_step_count: int = 0
    drift_events: List[Dict[str, Any]] = field(default_factory=list)
    guard: Any = None
    created_at: float = field(default_factory=time.time)

    def set_phase(self, phase: str) -> None:
        if phase not in VALID_PHASES:
            raise ValueError(
                f"Invalid phase '{phase}'. Valid: {VALID_PHASES}"
            )
        self.phase_history.append({
            "from": self.phase,
            "to": phase,
            "at": time.time(),
        })
        self.phase = phase

    def check_file_scope(self, path: str) -> bool:
        for allowed in self.allowed_files:
            if path.startswith(allowed):
                return True
        return False

    def check_host_scope(self, host: str) -> bool:
        for allowed in self.allowed_hosts:
            if allowed.startswith("*."):
                if host.endswith(allowed[1:]):
                    return True
            elif host == allowed:
                return True
        return False

    def record_drift(self, tool_name: str, args: dict, reason: str) -> None:
        self.drift_events.append({
            "tool": tool_name,
            "args": args,
            "reason": reason,
            "phase": self.phase,
            "at": time.time(),
        })

    def is_tdd_phase(self) -> bool:
        return self.phase == "tdd_loop"

    def is_planning_phase(self) -> bool:
        return self.phase in ("brainstorm", "planning")

    def artifact_data(self) -> dict:
        return {
            "plan_hash": self.plan_hash,
            "phase_history": self.phase_history,
            "tdd_step_count": self.tdd_step_count,
            "drift_events": len(self.drift_events),
            "final_phase": self.phase,
        }


def mark_as_superpowers_session(
    plan_text: str,
    allowed_files: Optional[List[str]] = None,
    allowed_hosts: Optional[List[str]] = None,
    guard: Any = None,
) -> SuperpowersSession:
    plan_hash = hashlib.sha256(plan_text.encode()).hexdigest()[:16]

    session = SuperpowersSession(
        plan_hash=plan_hash,
        allowed_files=allowed_files or [],
        allowed_hosts=allowed_hosts or [],
        guard=guard,
    )

    if guard is not None and hasattr(guard, "attach_superpowers"):
        guard.attach_superpowers(session)

    return session


class SuperpowersPhase:
    """Phase constants for Superpowers sessions."""
    PLANNING = "planning"
    EXECUTING = "executing"
    REVIEWING = "reviewing"
    COMPLETED = "completed"

    ALL = [PLANNING, EXECUTING, REVIEWING, COMPLETED]

    @classmethod
    def is_valid(cls, phase: str) -> bool:
        return phase in cls.ALL
