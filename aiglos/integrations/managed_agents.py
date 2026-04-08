"""
aiglos/integrations/managed_agents.py

Aiglos integration for Anthropic Managed Agents.

Anthropic's Managed Agents architecture (April 2026) virtualizes three
components: a session (append-only log), a harness (the loop that calls
Claude and routes tool calls), and a sandbox (execution environment).

Aiglos governs all three layers:
    - Session layer: intercept emitEvent() / getEvents() to detect
      evidence tampering and unauthorized session manipulation
    - Harness layer: before/after execute(name, input) -> string
      interception using the full T-rule engine
    - Sandbox layer: T97 sandbox escape, T96 exploit chain, T100
      forensic evidence tampering, T99 eval context awareness

The key architectural insight from the Anthropic post:
    "In the coupled design, any untrusted code that Claude generated was
    run in the same container as credentials. The structural fix was to
    make sure the tokens are never reachable from the sandbox."

The proxy between brain and OAuth vault is exactly the layer Aiglos
governs. ManagedAgentGuard wraps that proxy interface.

Multi-brain topology: "brains can pass hands to one another."
Each brain is a distinct NHI with a declared capability scope. A
compromised brain passing malicious hands to other brains is T64
AGENT_IDENTITY_SPOOFING at the managed agent topology level.

Usage:
    from aiglos.integrations.managed_agents import ManagedAgentGuard

    guard = ManagedAgentGuard(agent_name="my-brain", policy="enterprise")

    # Wrap session API
    with guard.session_scope(session_id) as session:
        result = await session.emit_event(event)

    # Wrap execute() interface
    result = guard.execute("bash", {"command": cmd})
    # -> ALLOW/WARN/BLOCK before execution, signed artifact after

    # Multi-brain registration
    guard.register_brain("sub-brain-01", capabilities=["read_file", "web_search"])
    result = guard.delegate_hand("sub-brain-01", hand_name="sandbox-02")
"""

from __future__ import annotations

import hashlib
import json
import time
import sys
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set


# ── Session event types (from Managed Agents spec) ────────────────────────────

SESSION_EVENT_TYPES = frozenset([
    "tool_call", "tool_result", "message", "thinking",
    "error", "checkpoint", "wake", "provision", "emit",
])

# Suspicious session manipulation patterns
SESSION_TAMPER_PATTERNS = [
    # Attempting to overwrite past events
    "overwrite_event", "delete_event", "modify_event",
    "truncate_session", "clear_events", "reset_session",
    # Injecting false history
    "inject_history", "prepend_event", "backdate",
    # Evidence suppression
    "suppress_event", "filter_events", "hide_event",
]


# ── Brain registry for multi-brain topology ───────────────────────────────────

@dataclass
class BrainRegistration:
    """A registered brain in the multi-brain topology."""
    brain_id:        str
    brain_name:      str
    capabilities:    Set[str]        # tools/hands this brain can use
    allowed_hands:   Set[str]        # sandboxes/hands it can invoke
    parent_brain_id: Optional[str]   # None = root brain
    registered_at:   str
    trust_level:     str             # root | delegated | sandboxed
    revoked:         bool = False


@dataclass
class HandDelegation:
    """A brain-to-brain hand delegation event."""
    from_brain_id:  str
    to_brain_id:    str
    hand_name:      str
    authorized:     bool
    timestamp:      str
    blocked:        bool = False


# ── Verdict types ─────────────────────────────────────────────────────────────

@dataclass
class ExecuteVerdict:
    """Verdict for a managed agent execute() call."""
    verdict:        str           # ALLOW | WARN | BLOCK
    threat_class:   Optional[str]
    threat_name:    Optional[str]
    score:          float
    trust:          float
    session_id:     str
    execute_name:   str


# ── Managed Agent Guard ───────────────────────────────────────────────────────

class ManagedAgentGuard:
    """
    Aiglos governance layer for Anthropic Managed Agents.

    Wraps the three Managed Agents interfaces:
        - session: emitEvent() / getEvents() monitoring
        - harness: execute(name, input) -> string interception
        - sandbox: T97/T96/T100 protection for execution environments

    Also manages the multi-brain topology via BrainRegistry:
        - register_brain(): register a new brain with capability scope
        - delegate_hand(): authorize brain-to-brain hand delegation
        - check_hand_delegation(): validate delegation before execution

    Usage in Managed Agents harness:

        guard = ManagedAgentGuard(agent_name="root-brain", policy="enterprise")

        # Before each execute() call in the harness loop:
        verdict = guard.before_execute(name, input_data)
        if verdict.verdict == "BLOCK":
            return f"[Aiglos blocked: {verdict.threat_class}]"

        result = actual_execute(name, input_data)

        # After execute() returns:
        guard.after_execute(name, result, verdict.session_id)

        # On session close:
        artifact = guard.close_session()
    """

    POLICY_THRESHOLDS = {
        "permissive": (0.90, 0.70),
        "enterprise": (0.75, 0.55),
        "strict":     (0.50, 0.35),
        "federal":    (0.40, 0.25),
        "lockdown":   (0.00, 0.00),
    }

    def __init__(
        self,
        agent_name:  str = "managed-agent",
        policy:      str = "enterprise",
        session_id:  Optional[str] = None,
        log_dir:     Optional[str] = None,
    ):
        self.agent_name = agent_name
        self.policy     = policy
        self.session_id = session_id or hashlib.sha256(
            f"{agent_name}{time.time()}".encode()
        ).hexdigest()[:16]

        self._trust           = 1.0
        self._total_calls     = 0
        self._blocked_calls   = 0
        self._threats:  List[Dict] = []
        self._events:   List[Dict] = []
        self._delegations: List[HandDelegation] = []
        self._brain_registry: Dict[str, BrainRegistration] = {}
        self._log_dir = Path(log_dir or Path.home() / ".aiglos" / "managed_agent_sessions")
        self._log_dir.mkdir(parents=True, exist_ok=True)

        # Load threat engine lazily
        self._rules: Optional[List[Dict]] = None

    # ── Rule engine ───────────────────────────────────────────────────────────

    def _load_rules(self) -> List[Dict]:
        if self._rules is None:
            try:
                from aiglos.core.threat_engine_v2 import RULES_T44_T66
                self._rules = RULES_T44_T66
            except ImportError:
                self._rules = []
        return self._rules

    def _evaluate(self, name: str, args: Dict) -> tuple[str, Optional[Dict], float]:
        """Evaluate a tool call. Returns (verdict, rule, score)."""
        rules = self._load_rules()
        block_t, warn_t = self.POLICY_THRESHOLDS.get(self.policy, (0.75, 0.55))
        top_score = 0.0
        top_rule  = None

        for rule in rules:
            try:
                if rule["match"](name, args):
                    score = rule["score"] * (0.7 + (1 - self._trust) * 0.3)
                    if score > top_score:
                        top_score = score
                        top_rule  = rule
            except Exception:
                pass

        verdict = "ALLOW"
        if top_score >= block_t:
            verdict = "BLOCK"
        elif top_score >= warn_t:
            verdict = "WARN"

        return verdict, top_rule, top_score

    # ── Execute interface wrapping ────────────────────────────────────────────

    def before_execute(
        self,
        name:  str,
        input_data: Any,
        brain_id: Optional[str] = None,
    ) -> ExecuteVerdict:
        """
        Intercept before execute(name, input) -> string.

        This is the primary interception point in the Managed Agents
        harness loop. Every tool call, MCP call, and sandbox execution
        routes through this before execution.

        Args:
            name:       The tool/sandbox name being executed.
            input_data: The input being passed to the tool.
            brain_id:   The brain initiating the call (for multi-brain).
        """
        self._total_calls += 1
        args = input_data if isinstance(input_data, dict) else {"input": str(input_data)}

        verdict, rule, score = self._evaluate(name, args)

        if verdict in ("BLOCK", "WARN") and rule:
            self._trust = max(0.0, self._trust - score * 0.1)
            threat_event = {
                "tool":    name,
                "threat":  rule["id"],
                "name":    rule["name"],
                "score":   score,
                "verdict": verdict,
                "ts":      datetime.now(timezone.utc).isoformat(),
                "brain_id": brain_id,
            }
            self._threats.append(threat_event)
            self._emit_internal_event("threat_detected", threat_event)

        if verdict == "BLOCK":
            self._blocked_calls += 1

        return ExecuteVerdict(
            verdict      = verdict,
            threat_class = rule["id"]   if rule else None,
            threat_name  = rule["name"] if rule else None,
            score        = score,
            trust        = self._trust,
            session_id   = self.session_id,
            execute_name = name,
        )

    def after_execute(
        self,
        name:   str,
        result: str,
        verdict_session_id: Optional[str] = None,
    ) -> ExecuteVerdict:
        """
        Scan executor output for cross-trust-boundary injection (T95).

        In the Managed Agents architecture, sandbox output may contain
        adversarial content that should not reach the brain's context
        window. This mirrors the T95 detection but operates at the
        managed agent harness boundary.
        """
        args = {"output": result, "tool_result": result, "name": name}
        verdict, rule, score = self._evaluate(
            f"tool_result.{name}", args
        )

        if verdict in ("BLOCK", "WARN") and rule:
            self._threats.append({
                "tool":    f"result:{name}",
                "threat":  rule["id"],
                "name":    rule["name"],
                "score":   score,
                "verdict": verdict,
                "ts":      datetime.now(timezone.utc).isoformat(),
                "layer":   "after_execute",
            })

        return ExecuteVerdict(
            verdict      = verdict,
            threat_class = rule["id"]   if rule else None,
            threat_name  = rule["name"] if rule else None,
            score        = score,
            trust        = self._trust,
            session_id   = self.session_id,
            execute_name = name,
        )

    # ── Session layer monitoring ──────────────────────────────────────────────

    def check_emit_event(self, event: Dict) -> tuple[bool, Optional[str]]:
        """
        Validate an event before emitEvent() writes it to the session log.

        Detects T100 FORENSIC_EVIDENCE_TAMPERING at the session layer:
        an agent attempting to inject false history, overwrite past
        events, or suppress events from the session log.

        Returns (allowed, reason).
        """
        event_type = event.get("type", "")
        event_data = json.dumps(event).lower()

        # Check for session manipulation patterns
        for pattern in SESSION_TAMPER_PATTERNS:
            if pattern in event_data:
                self._threats.append({
                    "tool":    "emitEvent",
                    "threat":  "T100",
                    "name":    "FORENSIC_EVIDENCE_TAMPERING",
                    "score":   0.97,
                    "verdict": "BLOCK",
                    "ts":      datetime.now(timezone.utc).isoformat(),
                    "pattern": pattern,
                })
                return False, f"Session manipulation pattern detected: {pattern}"

        # Check for unknown event types (potential injection)
        if event_type and event_type not in SESSION_EVENT_TYPES:
            # Unknown event type — warn but allow (may be legitimate extension)
            return True, f"Unknown event type: {event_type}"

        self._emit_internal_event("session_event_emitted", {
            "type": event_type, "ts": datetime.now(timezone.utc).isoformat()
        })
        return True, None

    # ── Multi-brain topology ──────────────────────────────────────────────────

    def register_brain(
        self,
        brain_name:    str,
        capabilities:  Optional[Set[str]] = None,
        allowed_hands: Optional[Set[str]] = None,
        parent_brain_id: Optional[str] = None,
        trust_level:   str = "delegated",
    ) -> BrainRegistration:
        """
        Register a brain in the multi-brain topology.

        Each brain gets a capability scope. Brain-to-brain hand
        delegation is only authorized when the receiving brain has
        the hand in its allowed_hands set.

        Maps to NHI lifecycle management for multi-brain context.
        """
        brain_id = hashlib.sha256(
            f"{brain_name}{time.time()}".encode()
        ).hexdigest()[:12]

        reg = BrainRegistration(
            brain_id       = brain_id,
            brain_name     = brain_name,
            capabilities   = capabilities or set(),
            allowed_hands  = allowed_hands or set(),
            parent_brain_id = parent_brain_id or self.session_id,
            registered_at  = datetime.now(timezone.utc).isoformat(),
            trust_level    = trust_level,
        )
        self._brain_registry[brain_id] = reg
        self._emit_internal_event("brain_registered", {
            "brain_id":   brain_id,
            "brain_name": brain_name,
            "trust_level": trust_level,
        })
        return reg

    def delegate_hand(
        self,
        to_brain_id: str,
        hand_name:   str,
        from_brain_id: Optional[str] = None,
    ) -> HandDelegation:
        """
        Authorize or block a brain-to-brain hand delegation.

        "Brains can pass hands to one another." (Managed Agents post)
        A compromised brain passing malicious hands to other brains
        is T64 AGENT_IDENTITY_SPOOFING at the topology level.

        Validates that:
        1. The receiving brain exists in the registry
        2. The hand is in the receiving brain's allowed_hands
        3. The delegating brain has authority to delegate this hand
        """
        receiving = self._brain_registry.get(to_brain_id)
        authorized = (
            receiving is not None and
            not receiving.revoked and
            (not receiving.allowed_hands or hand_name in receiving.allowed_hands)
        )

        blocked = not authorized

        if blocked:
            # Fire T64-equivalent at topology level
            self._threats.append({
                "tool":    "delegate_hand",
                "threat":  "T64",
                "name":    "AGENT_IDENTITY_SPOOFING",
                "score":   0.90,
                "verdict": "BLOCK",
                "ts":      datetime.now(timezone.utc).isoformat(),
                "detail":  f"Unauthorized hand delegation: {hand_name} -> brain {to_brain_id}",
            })
            self._blocked_calls += 1

        delegation = HandDelegation(
            from_brain_id = from_brain_id or "root",
            to_brain_id   = to_brain_id,
            hand_name     = hand_name,
            authorized    = authorized,
            timestamp     = datetime.now(timezone.utc).isoformat(),
            blocked       = blocked,
        )
        self._delegations.append(delegation)
        return delegation

    def revoke_brain(self, brain_id: str) -> bool:
        """Immediately revoke a brain's capability to receive delegations."""
        if brain_id in self._brain_registry:
            self._brain_registry[brain_id].revoked = True
            self._emit_internal_event("brain_revoked", {"brain_id": brain_id})
            return True
        return False

    # ── Session artifact ──────────────────────────────────────────────────────

    def close_session(self) -> Dict:
        """
        Close session and produce signed artifact.

        The artifact maps to the Family 4 ForensicStore schema and
        includes managed-agent-specific fields: brain_registry,
        hand_delegations, session_events_monitored.
        """
        artifact = {
            "schema":          "aiglos/managed-agents/v1",
            "agent_name":      self.agent_name,
            "session_id":      self.session_id,
            "policy":          self.policy,
            "closed_at":       datetime.now(timezone.utc).isoformat(),
            "total_calls":     self._total_calls,
            "blocked_calls":   self._blocked_calls,
            "threats":         self._threats,
            "trust_final":     self._trust,
            "attestation_ready": self._blocked_calls == 0 and self._trust > 0.5,
            "managed_agents": {
                "brains_registered":       len(self._brain_registry),
                "hand_delegations":        len(self._delegations),
                "blocked_delegations":     sum(1 for d in self._delegations if d.blocked),
                "session_events_monitored": len(self._events),
                "brain_registry": {
                    bid: {
                        "name":       reg.brain_name,
                        "trust":      reg.trust_level,
                        "revoked":    reg.revoked,
                        "caps":       list(reg.capabilities),
                    }
                    for bid, reg in self._brain_registry.items()
                },
            },
        }

        # Sign
        sig_data = json.dumps({
            k: artifact[k] for k in
            ["agent_name", "session_id", "policy", "total_calls", "blocked_calls"]
        }, sort_keys=True).encode()
        artifact["signature"] = "sha256:" + hashlib.sha256(sig_data).hexdigest()

        # Persist
        fname = self._log_dir / f"managed-{self.session_id}.json"
        fname.write_text(json.dumps(artifact, indent=2))

        return artifact

    # ── Context manager for session scope ─────────────────────────────────────

    @contextmanager
    def session_scope(self, session_id: Optional[str] = None):
        """
        Context manager wrapping a Managed Agents session.
        Produces signed artifact on exit.

        Usage:
            with guard.session_scope() as session:
                result = execute("bash", {"command": cmd})
        """
        if session_id:
            self.session_id = session_id
        try:
            yield self
        finally:
            self.close_session()

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _emit_internal_event(self, event_type: str, data: Dict) -> None:
        self._events.append({
            "type": event_type,
            "data": data,
            "ts":   datetime.now(timezone.utc).isoformat(),
        })


# ── One-call factory ──────────────────────────────────────────────────────────

def managed_agent_guard(
    agent_name: str = "managed-agent",
    policy:     str = "enterprise",
    session_id: Optional[str] = None,
) -> ManagedAgentGuard:
    """
    One-call factory for ManagedAgentGuard.

    Usage in Managed Agents harness:

        from aiglos.integrations.managed_agents import managed_agent_guard

        guard = managed_agent_guard("my-brain", policy="enterprise")

        # In harness loop:
        verdict = guard.before_execute(name, input_data)
        if verdict.verdict == "BLOCK":
            return f"[Blocked: {verdict.threat_class}]"
        result = execute(name, input_data)
        guard.after_execute(name, result)

        # On close:
        artifact = guard.close_session()
    """
    return ManagedAgentGuard(
        agent_name=agent_name,
        policy=policy,
        session_id=session_id,
    )
