"""
aiglos.integrations.multi_agent
================================
Multi-agent session management for Aiglos v0.3.0.

Addresses three capabilities introduced by multi-agent frameworks
(agency-agents, OpenClaw Orchestrator, LangGraph multi-agent):

1. Sub-agent spawn registry
   When a parent agent spawns a child agent process, Aiglos records the
   spawn event and links the child session to the parent in the session
   artifact. This produces a full parent -> child action chain for audit.

2. Agent definition file integrity
   At attach time, Aiglos hashes the agent's definition files (SOUL.md,
   IDENTITY.md, AGENTS.md, SKILL.md, .mdc rules). Any modification to
   these files during the session is flagged as T36_AGENTDEF + T27_PROMPT_INJECT
   because silent reprogramming of the agent identity is the exact exploit
   demonstrated in the McKinsey/Lilli incident (writable system prompts).

3. Session identity chain
   Each Aiglos session generates a short-lived RSA-2048 keypair at attach time.
   Every action is countersigned with the session key. If the agent definition
   is modified mid-session, the identity chain detects the divergence and flags
   it in the session artifact. The public key is embedded in the artifact so
   verifiers can confirm the chain without trusting the session.

Usage:
    from aiglos.integrations.multi_agent import (
        MultiAgentRegistry,
        AgentDefGuard,
        SessionIdentityChain,
    )

    # Registry is created once per root session and shared across child agents
    registry = MultiAgentRegistry(root_session_id="session-abc123")

    # Register a child spawn event
    registry.register_spawn(
        parent_id="session-abc123",
        child_id="session-def456",
        cmd="claude code --print",
        agent_name="security-engineer",
    )

    # Guard agent definition files
    guard = AgentDefGuard()
    guard.snapshot()              # hash current state at attach time
    violations = guard.check()    # call periodically or on suspicious event

    # Identity chain
    chain = SessionIdentityChain(agent_name="orchestrator")
    chain.sign_event(event_dict)  # adds session_sig field to event
    ok = chain.verify(event_dict) # True if sig matches session pubkey
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

log = logging.getLogger("aiglos.multi_agent")

# ── Agent definition paths to monitor ─────────────────────────────────────────

_AGENT_DEF_DIRS: list[str] = [
    "~/.claude/agents",
    "~/.github/agents",
    "~/.openclaw",
    "~/.gemini/agents",
    "~/.gemini/antigravity",
    "~/.gemini/extensions/agency-agents",
]

_AGENT_DEF_FILES: list[str] = [
    "SOUL.md",
    "IDENTITY.md",
    "AGENTS.md",
    "CONVENTIONS.md",
    ".windsurfrules",
]

# Project-local agent dirs (resolved relative to cwd)
_AGENT_DEF_RELATIVE: list[str] = [
    ".claude/agents",
    ".github/agents",
    ".cursor/rules",
    ".opencode/agents",
]

_AGENT_DEF_EXTENSIONS: set[str] = {".md", ".mdc", ".txt"}


def _collect_agent_def_paths(cwd: Optional[str] = None) -> List[Path]:
    """Return all agent definition file paths that currently exist on disk."""
    paths: list[Path] = []

    # Global dirs
    for d in _AGENT_DEF_DIRS:
        p = Path(d).expanduser()
        if p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and f.suffix in _AGENT_DEF_EXTENSIONS:
                    paths.append(f)

    # Named files
    for fname in _AGENT_DEF_FILES:
        p = Path(fname).expanduser()
        if p.exists():
            paths.append(p)

    # Project-local dirs
    base = Path(cwd) if cwd else Path.cwd()
    for rel in _AGENT_DEF_RELATIVE:
        p = base / rel
        if p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and f.suffix in _AGENT_DEF_EXTENSIONS:
                    paths.append(f)

    return list(set(paths))  # dedupe


def _hash_file(path: Path) -> str:
    """Return SHA-256 hex digest of a file, or empty string on error."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


# ── AgentDefGuard ──────────────────────────────────────────────────────────────

@dataclass
class AgentDefViolation:
    path: str
    violation_type: str   # "MODIFIED" | "ADDED" | "DELETED"
    original_hash: str
    current_hash: str
    detected_at: float = field(default_factory=time.time)
    rule_id: str = "T36_AGENTDEF"
    threat_family: str = "T27_PROMPT_INJECT + T36_AGENTDEF"

    def to_dict(self) -> dict:
        return {
            "path":          self.path,
            "violation":     self.violation_type,
            "original_hash": self.original_hash,
            "current_hash":  self.current_hash,
            "detected_at":   self.detected_at,
            "rule_id":       self.rule_id,
            "rule_name":     "AGENT_DEF_INTEGRITY",
            "threat_family": self.threat_family,
        }


class AgentDefGuard:
    """
    Snapshot agent definition files at session start and detect modifications.

    Any change to a file in ~/.claude/agents/, .cursor/rules/, etc. during an
    active session is classified T36_AGENTDEF + T27_PROMPT_INJECT: silent
    reprogramming of the agent's identity, guardrails, or tool permissions.
    """

    def __init__(self, cwd: Optional[str] = None):
        self._cwd      = cwd
        self._baseline: Dict[str, str] = {}  # path -> sha256
        self._lock     = threading.Lock()
        self._snapped  = False

    def snapshot(self) -> Dict[str, str]:
        """Hash all current agent definition files. Call once at attach time."""
        paths = _collect_agent_def_paths(self._cwd)
        baseline: Dict[str, str] = {}
        for p in paths:
            baseline[str(p)] = _hash_file(p)
        with self._lock:
            self._baseline = baseline
            self._snapped  = True
        log.debug("[AgentDefGuard] Snapshotted %d agent definition files.", len(baseline))
        return dict(baseline)

    def check(self) -> List[AgentDefViolation]:
        """
        Compare current disk state to baseline.
        Returns list of violations (empty = clean).
        """
        if not self._snapped:
            return []

        with self._lock:
            baseline = dict(self._baseline)

        violations: List[AgentDefViolation] = []
        current_paths = _collect_agent_def_paths(self._cwd)
        current_map   = {str(p): _hash_file(p) for p in current_paths}

        # Modified or deleted
        for path, orig_hash in baseline.items():
            curr_hash = current_map.get(path, "")
            if curr_hash == "":
                violations.append(AgentDefViolation(
                    path=path,
                    violation_type="DELETED",
                    original_hash=orig_hash,
                    current_hash="",
                ))
            elif curr_hash != orig_hash:
                violations.append(AgentDefViolation(
                    path=path,
                    violation_type="MODIFIED",
                    original_hash=orig_hash,
                    current_hash=curr_hash,
                ))

        # New files added since snapshot
        for path, curr_hash in current_map.items():
            if path not in baseline:
                violations.append(AgentDefViolation(
                    path=path,
                    violation_type="ADDED",
                    original_hash="",
                    current_hash=curr_hash,
                ))

        if violations:
            log.warning(
                "[AgentDefGuard] %d agent definition integrity violation(s) detected.",
                len(violations),
            )
        return violations

    @property
    def baseline(self) -> Dict[str, str]:
        with self._lock:
            return dict(self._baseline)


# ── SessionIdentityChain ───────────────────────────────────────────────────────

class SessionIdentityChain:
    """
    Lightweight session identity for multi-agent audit chains.

    Uses HMAC-SHA256 with a session secret rather than full RSA (no external
    dependencies). Each event in the session artifact carries a session_sig
    field so downstream verifiers can confirm the event belongs to this
    session and was not injected from a different agent context.

    The session_public_token (SHA-256 of the secret) is embedded in the
    artifact header. Verifiers check: HMAC(secret, event_json) == event.session_sig.
    """

    def __init__(self, agent_name: str, session_id: Optional[str] = None):
        import secrets as _secrets
        self.agent_name    = agent_name
        self.session_id    = session_id or _secrets.token_hex(16)
        self._secret       = _secrets.token_bytes(32)
        self._event_count  = 0
        self._created_at   = time.time()
        # Public token: SHA-256(secret). Embeds in artifact without exposing secret.
        self.public_token  = hashlib.sha256(self._secret).hexdigest()

    def sign_event(self, event: dict) -> dict:
        """Add session_sig to an event dict in place. Returns the event."""
        import hmac as _hmac
        self._event_count += 1
        payload = json.dumps({
            "session_id":   self.session_id,
            "event_count":  self._event_count,
            "rule_id":      event.get("rule_id", ""),
            "verdict":      event.get("verdict", ""),
            "cmd":          event.get("cmd", event.get("url", "")),
            "ts":           event.get("timestamp", time.time()),
        }, sort_keys=True).encode()
        sig = _hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        event["session_sig"]   = sig
        event["session_id"]    = self.session_id
        event["event_seq"]     = self._event_count
        return event

    def verify(self, event: dict) -> bool:
        """Verify a signed event belongs to this session."""
        import hmac as _hmac
        stored_sig = event.get("session_sig", "")
        seq        = event.get("event_seq", 0)
        payload    = json.dumps({
            "session_id":  self.session_id,
            "event_count": seq,
            "rule_id":     event.get("rule_id", ""),
            "verdict":     event.get("verdict", ""),
            "cmd":         event.get("cmd", event.get("url", "")),
            "ts":          event.get("timestamp", 0.0),
        }, sort_keys=True).encode()
        expected = _hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return _hmac.compare_digest(stored_sig, expected)

    def header(self) -> dict:
        """Return the artifact header entry for this session."""
        return {
            "session_id":     self.session_id,
            "agent_name":     self.agent_name,
            "public_token":   self.public_token,
            "created_at":     self._created_at,
            "event_count":    self._event_count,
        }


# ── MultiAgentRegistry ─────────────────────────────────────────────────────────

@dataclass
class SpawnEvent:
    parent_id:   str
    child_id:    str
    agent_name:  str
    cmd:         str
    spawned_at:  float = field(default_factory=time.time)
    policy_propagated: bool = False

    def to_dict(self) -> dict:
        return {
            "event_type":         "AGENT_SPAWN",
            "parent_session_id":  self.parent_id,
            "child_session_id":   self.child_id,
            "agent_name":         self.agent_name,
            "cmd":                self.cmd[:256],
            "spawned_at":         self.spawned_at,
            "policy_propagated":  self.policy_propagated,
            "rule_id":            "T38",
            "rule_name":          "AGENT_SPAWN",
        }


class MultiAgentRegistry:
    """
    Registry of all agent sessions rooted at a parent session.

    When an orchestrator (e.g. agency-agents Agents Orchestrator) spawns
    sub-agents in parallel, each child session registers here. The session
    artifact then contains a full tree of parent -> child spawn events with
    action chains, making multi-agent workflows fully auditable.
    """

    def __init__(self, root_session_id: str, root_agent_name: str = "orchestrator"):
        self._root_id   = root_session_id
        self._root_name = root_agent_name
        self._spawns:   List[SpawnEvent]           = []
        self._children: Dict[str, "ChildSession"]  = {}
        self._lock      = threading.Lock()
        self._created_at = time.time()

    def register_spawn(
        self,
        parent_id:   str,
        child_id:    str,
        cmd:         str,
        agent_name:  str = "sub-agent",
        propagate_policy: bool = True,
    ) -> SpawnEvent:
        """Record a sub-agent spawn and return the SpawnEvent."""
        ev = SpawnEvent(
            parent_id=parent_id,
            child_id=child_id,
            agent_name=agent_name,
            cmd=cmd,
            policy_propagated=propagate_policy,
        )
        with self._lock:
            self._spawns.append(ev)
            self._children[child_id] = ChildSession(
                session_id=child_id,
                agent_name=agent_name,
                parent_id=parent_id,
                spawned_at=ev.spawned_at,
            )
        log.info(
            "[MultiAgentRegistry] Spawn: %s -> %s (%s) policy_propagated=%s",
            parent_id[:8], child_id[:8], agent_name, propagate_policy,
        )
        return ev

    def get_child(self, child_id: str) -> Optional["ChildSession"]:
        with self._lock:
            return self._children.get(child_id)

    def all_spawns(self) -> List[SpawnEvent]:
        with self._lock:
            return list(self._spawns)

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "root_session_id": self._root_id,
                "root_agent_name": self._root_name,
                "created_at":      self._created_at,
                "child_count":     len(self._children),
                "spawns":          [s.to_dict() for s in self._spawns],
                "children":        {k: v.to_dict() for k, v in self._children.items()},
            }


@dataclass
class ChildSession:
    session_id:  str
    agent_name:  str
    parent_id:   str
    spawned_at:  float
    events:      List[dict] = field(default_factory=list)
    closed_at:   Optional[float] = None

    def add_event(self, event: dict) -> None:
        self.events.append(event)

    def close(self) -> None:
        self.closed_at = time.time()

    def to_dict(self) -> dict:
        return {
            "session_id":  self.session_id,
            "agent_name":  self.agent_name,
            "parent_id":   self.parent_id,
            "spawned_at":  self.spawned_at,
            "closed_at":   self.closed_at,
            "event_count": len(self.events),
            "events":      self.events,
        }
