"""
aiglos/integrations/nemoclaw.py
=================================
NemoClaw session management -- the underlying policy enforcement layer
for NVIDIA's sandbox technology.

NemoClaw was the launch vehicle. OpenShell is the product name.
New integrations should use aiglos/integrations/openShell.py instead.

This module provides the session primitives that openShell.py builds on:
  - NeMoClawSession: policy-bound session with scope enforcement
  - mark_as_nemoclaw_session(): attach a YAML policy to a guard
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger("aiglos.nemoclaw")


def _load_yaml_policy(policy_path: str) -> dict:
    """Load a YAML policy file using stdlib only (no PyYAML dependency)."""
    path = Path(os.path.expanduser(policy_path))
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {path}")

    text = path.read_text(encoding="utf-8")
    policy: Dict[str, Any] = {}
    current_section: Optional[str] = None
    current_key: Optional[str] = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())

        if indent == 0 and ":" in stripped:
            key = stripped.split(":")[0].strip()
            val = stripped.split(":", 1)[1].strip()
            if val:
                policy[key] = _parse_yaml_value(val)
            else:
                policy[key] = {}
                current_section = key
            current_key = None
            continue

        if current_section is not None:
            if stripped.startswith("- "):
                item = stripped[2:].strip().strip('"').strip("'")
                if current_key and isinstance(policy[current_section].get(current_key), list):
                    policy[current_section][current_key].append(item)
                continue

            if ":" in stripped:
                key = stripped.split(":")[0].strip()
                val = stripped.split(":", 1)[1].strip()
                if val:
                    policy[current_section][key] = _parse_yaml_value(val)
                else:
                    policy[current_section][key] = []
                    current_key = key

    return policy


def _parse_yaml_value(val: str) -> Any:
    """Parse a simple YAML scalar value."""
    if val.lower() == "true":
        return True
    if val.lower() == "false":
        return False
    if val.startswith('"') and val.endswith('"'):
        return val[1:-1]
    if val.startswith("'") and val.endswith("'"):
        return val[1:-1]
    try:
        return int(val)
    except ValueError:
        pass
    try:
        return float(val)
    except ValueError:
        pass
    return val


@dataclass
class NeMoClawSession:
    """A policy-bound session for sandbox enforcement."""

    session_id: str
    policy_hash: str
    policy_data: Dict[str, Any]
    guard: Any = None
    created_at: float = field(default_factory=time.time)
    events: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def allowed_hosts(self) -> List[str]:
        network = self.policy_data.get("network", {})
        return network.get("allow", [])

    @property
    def denied_hosts(self) -> List[str]:
        network = self.policy_data.get("network", {})
        return network.get("deny", [])

    @property
    def workspace(self) -> Optional[str]:
        fs = self.policy_data.get("filesystem", {})
        return fs.get("workspace")

    @property
    def allowed_tools(self) -> List[str]:
        tools = self.policy_data.get("tools", {})
        return tools.get("allowed", [])

    @property
    def denied_tools(self) -> List[str]:
        tools = self.policy_data.get("tools", {})
        return tools.get("denied", [])

    def check_host_scope(self, host: str) -> bool:
        for denied in self.denied_hosts:
            if denied == "*" or denied == host:
                if host not in self.allowed_hosts:
                    return False
        return True

    def check_file_scope(self, path: str) -> bool:
        ws = self.workspace
        if ws and not path.startswith(ws):
            return False
        return True

    def record_event(self, event_type: str, details: dict) -> None:
        self.events.append({
            "type": event_type,
            "details": details,
            "at": time.time(),
        })

    def artifact_data(self) -> dict:
        return {
            "session_id": self.session_id,
            "policy_hash": self.policy_hash,
            "events": len(self.events),
            "created_at": self.created_at,
        }


def mark_as_nemoclaw_session(
    policy_path: str,
    session_id: Optional[str] = None,
    guard: Any = None,
) -> NeMoClawSession:
    """
    Load a YAML policy and create a NeMoClawSession bound to the guard.

    policy_path:  Path to the YAML policy file
    session_id:   Optional session ID (auto-generated if None)
    guard:        Any Aiglos guard (OpenClawGuard or compatible)

    Returns a NeMoClawSession with the parsed policy.
    """
    policy_data = _load_yaml_policy(policy_path)
    policy_text = Path(os.path.expanduser(policy_path)).read_text(encoding="utf-8")
    policy_hash = hashlib.sha256(policy_text.encode()).hexdigest()[:16]

    sid = session_id or f"nmc-{hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]}"

    session = NeMoClawSession(
        session_id=sid,
        policy_hash=policy_hash,
        policy_data=policy_data,
        guard=guard,
    )

    if guard is not None:
        guard.sandbox_context = True
        guard.sandbox_type = "openShell"
        guard._nemoclaw_session = session

        if hasattr(guard, "attach_nemoclaw"):
            guard.attach_nemoclaw(session)

    log.info(
        "[NemoClaw] Session created -- id=%s policy_hash=%s",
        sid, policy_hash,
    )

    return session
