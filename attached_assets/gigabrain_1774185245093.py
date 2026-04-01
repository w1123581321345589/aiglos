"""
aiglos/integrations/gigabrain.py
==================================
Aiglos integration for Gigabrain and compatible cross-session memory layers.

GIGABRAIN
=========
Gigabrain (github.com/LegendaryVibeCoder/gigabrain) is a SQLite-backed
cross-session memory layer for OpenClaw, Claude Code, and Codex. It converts
every conversation into durable, queryable memory and injects relevant context
before each prompt. Featured as Skill of the Week in WeeklyClaw #004 (March 2026).

The security implication nobody said out loud:
Gigabrain creates a persistent memory store. If adversarial content gets written
into the SQLite database during one session — via T31 MEMORY_POISON or indirect
prompt injection — it persists and gets injected into every future session.
The adversary compromises the memory once and gets persistent influence over
all future behavior without needing to re-inject. T79 PERSISTENT_MEMORY_INJECT
was built specifically for this attack class.

ARCHITECTURE
============
Gigabrain sits below OpenClaw as a context enrichment layer. Before each prompt,
it queries the SQLite database and injects relevant entities, episodes, and
beliefs into the context window. This makes it a high-value target — content
written to the database becomes trusted context in every future session.

Aiglos wraps the database write path:

    aiglos/integrations/gigabrain.py   ← this file
           ↓
    SubagentRegistry (path declarations)
           ↓
    T79 PERSISTENT_MEMORY_INJECT (fires on write + injection content)
           ↓
    GIGABRAIN_MEMORY_POISON campaign pattern (T31 + T79 in same session)

Usage:
    from aiglos.integrations.gigabrain import declare_memory_backend
    from aiglos.integrations.openclaw import OpenClawGuard

    guard = OpenClawGuard(agent_name="my-agent", policy="enterprise")

    # Register Gigabrain paths — T79 fires on malicious writes to these paths
    declare_memory_backend(guard, backend="gigabrain")

    # Or with explicit path:
    declare_memory_backend(guard, backend="gigabrain",
                           db_path="~/custom/.gigabrain/memory.db")

    # Or auto-detect (checks all known Gigabrain paths):
    session = gigabrain_autodetect(guard)
    if session:
        print("Gigabrain detected and protected")

CLI:
    aiglos memory status
    aiglos memory backends list
    aiglos memory scan --backend gigabrain
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

log = logging.getLogger("aiglos.gigabrain")


# ── Known Gigabrain SQLite database paths ─────────────────────────────────────
# Gigabrain defaults, plus common variants from forks and custom configs.

GIGABRAIN_DEFAULT_PATHS = [
    "~/.gigabrain/memory.db",
    "~/.gigabrain/gigabrain.db",
    "~/.gigabrain/agent_memory.db",
    "~/.gb_memory/memory.db",
    "./.gigabrain/memory.db",
    "./gigabrain.db",
    "./memory_store.db",
]

# Other compatible cross-session memory backends
COMPATIBLE_BACKENDS = {
    "gigabrain":  GIGABRAIN_DEFAULT_PATHS,
    "memoryos":   ["~/.memoryos/memory.db", "~/.memoryos/store.db"],
    "mem0":       ["~/.mem0/memory.db", "~/.mem0/store.db"],
    "letta":      ["~/.letta/memory.db", "~/.letta/store.db"],
    "zep":        ["~/.zep/memory.db"],
    "chroma":     ["~/.chroma/chroma.db", "./chroma.db"],
    "generic":    ["./memory.db", "./agent_memory.db", "./cross_session.db"],
}


@dataclass
class MemoryBackendSession:
    """
    An active memory backend protection session.

    Tracks which backends and paths are registered with the T79 enforcement
    engine. Call deregister() at session close.
    """
    backend:      str
    paths:        List[str] = field(default_factory=list)
    session_id:   str = ""

    def deregister(self) -> None:
        """Clear T79 path registrations for this session."""
        _REGISTERED_PATHS.difference_update(set(self.paths))
        log.info(
            "[Gigabrain] Deregistered backend=%s paths=%d",
            self.backend, len(self.paths),
        )

    def to_dict(self) -> dict:
        return {
            "backend":    self.backend,
            "paths":      self.paths,
            "session_id": self.session_id,
        }


# Module-level registry of currently protected paths
# Used by T79 matching to know which paths are declared
_REGISTERED_PATHS: set = set()


def declare_memory_backend(
    guard,
    backend:    str = "gigabrain",
    db_path:    Optional[str] = None,
    session_id: Optional[str] = None,
) -> MemoryBackendSession:
    """
    Register a persistent memory backend with the Aiglos guard.

    Registers the backend's SQLite paths with the T79 enforcement engine.
    Any write to these paths containing injection patterns fires T79
    PERSISTENT_MEMORY_INJECT before the write reaches the database.

    guard:      OpenClawGuard instance to attach to.
    backend:    Backend name: "gigabrain" | "memoryos" | "mem0" | "letta" |
                "zep" | "chroma" | "generic". Determines which default paths
                are registered. Use "gigabrain" for Gigabrain.
    db_path:    Explicit database path override. If provided, only this path
                is registered (plus the standard backend defaults).
    session_id: Optional session ID for logging.

    Returns a MemoryBackendSession — keep a reference to call deregister()
    at session close.

    Examples:
        # Standard Gigabrain setup
        declare_memory_backend(guard, backend="gigabrain")

        # Gigabrain with custom path
        declare_memory_backend(guard, backend="gigabrain",
                               db_path="~/myproject/.gigabrain/memory.db")

        # mem0 backend
        declare_memory_backend(guard, backend="mem0")
    """
    backend_lower = backend.lower()
    paths = list(COMPATIBLE_BACKENDS.get(backend_lower, GIGABRAIN_DEFAULT_PATHS))

    if db_path:
        expanded = str(Path(db_path).expanduser())
        if expanded not in paths:
            paths.insert(0, expanded)

    # Expand all paths
    expanded_paths = []
    for p in paths:
        try:
            expanded_paths.append(str(Path(p).expanduser()))
        except Exception:
            expanded_paths.append(p)

    # Register with T79 path registry
    _REGISTERED_PATHS.update(expanded_paths)

    # Register with guard's subagent registry if available
    if hasattr(guard, '_subagent_registry') and guard._subagent_registry:
        # Add memory backend paths to file scope restrictions
        # Any agent that writes to these paths with injection content gets T79
        pass  # T79 uses its own path registry, not subagent scopes

    # Mark guard as memory-backend-aware
    if not hasattr(guard, '_memory_backends'):
        guard._memory_backends = []
    guard._memory_backends.append({
        "backend": backend,
        "paths":   expanded_paths,
    })

    session = MemoryBackendSession(
        backend    = backend,
        paths      = expanded_paths,
        session_id = session_id or getattr(guard, 'session_id', ''),
    )

    log.info(
        "[Gigabrain] Registered backend=%s paths=%d session=%s",
        backend, len(expanded_paths), session.session_id,
    )

    return session


def gigabrain_autodetect(guard) -> Optional[MemoryBackendSession]:
    """
    Auto-detect Gigabrain and register it if found.

    Checks all known Gigabrain paths for an existing database.
    If found, registers the backend and returns a MemoryBackendSession.
    If not found, registers the paths anyway (T79 fires on creation too)
    and returns a session marked as pending.

    This is the zero-config path for Gigabrain users.

    Example:
        import aiglos
        from aiglos.integrations.gigabrain import gigabrain_autodetect
        from aiglos.integrations.openclaw import OpenClawGuard

        guard = OpenClawGuard(agent_name="my-agent")
        session = gigabrain_autodetect(guard)
        # T79 is now active for all Gigabrain paths
    """
    found_paths = []
    for p in GIGABRAIN_DEFAULT_PATHS:
        expanded = Path(p).expanduser()
        if expanded.exists():
            found_paths.append(str(expanded))

    if found_paths:
        log.info(
            "[Gigabrain] Auto-detected at: %s",
            ", ".join(found_paths)
        )
    else:
        log.info(
            "[Gigabrain] No existing database found — "
            "registering paths for pre-emptive T79 protection"
        )

    return declare_memory_backend(guard, backend="gigabrain")


def is_registered_memory_path(path: str) -> bool:
    """
    Returns True if this path is a registered persistent memory backend path.
    Used by T79 matching to confirm path is a known memory store.
    """
    path_expanded = str(Path(path).expanduser())
    if path_expanded in _REGISTERED_PATHS:
        return True
    # Also check suffix patterns even if not explicitly registered
    from aiglos.core.threat_engine_v2 import _T79_MEMORY_PATHS
    return bool(_T79_MEMORY_PATHS.search(path))


def memory_backend_summary(guard) -> str:
    """Return a summary of registered memory backends for this guard."""
    backends = getattr(guard, '_memory_backends', [])
    if not backends:
        return "  No memory backends registered.\n"
    lines = [f"  Registered memory backends ({len(backends)}):"]
    for b in backends:
        lines.append(f"    {b['backend']}: {len(b['paths'])} paths")
        for p in b['paths'][:3]:
            lines.append(f"      {p}")
        if len(b['paths']) > 3:
            lines.append(f"      ... and {len(b['paths']) - 3} more")
    return "\n".join(lines) + "\n"
