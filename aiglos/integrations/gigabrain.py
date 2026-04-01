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
import re
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
    "byterover":  ["~/byterover/", ".byterover/", "./byterover/",
                   "~/.byterover/", "byterover/context_tree/"],
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


BYTEROVER_DEFAULT_PATHS = [
    "~/byterover/",
    ".byterover/",
    "./byterover/",
    "~/.byterover/",
    "byterover/context_tree/",
]


def byterover_autodetect(guard) -> Optional["MemoryBackendSession"]:
    """
    Auto-detect ByteRover and register it with T79 protection.

    ByteRover is a file-based Context Tree memory plugin for OpenClaw
    (30,000+ downloads in first week). Unlike Gigabrain (SQLite), ByteRover
    writes structured markdown files to a Context Tree directory after every turn
    and runs a daily 9am cron to mine architectural decisions.

    T79 protects the Context Tree write path.
    T67 monitors the daily cron cadence — fires if the 9am job runs at 3am.

    Example:
        from aiglos.integrations.gigabrain import byterover_autodetect
        session = byterover_autodetect(guard)
    """
    found_paths = []
    for p in BYTEROVER_DEFAULT_PATHS:
        from pathlib import Path as _Path
        expanded = _Path(p.rstrip("/")).expanduser()
        if expanded.exists():
            found_paths.append(str(expanded))

    if found_paths:
        log.info("[ByteRover] Auto-detected at: %s", ", ".join(found_paths))
    else:
        log.info(
            "[ByteRover] No existing Context Tree found — "
            "registering paths for pre-emptive T79 protection"
        )

    session = declare_memory_backend(guard, backend="byterover")

    # Register expected daily cron with T67 monitoring
    # ByteRover daily knowledge mining runs at 9:00 AM
    if hasattr(guard, '_expected_crons'):
        guard._expected_crons.append({
            "name":     "byterover_daily_review",
            "schedule": "0 9 * * *",
            "expected_hour": 9,
        })
    else:
        guard._expected_crons = [{
            "name":     "byterover_daily_review",
            "schedule": "0 9 * * *",
            "expected_hour": 9,
        }]

    log.info(
        "[ByteRover] Registered — T79 active on Context Tree writes, "
        "T67 monitoring 9am daily cron"
    )
    return session


# DGM-Hyperagents pipeline path patterns (synced with T82)
DGM_PIPELINE_PATHS = [
    "./agents/",
    "./archive/",
    "./evolution/",
    "./checkpoints/",
    "./self_improve/",
    "./eval_results.json",
    "./performance_log.json",
    "./improvement_history.json",
    "./agent_archive.json",
    "./fitness_scores.json",
    "./reward_design.json",
    "./generation_log.json",
]


# ── Studio role → default tools + hard bans ──────────────────────────────────
# Maps common game studio / multi-agent studio roles to sensible tool scopes.
# Based on Claude Code Game Studios hierarchy (48 agents, github.com/Donchitos).
# Each role gets minimum necessary tool access — principle of least privilege.
# Override any role with explicit declare_subagent() calls after declare_studio_pipeline().

STUDIO_ROLE_TOOLS = {
    # Creative direction
    "art-director":       {"tools": ["filesystem.read"], "scope": ["assets/", "specs/"], "bans": ["deploy", "push_to_main"]},
    "creative-director":  {"tools": ["filesystem.read", "filesystem.write"], "scope": ["specs/", "docs/"], "bans": ["deploy", "push_to_main"]},
    "game-designer":      {"tools": ["filesystem.read", "filesystem.write"], "scope": ["design/", "docs/"], "bans": ["deploy"]},
    "narrative-designer": {"tools": ["filesystem.read", "filesystem.write"], "scope": ["story/", "scripts/"], "bans": ["deploy", "push_to_main"]},

    # Technical
    "lead-programmer":    {"tools": ["filesystem", "shell.execute", "git.push"], "scope": ["src/"], "bans": ["push_to_main_without_review", "fabricate_data"]},
    "engine-programmer":  {"tools": ["filesystem", "shell.execute"], "scope": ["src/engine/"], "bans": ["push_to_main", "deploy"]},
    "gameplay-programmer":{"tools": ["filesystem", "shell.execute"], "scope": ["src/gameplay/"], "bans": ["push_to_main", "deploy"]},
    "ai-programmer":      {"tools": ["filesystem", "shell.execute"], "scope": ["src/ai/"], "bans": ["push_to_main", "deploy"]},
    "tools-programmer":   {"tools": ["filesystem", "shell.execute"], "scope": ["tools/", "src/tools/"], "bans": ["push_to_main"]},

    # Art / assets
    "level-designer":     {"tools": ["filesystem.read", "filesystem.write"], "scope": ["levels/", "assets/levels/"], "bans": ["deploy", "push_to_main"]},
    "environment-artist": {"tools": ["filesystem.read", "filesystem.write"], "scope": ["assets/environment/"], "bans": ["deploy", "push_to_main"]},
    "character-artist":   {"tools": ["filesystem.read", "filesystem.write"], "scope": ["assets/characters/"], "bans": ["deploy"]},
    "ui-designer":        {"tools": ["filesystem.read", "filesystem.write"], "scope": ["assets/ui/", "src/ui/"], "bans": ["deploy", "push_to_main"]},
    "vfx-artist":         {"tools": ["filesystem.read", "filesystem.write"], "scope": ["assets/vfx/"], "bans": ["deploy"]},

    # Audio
    "sound-designer":     {"tools": ["filesystem.read", "filesystem.write"], "scope": ["assets/audio/", "src/audio/"], "bans": ["deploy", "push_to_main"]},
    "composer":           {"tools": ["filesystem.read", "filesystem.write"], "scope": ["assets/music/"], "bans": ["deploy"]},
    "audio-programmer":   {"tools": ["filesystem", "shell.execute"], "scope": ["src/audio/"], "bans": ["push_to_main", "deploy"]},

    # QA / production
    "qa-lead":            {"tools": ["filesystem.read", "shell.execute"], "scope": ["tests/", "src/"], "bans": ["push_to_main", "deploy", "modify_tests_without_approval"]},
    "qa-tester":          {"tools": ["filesystem.read", "shell.execute"], "scope": ["tests/"], "bans": ["push_to_main", "deploy", "filesystem.write"]},
    "producer":           {"tools": ["filesystem.read", "filesystem.write"], "scope": ["docs/", "specs/", "roadmap/"], "bans": ["deploy", "push_to_main"]},
    "project-manager":    {"tools": ["filesystem.read", "filesystem.write"], "scope": ["docs/", "roadmap/"], "bans": ["deploy", "push_to_main"]},

    # Research / writing
    "researcher":         {"tools": ["web_search", "filesystem.read"], "scope": ["research/"], "bans": ["deploy", "push_to_main", "filesystem.write"]},
    "writer":             {"tools": ["filesystem.read", "filesystem.write"], "scope": ["story/", "scripts/", "docs/"], "bans": ["deploy", "push_to_main"]},
    "localization":       {"tools": ["filesystem.read", "filesystem.write"], "scope": ["localization/"], "bans": ["deploy", "push_to_main"]},

    # Default fallback for unlisted roles
    "_default":           {"tools": ["filesystem.read"], "scope": [], "bans": ["deploy", "push_to_main", "fabricate_data"]},
}


def declare_studio_pipeline(
    guard,
    roles:         list   = None,
    studio_name:   str    = "game-studio",
    allow_deploys: list   = None,
    coordinator_role: str = None,
) -> list:
    """
    Register a multi-agent studio pipeline with the Aiglos guard.

    Replaces 48 individual declare_subagent() calls with one call.
    Based on Claude Code Game Studios hierarchy (github.com/Donchitos/Claude-Code-Game-Studios).

    roles:         List of role names to register. Defaults to all STUDIO_ROLE_TOOLS.
                   Use shortened names: "art-director", "qa-lead", "sound-designer".
    studio_name:   Studio identifier prefix for agent names.
    allow_deploys: List of roles permitted to deploy (overrides default hard ban).
    coordinator_role: Role that acts as coordinator — gets slightly elevated trust
                   but T36 still fires if it tries to modify other agents' configs.

    Returns list of declared role names.

    T38 AGENT_SPAWN behavior after calling this:
      - Declared role + in-scope tool: score 0.0 (suppressed)
      - Declared role + out-of-scope: score 0.90 (elevated)
      - Undeclared spawn: score 0.78 (normal)

    T78 HALLUCINATION_CASCADE note: 48-agent pipelines are high-risk for
    cross-agent confidence amplification. The Art Director describes a vague
    style → Level Designer adds confidence → Asset Creator treats as authoritative.
    Aiglos T78 fires on this pattern across the session.

    Example:
        from aiglos.integrations.gigabrain import declare_studio_pipeline

        # Register full studio (48 roles from STUDIO_ROLE_TOOLS)
        declared = declare_studio_pipeline(guard, studio_name="my-studio")

        # Register specific roles only
        declared = declare_studio_pipeline(guard,
            roles=["art-director", "level-designer", "qa-lead", "sound-designer"],
            studio_name="indie-studio",
        )

        # With deployment gating
        declared = declare_studio_pipeline(guard,
            roles=["lead-programmer", "qa-lead", "producer"],
            allow_deploys=["lead-programmer"],  # only lead-programmer can deploy
        )
    """
    if roles is None:
        roles = [r for r in STUDIO_ROLE_TOOLS if not r.startswith("_")]

    allow_deploys = allow_deploys or []
    declared = []

    for role in roles:
        role_def = STUDIO_ROLE_TOOLS.get(role.lower(), STUDIO_ROLE_TOOLS["_default"])
        tools = list(role_def["tools"])
        scope = list(role_def["scope"])
        bans = list(role_def["bans"]) + ["fabricate_data", "unverified_claims"]

        # Remove deploy ban for allowed deployers
        if role in allow_deploys and "deploy" in bans:
            bans.remove("deploy")

        # Coordinator gets slightly more filesystem scope
        if role == coordinator_role:
            if "filesystem.read" in tools and "filesystem.write" not in tools:
                tools.append("filesystem.write")
            bans.append("modify_other_agent_configs")

        agent_name = f"{studio_name}/{role}"

        guard.declare_subagent(
            agent_name,
            tools       = tools,
            scope_files = scope if scope else None,
            hard_bans   = bans,
        )
        declared.append(agent_name)

    log.info(
        "[StudioPipeline] Registered %d roles for studio=%s T38 enforcement active",
        len(declared), studio_name,
    )

    return declared


# ── AI Scientist path patterns (Sakana AI, Nature 2026) ──────────────────────
# The AI Scientist architecture (arxiv.org/abs/2408.06292, published Nature 2026):
#   - Idea generation log:   ideas/
#   - Experiment results:    experiment_results/, results/
#   - Generated papers:      logs/generated_papers_*/
#   - Automated Reviewer:    review_results/, reviewer_outputs/
#   - Scaling artifacts:     scaling_results/, model_outputs/
#
# The Automated Reviewer is the critical path: its evaluation criteria feed back
# into the pipeline. If the reviewer's scoring is poisoned, every subsequent
# paper scores highly regardless of quality/accuracy — and better foundation
# models make the misinformation more convincing (the scaling law of poisoned science).
# T82 fires on adversarial writes to reviewer_results/ and review_criteria/.

AI_SCIENTIST_PATHS = [
    "./ideas/",
    "./experiment_results/",
    "./results/",
    "./logs/generated_papers_",
    "./review_results/",
    "./reviewer_outputs/",
    "./review_criteria/",
    "./scaling_results/",
    "./model_outputs/",
    "./aider.benchmark.jsonl",
    "./run_*.py",
    "./final_info.json",
]


def declare_ai_scientist_pipeline(
    guard,
    idea_path:     str = None,
    paper_path:    str = None,
    reviewer_path: str = None,
    pipeline_name: str = "ai-scientist",
) -> "MemoryBackendSession":
    """
    Register an AI Scientist pipeline with the Aiglos guard.

    Protects the full AI Scientist architecture (Sakana AI, Nature 2026):
      - Idea generation logs (ideas/)
      - Experiment results (experiment_results/, results/)
      - Generated paper archives (logs/generated_papers_*)
      - Automated Reviewer outputs (review_results/, reviewer_outputs/)
      - Scaling result artifacts

    The Automated Reviewer is the highest-risk surface: its judgments feed
    back into the pipeline, and a compromised reviewer scores adversarially
    crafted papers highly. Combined with the scaling law of science (better
    foundation models → more convincing outputs), a single T82 injection into
    the reviewer criteria produces increasingly convincing misinformation at
    scale. METACOGNITIVE_POISON_CHAIN captures this: T31/T79 → T82.

    guard:         OpenClawGuard instance to attach to.
    idea_path:     Override path for idea generation logs.
    paper_path:    Override path for generated paper archive.
    reviewer_path: Override path for reviewer outputs / criteria.
    pipeline_name: Pipeline identifier for logging.

    Returns a MemoryBackendSession with registered paths.

    Example:
        from aiglos.integrations.gigabrain import declare_ai_scientist_pipeline

        # Sakana AI-Scientist default layout
        session = declare_ai_scientist_pipeline(guard)

        # Custom layout
        session = declare_ai_scientist_pipeline(guard,
            idea_path     = "./my_ideas/",
            paper_path    = "./papers/",
            reviewer_path = "./review/outputs/",
        )
    """
    from pathlib import Path as _Path

    paths = list(AI_SCIENTIST_PATHS)

    for override, default in [
        (idea_path, "./ideas/"),
        (paper_path, "./logs/generated_papers_"),
        (reviewer_path, "./review_results/"),
    ]:
        if override:
            expanded = str(_Path(override).expanduser())
            if expanded not in paths:
                paths.insert(0, expanded)

    expanded_paths = []
    for p in paths:
        try:
            expanded_paths.append(str(_Path(p).expanduser()))
        except Exception:
            expanded_paths.append(p)

    _REGISTERED_PATHS.update(expanded_paths)

    if not hasattr(guard, '_improvement_pipelines'):
        guard._improvement_pipelines = []
    guard._improvement_pipelines.append({
        "pipeline": pipeline_name,
        "paths":    expanded_paths,
        "note":     "AI Scientist — Automated Reviewer is highest-risk T82 surface",
    })

    session = MemoryBackendSession(
        backend    = f"ai-scientist/{pipeline_name}",
        paths      = expanded_paths,
        session_id = getattr(guard, 'session_id', ''),
    )

    log.info(
        "[AI-Scientist] Registered pipeline=%s paths=%d "
        "T82 enforcement active — Automated Reviewer protected",
        pipeline_name, len(expanded_paths),
    )
    return session


def ai_scientist_autodetect(guard) -> "MemoryBackendSession":
    """
    Auto-detect AI Scientist directory structure and register T82 protection.

    Scans for known AI Scientist paths (ideas/, experiment_results/,
    logs/generated_papers_*) and registers them pre-emptively.

    Example:
        from aiglos.integrations.gigabrain import ai_scientist_autodetect
        session = ai_scientist_autodetect(guard)
    """
    from pathlib import Path as _Path

    found = []
    for p in AI_SCIENTIST_PATHS:
        # Skip glob patterns for existence check
        if '*' in p or p.endswith('_'):
            continue
        expanded = _Path(p.rstrip("/")).expanduser()
        if expanded.exists():
            found.append(str(expanded))

    if found:
        log.info("[AI-Scientist] Auto-detected pipeline at: %s", ", ".join(found))
    else:
        log.info("[AI-Scientist] No existing pipeline found — pre-emptive T82 protection registered")

    return declare_ai_scientist_pipeline(guard)


def declare_self_improvement_pipeline(
    guard,
    archive_path:  Optional[str] = None,
    eval_path:     Optional[str] = None,
    pipeline_name: str           = "dgm-hyperagents",
) -> "MemoryBackendSession":
    """
    Register a self-improvement pipeline with the Aiglos guard.

    Registers DGM-Hyperagents style pipeline paths with the T82 enforcement
    engine. Any write to these paths containing adversarial injection patterns
    fires T82 SELF_IMPROVEMENT_HIJACK before it reaches the archive.

    Unlike declare_memory_backend() (which protects cross-session memory stores),
    this function protects the evolutionary infrastructure that GENERATES future
    agents. A successful T82 injection propagates forward through all future
    generations — one poisoned turn, infinite forward propagation.

    guard:         OpenClawGuard instance to attach to.
    archive_path:  Path to agent archive directory (default: ./agents/).
    eval_path:     Path to evaluation results file (default: ./eval_results.json).
    pipeline_name: Pipeline identifier for logging.

    Returns a MemoryBackendSession with the registered paths.

    Example:
        # DGM-Hyperagents running on OpenClaw
        from aiglos.integrations.gigabrain import declare_self_improvement_pipeline
        session = declare_self_improvement_pipeline(
            guard,
            archive_path="./agents/archive/",
            eval_path="./evals/results.json",
        )

        # Or zero-config — registers all known DGM-H paths
        session = declare_self_improvement_pipeline(guard)
    """
    from pathlib import Path as _Path

    paths = list(DGM_PIPELINE_PATHS)

    if archive_path:
        expanded = str(_Path(archive_path).expanduser())
        if expanded not in paths:
            paths.insert(0, expanded)

    if eval_path:
        expanded = str(_Path(eval_path).expanduser())
        if expanded not in paths:
            paths.insert(0, expanded)

    # Expand all paths
    expanded_paths = []
    for p in paths:
        try:
            expanded_paths.append(str(_Path(p).expanduser()))
        except Exception:
            expanded_paths.append(p)

    # Register with T79/T82 path registry
    _REGISTERED_PATHS.update(expanded_paths)

    # Track on guard
    if not hasattr(guard, '_improvement_pipelines'):
        guard._improvement_pipelines = []
    guard._improvement_pipelines.append({
        "pipeline": pipeline_name,
        "paths":    expanded_paths,
    })

    session = MemoryBackendSession(
        backend    = f"self-improvement/{pipeline_name}",
        paths      = expanded_paths,
        session_id = getattr(guard, 'session_id', ''),
    )

    log.info(
        "[DGM-H] Registered self-improvement pipeline=%s paths=%d "
        "T82 enforcement active",
        pipeline_name, len(expanded_paths),
    )
    return session


def dgm_hyperagents_autodetect(guard) -> Optional["MemoryBackendSession"]:
    """
    Auto-detect DGM-Hyperagents directory structure and register T82 protection.

    Scans for known DGM-H paths (agents/, archive/, eval_results.json, etc.)
    and registers them with the T82 enforcement engine. If a DGM-H style
    directory structure is detected, logs a warning that self-improvement
    pipeline protection is now active.

    Example:
        from aiglos.integrations.gigabrain import dgm_hyperagents_autodetect
        session = dgm_hyperagents_autodetect(guard)
    """
    from pathlib import Path as _Path

    found = []
    for p in DGM_PIPELINE_PATHS:
        expanded = _Path(p.rstrip("/")).expanduser()
        if expanded.exists():
            found.append(str(expanded))

    if found:
        log.info(
            "[DGM-H] Auto-detected self-improvement pipeline at: %s",
            ", ".join(found)
        )
    else:
        log.info(
            "[DGM-H] No existing pipeline found — "
            "registering paths for pre-emptive T82 protection"
        )

    return declare_self_improvement_pipeline(guard)


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


# ── KAIROS multi-agent orchestrator integration ──────────────────────────────

KAIROS_PATHS = [
    "~/.kairos/config.yaml",
    "~/.kairos/agents.yaml",
    "~/.kairos/sessions/",
    ".kairos/config.yaml",
    ".kairos/agents.yaml",
]


def declare_kairos_agent(guard, agent_id: str, role: str = "worker") -> dict:
    """
    Register a KAIROS-managed agent with the Aiglos guard.

    KAIROS manages multi-agent pipelines. Each agent in the pipeline
    gets its own Aiglos guard, but they share session context for
    cross-agent coordination detection (T28).
    """
    if not hasattr(guard, '_kairos_agents'):
        guard._kairos_agents = []

    entry = {
        "agent_id": agent_id,
        "role":     role,
        "declared": True,
    }
    guard._kairos_agents.append(entry)
    log.info("[KAIROS] Agent declared: %s (role=%s)", agent_id, role)
    return entry


def kairos_autodetect(guard) -> bool:
    """
    Auto-detect KAIROS configuration files and register paths.
    Returns True if KAIROS config was found.
    """
    found = False
    for kp in KAIROS_PATHS:
        expanded = str(Path(kp).expanduser())
        if Path(expanded).exists():
            if not hasattr(guard, '_kairos_paths'):
                guard._kairos_paths = []
            guard._kairos_paths.append(expanded)
            found = True
            log.info("[KAIROS] Config found: %s", expanded)
    return found


# ── Hermes supervisor integration ─────────────────────────────────────────────

HERMES_PEER_MENTIONS = re.compile(
    r'(?:@|mention|notify|escalate\s+to)\s*[a-zA-Z_][a-zA-Z0-9_\-]*',
    re.IGNORECASE,
)


def declare_hermes_supervisor(guard, supervisor_id: str) -> dict:
    """
    Register a Hermes supervisor agent.
    Hermes supervises multi-agent workflows — this declaration lets
    Aiglos distinguish legitimate supervisor commands from T28
    cross-agent coordination attacks.
    """
    if not hasattr(guard, '_hermes_supervisors'):
        guard._hermes_supervisors = []

    entry = {
        "supervisor_id": supervisor_id,
        "declared":      True,
    }
    guard._hermes_supervisors.append(entry)
    log.info("[Hermes] Supervisor declared: %s", supervisor_id)
    return entry


def hermes_on_escalation(guard, from_agent: str, to_agent: str,
                         reason: str = "") -> dict:
    """
    Record an escalation event between agents in a Hermes-managed workflow.
    Returns the event dict for logging.
    """
    event = {
        "type":       "escalation",
        "from_agent": from_agent,
        "to_agent":   to_agent,
        "reason":     reason,
        "declared_supervisors": [
            s["supervisor_id"]
            for s in getattr(guard, '_hermes_supervisors', [])
        ],
    }
    if not hasattr(guard, '_hermes_events'):
        guard._hermes_events = []
    guard._hermes_events.append(event)
    log.info("[Hermes] Escalation: %s -> %s (%s)", from_agent, to_agent, reason)
    return event


def hermes_on_escalation_resolved(guard, from_agent: str, to_agent: str,
                                   resolution: str = "completed") -> dict:
    """
    Record resolution of an escalation event.
    """
    event = {
        "type":       "escalation_resolved",
        "from_agent": from_agent,
        "to_agent":   to_agent,
        "resolution": resolution,
    }
    if not hasattr(guard, '_hermes_events'):
        guard._hermes_events = []
    guard._hermes_events.append(event)
    log.info("[Hermes] Resolved: %s -> %s (%s)", from_agent, to_agent, resolution)
    return event
