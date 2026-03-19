"""
aiglos/integrations/openShell.py
==================================
Aiglos integration for NVIDIA OpenShell -- the agent-agnostic security sandbox
announced at GTC 2026.

THE ARCHITECTURE INSIGHT
========================
Every AI agent has guardrails. The question is where those guardrails live.

Claude Code: permission rules enforced by the agent process itself. Earlier
this year, internal tool definitions silently overrode operator guardrails. The
agent self-approved a 383-line commit. The guardrail was inside the agent.

OpenClaw: config files the agent can rewrite. Test result from February 2026:
"The agent disabled its own safety controls instantly." The guardrail was
inside the agent.

OpenShell moves enforcement outside the agent entirely. The sandbox runs at the
kernel level. The agent cannot reason around a network policy it doesn't have
access to modify. Deny-by-default. The agent doesn't know what it can't reach.

    openshell sandbox create -- claude    # Claude Code inside OpenShell
    openshell sandbox create -- codex     # Codex inside OpenShell
    openshell sandbox create -- cursor    # Cursor inside OpenShell
    openshell sandbox create -- openclaw  # OpenClaw inside OpenShell

Same YAML policy. Same isolation. Same behavioral guarantees. Agent-agnostic.

This is the CUDA parallel. NVIDIA launched CUDA for gaming because that's where
the GPUs were. They launched OpenShell for OpenClaw because that's where the
hype is. The architecture works for every agent. OpenClaw is the launch vehicle.

AIGLOS POSITION
===============
OpenShell answers: "What is this agent ALLOWED to do?" -- enforced outside the
agent's reasoning process at the kernel/network level.

Aiglos answers: "What is this agent ACTUALLY doing?" -- also enforced outside
the agent's reasoning process, at the behavioral sequence level.

Two orthogonal guarantees. Neither can be reasoned around. Both are necessary.
Neither replaces the other.

AUTO-DETECTION
==============
When an agent runs inside OpenShell, the sandbox sets environment variables:

    OPENSHELL_SANDBOX_ID    -- unique sandbox instance ID
    OPENSHELL_POLICY_PATH   -- path to the active policy YAML
    OPENSHELL_AGENT         -- which agent is running inside
    OPENSHELL_VERSION       -- OpenShell version

If these exist, Aiglos auto-configures. Zero code changes required.

Usage (manual):
    import aiglos
    from aiglos.integrations.openShell import attach_openShell

    guard = aiglos.OpenClawGuard(agent_name="my-agent")
    attach_openShell(guard)   # reads OPENSHELL_POLICY_PATH automatically

Usage (auto-detect, zero config):
    import aiglos
    # If running inside OpenShell, aiglos.attach() auto-wires.
    aiglos.attach(agent_name="my-agent")

Usage (explicit):
    from aiglos.integrations.openShell import attach_openShell
    attach_openShell(
        guard,
        policy_path="~/.nemoclaw/policy.yaml",
        agent="claude-code",
    )
"""

from __future__ import annotations

import logging
import os
from typing import Optional

log = logging.getLogger("aiglos.openShell")

ENV_SANDBOX_ID   = "OPENSHELL_SANDBOX_ID"
ENV_POLICY_PATH  = "OPENSHELL_POLICY_PATH"
ENV_AGENT        = "OPENSHELL_AGENT"
ENV_VERSION      = "OPENSHELL_VERSION"

KNOWN_AGENTS = {
    "claude-code":  "Claude Code (Anthropic)",
    "claude":       "Claude Code (Anthropic)",
    "codex":        "Codex (OpenAI)",
    "cursor":       "Cursor",
    "openclaw":     "OpenClaw",
    "windsurf":     "Windsurf",
    "aider":        "Aider",
    "continue":     "Continue",
    "cody":         "Cody (Sourcegraph)",
}


def is_inside_openShell() -> bool:
    """
    Returns True if the current process is running inside an OpenShell sandbox.

    Detection: OpenShell sets OPENSHELL_SANDBOX_ID before launching the inner agent.
    This env var is present in all OpenShell-wrapped processes.

    Example:
        if aiglos.is_inside_openShell():
            print("Running inside OpenShell -- auto-configuring")
    """
    return bool(os.environ.get(ENV_SANDBOX_ID))


def openShell_context() -> Optional[dict]:
    """
    Returns the OpenShell context if running inside a sandbox, else None.

    Return dict:
        sandbox_id:   str -- OPENSHELL_SANDBOX_ID
        policy_path:  str | None -- OPENSHELL_POLICY_PATH
        agent:        str | None -- OPENSHELL_AGENT (e.g. "claude-code")
        agent_name:   str -- human-readable agent name
        version:      str | None -- OPENSHELL_VERSION

    Example:
        ctx = aiglos.openShell_context()
        if ctx:
            print(f"Inside OpenShell {ctx['version']}, agent: {ctx['agent_name']}")
    """
    sandbox_id = os.environ.get(ENV_SANDBOX_ID)
    if not sandbox_id:
        return None

    agent_key  = os.environ.get(ENV_AGENT, "").lower()
    agent_name = KNOWN_AGENTS.get(agent_key, agent_key or "unknown agent")

    return {
        "sandbox_id":  sandbox_id,
        "policy_path": os.environ.get(ENV_POLICY_PATH),
        "agent":       agent_key or None,
        "agent_name":  agent_name,
        "version":     os.environ.get(ENV_VERSION),
    }


def openshell_detect(guard=None) -> Optional[object]:
    """
    Auto-detect an OpenShell sandbox and configure Aiglos.

    If running inside OpenShell (OPENSHELL_SANDBOX_ID is set):
      - Reads the policy from OPENSHELL_POLICY_PATH
      - Calls mark_as_nemoclaw_session() with the detected policy
      - Attaches to guard if provided

    Returns a NeMoClawSession if inside OpenShell, None otherwise.

    This is the zero-config path. Drop `import aiglos` into any agent that
    runs inside OpenShell and behavioral detection auto-wires.

    Example:
        import aiglos
        guard = aiglos.OpenClawGuard(agent_name="my-agent")
        session = aiglos.openshell_detect(guard=guard)
        if session:
            print("OpenShell detected -- behavioral layer active")
    """
    ctx = openShell_context()
    if ctx is None:
        return None

    log.info(
        "[OpenShell] Auto-detected -- sandbox=%s agent=%s version=%s",
        ctx["sandbox_id"],
        ctx["agent_name"],
        ctx["version"] or "unknown",
    )

    policy_path = ctx["policy_path"]
    if not policy_path:
        log.warning(
            "[OpenShell] OPENSHELL_POLICY_PATH not set -- "
            "behavioral detection active without policy boundary enforcement. "
            "Set OPENSHELL_POLICY_PATH to enable T69/T76 scope enforcement."
        )
        if guard is not None:
            guard.sandbox_context = True
            guard.sandbox_type    = "openShell"
        return None

    from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session
    session = mark_as_nemoclaw_session(
        policy_path = policy_path,
        session_id  = ctx["sandbox_id"],
        guard       = guard,
    )
    log.info(
        "[OpenShell] Session configured -- agent=%s policy=%s",
        ctx["agent_name"],
        policy_path,
    )
    return session


def attach_openShell(
    guard,
    policy_path:    Optional[str] = None,
    agent:          Optional[str] = None,
    session_id:     Optional[str] = None,
) -> Optional[object]:
    """
    Attach OpenShell behavioral detection to any AI agent guard.

    Works with Claude Code, Cursor, Codex, OpenClaw, or any agent running
    inside an OpenShell sandbox. The YAML policy is agent-agnostic.

    guard:        Any Aiglos guard (OpenClawGuard or compatible)
    policy_path:  Path to the OpenShell YAML policy file.
                  If None, reads from OPENSHELL_POLICY_PATH env var,
                  then falls back to ~/.nemoclaw/policy.yaml
    agent:        Agent identifier: "claude-code" | "codex" | "cursor" | etc.
                  If None, reads from OPENSHELL_AGENT env var.
    session_id:   Optional session ID. Uses OPENSHELL_SANDBOX_ID if set.

    Returns a NeMoClawSession, or None if no policy is found.

    Examples:
        # Claude Code inside OpenShell
        attach_openShell(guard, agent="claude-code")

        # Codex with explicit policy
        attach_openShell(guard,
            policy_path="/etc/openShell/strict.yaml",
            agent="codex")

        # Auto-detect everything from environment
        attach_openShell(guard)
    """
    if policy_path is None:
        policy_path = (
            os.environ.get(ENV_POLICY_PATH) or
            "~/.nemoclaw/policy.yaml"
        )
    if agent is None:
        agent = os.environ.get(ENV_AGENT, "unknown").lower()
    if session_id is None:
        session_id = os.environ.get(ENV_SANDBOX_ID)

    agent_name = KNOWN_AGENTS.get(agent, agent or "unknown agent")

    log.info(
        "[OpenShell] Attaching -- agent=%s policy=%s session=%s",
        agent_name,
        policy_path,
        session_id or "auto",
    )

    if agent_name and agent_name != "unknown agent":
        guard._openShell_agent = agent_name

    try:
        from aiglos.integrations.nemoclaw import mark_as_nemoclaw_session
        session = mark_as_nemoclaw_session(
            policy_path = policy_path,
            session_id  = session_id,
            guard       = guard,
        )
        return session
    except FileNotFoundError:
        log.warning(
            "[OpenShell] Policy file not found: %s -- "
            "T76 policy bypass detection still active, "
            "T69 scope enforcement inactive (no policy boundary defined).",
            policy_path,
        )
        guard.sandbox_context = True
        guard.sandbox_type    = "openShell"
        return None


def attach_for_claude_code(guard, policy_path: Optional[str] = None) -> Optional[object]:
    """
    Attach OpenShell + Aiglos behavioral detection for Claude Code.

        openshell sandbox create -- claude
        # Claude Code runs inside OpenShell
        # Add this to your agent setup:

        import aiglos
        from aiglos.integrations.openShell import attach_for_claude_code

        guard = aiglos.OpenClawGuard(agent_name="claude-code")
        attach_for_claude_code(guard)
    """
    return attach_openShell(guard, policy_path=policy_path, agent="claude-code")


def attach_for_codex(guard, policy_path: Optional[str] = None) -> Optional[object]:
    """
    Attach OpenShell + Aiglos behavioral detection for OpenAI Codex.

        openshell sandbox create -- codex
    """
    return attach_openShell(guard, policy_path=policy_path, agent="codex")


def attach_for_cursor(guard, policy_path: Optional[str] = None) -> Optional[object]:
    """
    Attach OpenShell + Aiglos behavioral detection for Cursor.

        openshell sandbox create -- cursor
    """
    return attach_openShell(guard, policy_path=policy_path, agent="cursor")


def attach_for_openclaw(guard, policy_path: Optional[str] = None) -> Optional[object]:
    """
    Attach OpenShell + Aiglos behavioral detection for OpenClaw.

        openshell sandbox create -- openclaw
    """
    return attach_openShell(guard, policy_path=policy_path, agent="openclaw")
