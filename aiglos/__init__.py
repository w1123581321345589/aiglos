"""
Aiglos — AI Agent Security Runtime
===================================
Runtime security monitor for AI agent frameworks.
Intercepts tool calls before execution, blocks T1-T36 threats,
and produces cryptographically signed session artifacts.

Quick start:
    import aiglos
    aiglos.attach(policy="enterprise")

    result = aiglos.check("terminal", {"command": cmd})
    if result.blocked:
        raise RuntimeError(result.reason)

    aiglos.on_heartbeat()          # call at each cron/heartbeat cycle
    artifact = aiglos.close()      # signed session artifact

Framework integrations:
    from aiglos.integrations.openclaw import OpenClawGuard, attach, check, close
    from aiglos.integrations.hermes import HermesGuard, attach, check, close
"""

from __future__ import annotations

from typing import Any, Dict, Optional

__version__ = "0.1.0"
__author__  = "Aiglos"
__email__   = "will@aiglos.dev"
__license__ = "MIT"

# Re-export the most commonly used integration surface.
# By default the module-level API uses a generic guard that works
# without any framework-specific integration.

from aiglos.integrations.openclaw import (   # noqa: F401
    OpenClawGuard,
    SessionArtifact,
    GuardResult as CheckResult,
)
from aiglos.integrations.openclaw import (
    attach   as _oc_attach,
    check    as _oc_check,
    close    as _oc_close,
)
from aiglos.integrations.hermes import (     # noqa: F401
    HermesGuard,
)

# ---------------------------------------------------------------------------
# Module-level generic API  (framework-agnostic)
# ---------------------------------------------------------------------------
# Uses the OpenClaw integration as the default guard because it ships
# the most complete T1-T36 detection surface.  To use the hermes-specific
# surface, import from aiglos.integrations.hermes directly.

def attach(
    agent_name: str = "aiglos",
    policy:     str = "enterprise",
    log_path:   str = "./aiglos.log",
    **kwargs,
) -> "OpenClawGuard":
    """
    Attach Aiglos to the current session.

    Parameters
    ----------
    agent_name:
        Display name used in logs and the session artifact.
    policy:
        One of permissive | enterprise | strict | federal.
        federal enables NDAA §1513 artifact signing.
    log_path:
        Path for the append-only audit log.

    Returns
    -------
    OpenClawGuard
        Active guard instance. Most callers don't need the return value;
        use the module-level check() / close() functions instead.
    """
    return _oc_attach(agent_name=agent_name, policy=policy, log_path=log_path)


def check(
    tool_name: str,
    tool_args: Optional[Dict[str, Any]] = None,
) -> "CheckResult":
    """
    Evaluate a tool call before execution.

    Returns a CheckResult with .blocked / .warned / .allowed verdict.
    If blocked, do not execute the call.
    """
    return _oc_check(tool_name, tool_args or {})


def on_heartbeat() -> None:
    """Notify Aiglos of a cron/heartbeat cycle boundary."""
    from aiglos.integrations import openclaw as _oc
    if _oc._active_guard:
        _oc._active_guard.on_heartbeat()


def close() -> "SessionArtifact":
    """
    Close the current session and return a signed SessionArtifact.
    Call once at agent shutdown or end of task.
    """
    return _oc_close()


__all__ = [
    "__version__",
    "attach",
    "check",
    "on_heartbeat",
    "close",
    "OpenClawGuard",
    "HermesGuard",
    "CheckResult",
    "SessionArtifact",
]
