"""
Aiglos — AI Agent Security Runtime
===================================
Protocol-agnostic runtime security for AI agents. Intercepts every agent
action before execution — MCP tool calls, direct HTTP/API calls, CLI
execution, subprocess spawning — and applies T1–T36 threat detection.

Signed session artifacts cover all three execution surfaces in a single
compliance document. NDAA §1513, CMMC, and SOC 2 ready.

Quick start:
    import aiglos
    aiglos.attach(
        agent_name="my-agent",
        api_key=KEY,
        intercept_http=True,                    # optional: HTTP/API layer
        allow_http=["api.stripe.com"],          # optional: allow-list
        intercept_subprocess=True,              # optional: subprocess layer
        subprocess_tier3_mode="pause",          # optional: block | pause | warn
        tier3_approval_webhook="https://...",   # optional: PagerDuty / Slack
    )

    # MCP tool call inspection (manual API)
    result = aiglos.check("terminal", {"cmd": cmd})
    if result.blocked:
        raise RuntimeError(result.reason)

    aiglos.on_heartbeat()          # call at each cron/heartbeat cycle
    artifact = aiglos.close()      # signed session artifact -- all 3 surfaces

Framework integrations:
    from aiglos.integrations.openclaw import OpenClawGuard
    from aiglos.integrations.hermes   import HermesGuard
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

__version__ = "0.2.0"
__author__  = "Aiglos"
__email__   = "will@aiglos.dev"
__license__ = "MIT"

log = logging.getLogger("aiglos")

# Re-export key types for external use
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

_http_intercept_active:   bool = False
_subproc_intercept_active: bool = False


def attach(
    agent_name:             str            = "aiglos",
    policy:                 str            = "enterprise",
    log_path:               str            = "./aiglos.log",
    # HTTP/API interception
    intercept_http:         bool           = False,
    allow_http:             Optional[List[str]] = None,
    # Subprocess interception
    intercept_subprocess:   bool           = False,
    subprocess_tier3_mode:  str            = "warn",
    tier3_approval_webhook: Optional[str]  = None,
    **kwargs,
) -> "OpenClawGuard":
    """
    Attach Aiglos to the current session.

    Activates the MCP interception layer unconditionally.
    Optionally activates HTTP/API and subprocess layers.

    Parameters
    ----------
    agent_name              : Display name used in logs and session artifact.
    policy                  : "permissive" | "enterprise" | "strict" | "federal".
                              "federal" enables NDAA §1513 artifact signing.
    log_path                : Path for the append-only audit log.
    intercept_http          : Patch requests/httpx/aiohttp/urllib. Default False
                              (auto-True if AIGLOS_KEY set or AIGLOS_INTERCEPT_HTTP=true).
    allow_http              : Hostnames that receive relaxed HTTP rules.
                              Wildcards supported: "*.amazonaws.com".
    intercept_subprocess    : Patch subprocess module + os.system. Default False.
    subprocess_tier3_mode   : How to handle Tier 3 (destructive) commands.
                              "block" -- hard block (raises exception).
                              "pause" -- emit webhook, block until approved.
                              "warn"  -- log and allow.
    tier3_approval_webhook  : URL to POST Tier 3 approval requests (pause mode).

    Returns
    -------
    OpenClawGuard  -- active guard instance. Most callers don't need this;
                      use the module-level check() / close() functions.
    """
    global _http_intercept_active, _subproc_intercept_active

    # 1. Always activate MCP layer
    guard = _oc_attach(agent_name=agent_name, policy=policy, log_path=log_path)

    # 2. HTTP/API interception
    # Also auto-activate if AIGLOS_INTERCEPT_HTTP env var is set
    import os
    _env_http = os.environ.get("AIGLOS_INTERCEPT_HTTP", "").strip().lower() in ("true", "1", "yes")
    _env_key  = bool(os.environ.get("AIGLOS_KEY", "").strip())

    if intercept_http or _env_http:
        try:
            from aiglos.integrations.http_intercept import attach_http_intercept
            # Determine mode from policy
            mode = _policy_to_mode(policy)
            results = attach_http_intercept(
                allow_list=allow_http or [],
                mode=mode,
            )
            _http_intercept_active = True
            patched = [k for k, v in results.items() if v]
            log.info("[Aiglos] HTTP interception active: %s", patched)
        except Exception as e:
            log.warning("[Aiglos] HTTP interception failed to attach: %s", e)

    # 3. Subprocess interception
    _env_subproc = os.environ.get("AIGLOS_INTERCEPT_SUBPROCESS", "").strip().lower() in ("true", "1", "yes")
    _tier3_mode  = os.environ.get("AIGLOS_TIER3_MODE", subprocess_tier3_mode).strip().lower()
    _webhook     = os.environ.get("AIGLOS_TIER3_WEBHOOK", tier3_approval_webhook or "").strip() or tier3_approval_webhook

    if intercept_subprocess or _env_subproc:
        try:
            from aiglos.integrations.subprocess_intercept import attach_subprocess_intercept
            mode = _policy_to_mode(policy)
            results = attach_subprocess_intercept(
                mode=mode,
                tier3_mode=_tier3_mode,
                approval_webhook=_webhook or None,
            )
            _subproc_intercept_active = True
            patched = [k for k, v in results.items() if v]
            log.info("[Aiglos] Subprocess interception active: %s | tier3_mode=%s",
                     patched, _tier3_mode)
        except Exception as e:
            log.warning("[Aiglos] Subprocess interception failed to attach: %s", e)

    log.info(
        "[Aiglos v%s] Attached — agent=%s policy=%s mcp=on http=%s subprocess=%s",
        __version__, agent_name, policy,
        "on" if _http_intercept_active else "off",
        "on" if _subproc_intercept_active else "off",
    )

    return guard


def _policy_to_mode(policy: str) -> str:
    """Map guard policy to scanner mode."""
    return {
        "permissive": "warn",
        "enterprise": "block",
        "strict":     "block",
        "federal":    "block",
    }.get(policy, "block")


def check(
    tool_name: str,
    tool_args: Optional[Dict[str, Any]] = None,
) -> "CheckResult":
    """
    Evaluate an MCP tool call before execution.

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

    The artifact covers all three interception surfaces (MCP, HTTP, subprocess)
    in a unified signed document. Call once at agent shutdown or end of task.
    """
    # Collect events from all active layers
    http_events     = _collect_http_events()
    subproc_events  = _collect_subprocess_events()

    # Close the MCP guard and get base artifact
    artifact = _oc_close()

    # Attach multi-surface events if we have them and artifact supports it
    if artifact and (http_events or subproc_events):
        _augment_artifact(artifact, http_events, subproc_events)

    return artifact


def _collect_http_events() -> list:
    if not _http_intercept_active:
        return []
    try:
        from aiglos.integrations.http_intercept import (
            get_session_http_events, clear_session_http_events)
        events = get_session_http_events()
        clear_session_http_events()
        return events
    except Exception:
        return []


def _collect_subprocess_events() -> list:
    if not _subproc_intercept_active:
        return []
    try:
        from aiglos.integrations.subprocess_intercept import (
            get_session_subprocess_events, clear_session_subprocess_events)
        events = get_session_subprocess_events()
        clear_session_subprocess_events()
        return events
    except Exception:
        return []


def _augment_artifact(artifact: "SessionArtifact",
                       http_events: list,
                       subproc_events: list) -> None:
    """Attach HTTP and subprocess event lists to a session artifact."""
    try:
        if not hasattr(artifact, "extra"):
            artifact.extra = {}
        artifact.extra["http_events"]     = http_events
        artifact.extra["subproc_events"]  = subproc_events
        artifact.extra["http_blocked"]    = sum(
            1 for e in http_events if e.get("verdict") == "BLOCK")
        artifact.extra["subproc_blocked"] = sum(
            1 for e in subproc_events if e.get("verdict") == "BLOCK")
    except Exception:
        pass


def status() -> dict:
    """Return current Aiglos runtime status across all three layers."""
    mcp_status: dict = {}
    try:
        from aiglos.integrations import openclaw as _oc
        if _oc._active_guard:
            mcp_status = _oc._active_guard.status()
    except Exception:
        pass

    http_status: dict = {}
    if _http_intercept_active:
        try:
            from aiglos.integrations.http_intercept import http_intercept_status
            http_status = http_intercept_status()
        except Exception:
            pass

    subproc_status: dict = {}
    if _subproc_intercept_active:
        try:
            from aiglos.integrations.subprocess_intercept import subprocess_intercept_status
            subproc_status = subprocess_intercept_status()
        except Exception:
            pass

    return {
        "version":             __version__,
        "mcp_layer":           mcp_status,
        "http_layer_active":   _http_intercept_active,
        "http_layer":          http_status,
        "subprocess_layer_active": _subproc_intercept_active,
        "subprocess_layer":    subproc_status,
    }


__all__ = [
    "__version__",
    "attach",
    "check",
    "on_heartbeat",
    "close",
    "status",
    "OpenClawGuard",
    "HermesGuard",
    "CheckResult",
    "SessionArtifact",
]
