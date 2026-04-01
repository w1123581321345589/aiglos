"""
aiglos -- The Security Runtime for AI Agents

Zero-config embedded library.  One import, instant protection.

    import aiglos          # that's it.  Every MCP tool call is now scanned.

Or with an API key for cloud telemetry + usage billing:

    export AIGLOS_KEY=ak_live_xxx
    import aiglos

Or explicit control:

    import aiglos
    aiglos.register(mode="warn")   # override mode at runtime

Four-tier deployment:
  1. Library embed     (this file)      -- seconds
  2. Cloud proxy       (docker)         -- minutes
  3. On-prem container                  -- hours
  4. Program contract  (DoD/enterprise) -- weeks

Full stack: https://aiglos.dev/docs
"""

from __future__ import annotations

import os
import logging

from .config import AiglosConfig
from .interceptor import AiglosInterceptor, AiglosBlockedError
from .scanner import FastPathScanner, ScanResult, ScanVerdict
from .metering import MeterClient

__version__ = "1.0.0"
__all__ = [
    "register",
    "status",
    "stats",
    "AiglosInterceptor",
    "AiglosBlockedError",
    "FastPathScanner",
    "ScanResult",
    "ScanVerdict",
    "AiglosConfig",
    "MeterClient",
]

log = logging.getLogger("aiglos")

_interceptor: AiglosInterceptor | None = None


def _auto_register() -> None:
    """Called automatically when `import aiglos` executes."""
    global _interceptor
    config = AiglosConfig.from_env()

    _interceptor = AiglosInterceptor(config=config)
    result = _interceptor.register()

    patched = [k for k, v in result.items() if v]
    if patched:
        log.info(
            "[Aiglos %s] Registered. Patched: %s. Mode: %s. Free tier: %s",
            __version__,
            ", ".join(p.split(".")[-1] for p in patched),
            config.mode,
            config.is_free_tier,
        )
    else:
        log.info(
            "[Aiglos %s] Registered (MCP SDK not yet imported). "
            "Import hook active.",
            __version__,
        )

    if config.is_free_tier:
        print(
            f"[Aiglos] Running in free tier (up to {config.free_limit:,} tool calls/month). "
            f"Set AIGLOS_KEY for cloud telemetry. aiglos.dev"
        )


def register(
    api_key: str | None = None,
    mode: str | None = None,
) -> AiglosInterceptor:
    """
    Explicitly register (or re-register) the Aiglos interceptor.

    Call this if you want to override env-var configuration at runtime:

        aiglos.register(mode="warn")   # log threats but don't block
        aiglos.register(api_key="ak_live_xxx")

    Returns the AiglosInterceptor singleton.
    """
    global _interceptor

    config = AiglosConfig.from_env()
    if api_key is not None:
        config.api_key = api_key
        config.is_free_tier = False
    if mode is not None:
        if mode in ("block", "warn", "audit"):
            config.mode = mode

    _interceptor = AiglosInterceptor(config=config)
    _interceptor.register()
    return _interceptor


def status() -> dict:
    """Return current interceptor status."""
    if _interceptor is None:
        return {"registered": False, "message": "Call aiglos.register() first"}
    return _interceptor.status()


def stats() -> dict:
    """Return usage statistics from the metering client."""
    if _interceptor is None:
        return {}
    return _interceptor.meter.stats()


_auto_register()
