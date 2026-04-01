"""
aiglos.config
Configuration loaded from environment variables.  Zero-file, zero-yaml.

Required env vars (only one):
  AIGLOS_KEY   -- API key from aiglos.io.  If absent, runs in free-tier mode
                  (local-only scanning, no cloud telemetry, 10,000 call limit)

Optional env vars:
  AIGLOS_MODE                 -- "block" (default) | "warn" | "audit"
  AIGLOS_ENDPOINT             -- cloud telemetry endpoint (default: https://api.aiglos.io/v1)
  AIGLOS_LOG_LEVEL            -- "debug" | "info" (default) | "warning" | "error"
  AIGLOS_FREE_LIMIT           -- free-tier call limit per month (default: 10000)
  AIGLOS_INTERCEPT_HTTP       -- "true" | "false" -- HTTP/API interception (default: false in free, true in Pro)
  AIGLOS_ALLOW_HTTP           -- comma-separated allow-list hosts for HTTP layer
  AIGLOS_INTERCEPT_SUBPROCESS -- "true" | "false" -- subprocess monitoring (default: false)
  AIGLOS_TIER3_MODE           -- "block" | "pause" | "warn" -- Tier 3 subprocess handling
  AIGLOS_TIER3_WEBHOOK        -- URL to POST Tier 3 approval requests (pause mode)
"""

from __future__ import annotations

import os
import logging


class AiglosConfig:
    """
    Resolved configuration for the Aiglos embedded library.
    All fields have safe defaults so the library works with zero configuration.
    """

    DEFAULT_ENDPOINT = "https://api.aiglos.io/v1"
    DEFAULT_FREE_LIMIT = 10_000

    def __init__(
        self,
        api_key: str | None = None,
        mode: str = "block",
        endpoint: str = DEFAULT_ENDPOINT,
        log_level: str = "info",
        free_limit: int = DEFAULT_FREE_LIMIT,
        intercept_http: bool = False,
        allow_http: list | None = None,
        intercept_subprocess: bool = False,
        subprocess_tier3_mode: str = "warn",
        tier3_approval_webhook: str | None = None,
    ):
        self.api_key = api_key
        self.mode = mode                    # "block" | "warn" | "audit"
        self.endpoint = endpoint
        self.log_level = log_level
        self.free_limit = free_limit
        self.is_free_tier = not bool(api_key)
        # Protocol-agnostic interception settings
        self.intercept_http = intercept_http
        self.allow_http: list[str] = allow_http or []
        self.intercept_subprocess = intercept_subprocess
        self.subprocess_tier3_mode = subprocess_tier3_mode  # "block" | "pause" | "warn"
        self.tier3_approval_webhook = tier3_approval_webhook

    @classmethod
    def from_env(cls) -> AiglosConfig:
        key = os.environ.get("AIGLOS_KEY", "").strip() or None
        mode = os.environ.get("AIGLOS_MODE", "block").strip().lower()
        if mode not in ("block", "warn", "audit"):
            mode = "block"
        endpoint = os.environ.get("AIGLOS_ENDPOINT", cls.DEFAULT_ENDPOINT).strip()
        log_level = os.environ.get("AIGLOS_LOG_LEVEL", "info").strip().lower()
        try:
            free_limit = int(os.environ.get("AIGLOS_FREE_LIMIT", str(cls.DEFAULT_FREE_LIMIT)))
        except ValueError:
            free_limit = cls.DEFAULT_FREE_LIMIT

        # HTTP/subprocess interception settings
        _env_true = lambda k, default: (
            os.environ.get(k, "").strip().lower() in ("true", "1", "yes")
            if os.environ.get(k, "").strip()
            else default
        )
        intercept_http = _env_true("AIGLOS_INTERCEPT_HTTP", bool(key))  # Pro: on by default
        allow_http_raw = os.environ.get("AIGLOS_ALLOW_HTTP", "").strip()
        allow_http = [h.strip() for h in allow_http_raw.split(",") if h.strip()]
        intercept_subprocess = _env_true("AIGLOS_INTERCEPT_SUBPROCESS", False)
        tier3_mode = os.environ.get("AIGLOS_TIER3_MODE", "warn").strip().lower()
        if tier3_mode not in ("block", "pause", "warn"):
            tier3_mode = "warn"
        tier3_webhook = os.environ.get("AIGLOS_TIER3_WEBHOOK", "").strip() or None

        # Apply log level
        numeric = getattr(logging, log_level.upper(), logging.INFO)
        logging.getLogger("aiglos").setLevel(numeric)

        return cls(
            api_key=key,
            mode=mode,
            endpoint=endpoint,
            log_level=log_level,
            free_limit=free_limit,
            intercept_http=intercept_http,
            allow_http=allow_http,
            intercept_subprocess=intercept_subprocess,
            subprocess_tier3_mode=tier3_mode,
            tier3_approval_webhook=tier3_webhook,
        )

    def __repr__(self) -> str:
        masked = f"{self.api_key[:8]}..." if self.api_key else "None"
        return (
            f"AiglosConfig(api_key={masked}, mode={self.mode}, "
            f"free_tier={self.is_free_tier}, "
            f"intercept_http={self.intercept_http}, "
            f"intercept_subprocess={self.intercept_subprocess})"
        )
