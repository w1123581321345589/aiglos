"""
aiglos.config
Configuration loaded from environment variables.  Zero-file, zero-yaml.

Required env vars (only one):
  AIGLOS_KEY   -- API key from aiglos.dev.  If absent, runs in free-tier mode
                  (local-only scanning, no cloud telemetry, 10,000 call limit)

Optional env vars:
  AIGLOS_MODE       -- "block" (default) | "warn" | "audit"
  AIGLOS_ENDPOINT   -- cloud telemetry endpoint (default: https://api.aiglos.dev/v1)
  AIGLOS_LOG_LEVEL  -- "debug" | "info" (default) | "warning" | "error"
  AIGLOS_FREE_LIMIT -- free-tier call limit per month (default: 10000)
"""

from __future__ import annotations

import os
import logging


class AiglosConfig:
    """
    Resolved configuration for the Aiglos embedded library.
    All fields have safe defaults so the library works with zero configuration.
    """

    DEFAULT_ENDPOINT = "https://api.aiglos.dev/v1"
    DEFAULT_FREE_LIMIT = 10_000

    def __init__(
        self,
        api_key: str | None = None,
        mode: str = "block",
        endpoint: str = DEFAULT_ENDPOINT,
        log_level: str = "info",
        free_limit: int = DEFAULT_FREE_LIMIT,
    ):
        self.api_key = api_key
        self.mode = mode                    # "block" | "warn" | "audit"
        self.endpoint = endpoint
        self.log_level = log_level
        self.free_limit = free_limit
        self.is_free_tier = not bool(api_key)

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

        # Apply log level
        numeric = getattr(logging, log_level.upper(), logging.INFO)
        logging.getLogger("aiglos").setLevel(numeric)

        return cls(
            api_key=key,
            mode=mode,
            endpoint=endpoint,
            log_level=log_level,
            free_limit=free_limit,
        )

    def __repr__(self) -> str:
        masked = f"{self.api_key[:8]}..." if self.api_key else "None"
        return (f"AiglosConfig(api_key={masked}, mode={self.mode}, "
                f"free_tier={self.is_free_tier})")
