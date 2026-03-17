"""
server/auth.py
API key validation for the federation server.

Two tiers:
  Free  (ak_free_xxx)  -- pull only. Can download global prior.
  Pro   (ak_live_xxx)  -- contribute + pull. Can submit transitions and download prior.

In production, keys are stored in Supabase and validated against the DB.
In development/testing, the AIGLOS_MASTER_KEY env var bypasses all checks.

Key format:
  ak_free_<random 32 chars>   -- free tier
  ak_live_<random 32 chars>   -- pro tier
  ak_test_<random 32 chars>   -- test keys (bypass rate limits)
"""


import os
import hashlib
from typing import Optional, Tuple

from fastapi import HTTPException, Header


def _tier_from_key(key: str) -> str:
    """Derive tier from key prefix."""
    if key.startswith("ak_live_"):
        return "pro"
    if key.startswith("ak_free_"):
        return "free"
    if key.startswith("ak_test_"):
        return "test"
    return "unknown"


def validate_key(
    authorization: Optional[str] = Header(default=None),
) -> Tuple[str, str]:
    """
    FastAPI dependency that validates the Authorization header.
    Returns (api_key, tier).

    Raises HTTP 401 if missing or invalid.
    Raises HTTP 402 if free tier attempts a Pro-only operation.
    """
    master_key = os.environ.get("AIGLOS_MASTER_KEY", "")

    if not authorization:
        raise HTTPException(status_code=401, detail="Authorization header required.")

    # Strip "Bearer " prefix
    key = authorization
    if key.lower().startswith("bearer "):
        key = key[7:].strip()

    if not key:
        raise HTTPException(status_code=401, detail="API key missing.")

    # Master key bypass (dev/admin only)
    if master_key and key == master_key:
        return key, "admin"

    tier = _tier_from_key(key)
    if tier == "unknown":
        raise HTTPException(status_code=401, detail="Invalid API key format.")

    # In production: validate against Supabase
    # For MVP: accept any correctly-formatted key
    _validate_against_store(key, tier)

    return key, tier


def require_pro(
    authorization: Optional[str] = Header(default=None),
) -> Tuple[str, str]:
    """
    Like validate_key but requires Pro tier.
    Free tier gets HTTP 402.
    """
    key, tier = validate_key(authorization)
    if tier == "free":
        raise HTTPException(
            status_code=402,
            detail=(
                "Contributing to the global prior requires a Pro key. "
                "Free tier can pull the prior. "
                "Upgrade at aiglos.dev/pro"
            ),
        )
    return key, tier


def _validate_against_store(key: str, tier: str) -> None:
    """
    Validate key against the store.
    Production: check Supabase. MVP: accept any well-formed key.
    """
    # TODO production: query Supabase keys table
    # from server.store import get_store
    # store = get_store()
    # if not store.key_exists(key):
    #     raise HTTPException(status_code=401, detail="Invalid or revoked API key.")
    pass
