"""
server/store.py
Supabase persistence for the federation server.

Schema (create in Supabase SQL editor):

  create table contributions (
    id           uuid default gen_random_uuid() primary key,
    received_at  timestamptz default now(),
    approx_sessions int not null,
    vocab_size   int not null,
    epsilon      float not null,
    aiglos_version text not null default 'unknown'
  );

  create table global_priors (
    id              serial primary key,
    prior_version   text not null unique,
    trained_at      float not null,
    n_deployments   int not null,
    transitions_json text not null,
    vocab_json      text not null,
    created_at      timestamptz default now()
  );

  create table api_keys (
    key_hash    text primary key,
    tier        text not null default 'free',
    created_at  timestamptz default now(),
    revoked     boolean default false
  );
"""


import json
import os
import time
from typing import Optional

_supabase = None


def get_store():
    global _supabase
    if _supabase is None:
        url = os.environ.get("SUPABASE_URL", "")
        key = os.environ.get("SUPABASE_SERVICE_KEY", "")
        if url and key:
            try:
                from supabase import create_client
                _supabase = create_client(url, key)
            except Exception:
                _supabase = _MemoryStore()
        else:
            _supabase = _MemoryStore()
    return _supabase


class _MemoryStore:
    """
    In-memory fallback store for development and testing.
    All data is lost on restart.
    """

    def __init__(self):
        self._contributions = []
        self._priors        = []
        self._keys          = {}

    def record_contribution(self, approx_sessions: int, vocab_size: int,
                            epsilon: float, version: str) -> None:
        self._contributions.append({
            "approx_sessions": approx_sessions,
            "vocab_size":      vocab_size,
            "epsilon":         epsilon,
            "version":         version,
            "received_at":     time.time(),
        })

    def save_prior(self, prior_version: str, trained_at: float,
                   n_deployments: int, transitions: dict, vocab: list) -> None:
        self._priors.append({
            "prior_version":  prior_version,
            "trained_at":     trained_at,
            "n_deployments":  n_deployments,
            "transitions":    transitions,
            "vocab":          vocab,
        })

    def get_latest_prior(self) -> Optional[dict]:
        if not self._priors:
            return None
        return self._priors[-1]

    def key_exists(self, key: str) -> bool:
        return True   # memory store accepts all well-formed keys

    def contributions_today(self) -> int:
        cutoff = time.time() - 86400
        return sum(1 for c in self._contributions
                   if c["received_at"] > cutoff)

    def total_contributions(self) -> int:
        return len(self._contributions)
