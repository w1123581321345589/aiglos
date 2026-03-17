"""
server/models.py
Federation server request/response models.
"""


import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, validator


# ── Inbound ────────────────────────────────────────────────────────────────────

class ContributeRequest(BaseModel):
    """Anonymized transition counts from a contributing deployment."""
    transitions:     Dict[str, Dict[str, float]]   # from_rule -> {to_rule: noisy_count}
    approx_sessions: int                            # DP-noised session count
    vocab_size:      int
    epsilon:         float = 0.1
    nonce:           str   = ""
    aiglos_version:  str   = "unknown"
    contributed_at:  float = Field(default_factory=time.time)

    @validator("epsilon")
    def epsilon_must_be_positive(cls, v):
        if v <= 0 or v > 2.0:
            raise ValueError("epsilon must be in (0, 2.0]")
        return v

    @validator("transitions")
    def transitions_must_be_nonempty(cls, v):
        if not v:
            raise ValueError("transitions cannot be empty")
        return v


# ── Outbound ───────────────────────────────────────────────────────────────────

class GlobalPriorResponse(BaseModel):
    """The aggregated global Markov prior."""
    prior_version:            str
    trained_on_n_deployments: int
    trained_at:               float
    transitions:              Dict[str, Dict[str, float]]
    vocab:                    List[str]
    next_update_in_s:         int = 3600


class HealthResponse(BaseModel):
    status:          str = "ok"
    version:         str = "0.17.0"
    deployments:     int = 0
    prior_version:   str = "none"
    last_updated:    Optional[float] = None


class StatusResponse(BaseModel):
    deployments_total:     int
    contributions_today:   int
    prior_version:         str
    prior_transitions:     int
    prior_vocab_size:      int
    last_update:           Optional[float]
    next_update_in_s:      int


class ContributeResponse(BaseModel):
    accepted:    bool = True
    message:     str  = "Contribution accepted."
    prior_version: str = ""
