"""
server/main.py
Aiglos Federation Server -- FastAPI application.

Endpoints:
  POST /v1/contribute   -- Pro tier: submit anonymized transition counts
  GET  /v1/prior        -- Free+Pro: download current global prior
  GET  /v1/health       -- Unauthenticated: liveness check
  GET  /v1/status       -- Unauthenticated: public stats

Deploy:
  Railway one-click: railway up
  Docker: docker build -t aiglos-fed . && docker run -p 8000:8000 aiglos-fed
  Local:  uvicorn server.main:app --reload --port 8000

Environment variables:
  AIGLOS_MASTER_KEY       -- admin bypass key (set in Railway secrets)
  SUPABASE_URL            -- Supabase project URL
  SUPABASE_SERVICE_KEY    -- Supabase service role key
  CORS_ORIGINS            -- comma-separated allowed origins (default: *)
"""


import os
import time
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from server.aggregator import Aggregator
from server.auth import validate_key, require_pro
from server.models import (
    ContributeRequest,
    ContributeResponse,
    GlobalPriorResponse,
    HealthResponse,
    StatusResponse,
)
from server.store import get_store

# ── App state ─────────────────────────────────────────────────────────────────

_aggregator = Aggregator()
_start_time = time.time()

# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load existing prior from store on startup."""
    store = get_store()
    latest = store.get_latest_prior()
    if latest:
        from server.models import GlobalPriorResponse
        try:
            prior = GlobalPriorResponse(
                prior_version            = latest["prior_version"],
                trained_on_n_deployments = latest["n_deployments"],
                trained_at               = latest["trained_at"],
                transitions              = latest["transitions"],
                vocab                    = latest["vocab"],
            )
            _aggregator._global_prior  = prior
            _aggregator._prior_version = int(
                latest["prior_version"].split(".")[0].replace("v", "") or 0
            )
        except Exception:
            pass
    yield


# ── Application ───────────────────────────────────────────────────────────────

app = FastAPI(
    title       = "Aiglos Federation Server",
    description = "Federated threat intelligence for AI agent security.",
    version     = "0.17.0",
    lifespan    = lifespan,
)

# CORS
_cors_origins = [
    o.strip() for o in
    os.environ.get("CORS_ORIGINS", "*").split(",")
]
app.add_middleware(
    CORSMiddleware,
    allow_origins     = _cors_origins,
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/v1/health", response_model=HealthResponse, tags=["meta"])
async def health():
    """Liveness check. No authentication required."""
    stats  = _aggregator.stats()
    store  = get_store()
    return HealthResponse(
        status        = "ok",
        version       = "0.17.0",
        deployments   = store.total_contributions(),
        prior_version = stats["prior_version"],
        last_updated  = stats["last_update"],
    )


@app.get("/v1/status", response_model=StatusResponse, tags=["meta"])
async def status():
    """Public statistics. No authentication required."""
    stats = _aggregator.stats()
    store = get_store()
    return StatusResponse(
        deployments_total   = store.total_contributions(),
        contributions_today = store.contributions_today(),
        prior_version       = stats["prior_version"],
        prior_transitions   = stats["prior_transitions"],
        prior_vocab_size    = stats["prior_vocab_size"],
        last_update         = stats["last_update"],
        next_update_in_s    = stats["next_update_in_s"],
    )


@app.get("/v1/prior", response_model=GlobalPriorResponse, tags=["intelligence"])
async def get_prior(auth=Depends(validate_key)):
    """
    Download the current global Markov prior.

    Available to all authenticated keys (free + pro).
    Returns the aggregated transition probabilities trained on all
    contributing deployments.

    The prior is updated approximately every hour as new contributions
    arrive. If fewer than 3 deployments have contributed, returns 404.
    """
    prior = _aggregator.get_prior()
    if prior is None:
        raise HTTPException(
            status_code = 404,
            detail      = (
                "No global prior available yet. "
                "Requires at least 3 contributing deployments. "
                f"Current contributors: {len(_aggregator._contributions)}. "
                "Be one of the first to contribute: upgrade to Pro at aiglos.dev/pro"
            ),
        )
    return prior


@app.post("/v1/contribute", response_model=ContributeResponse, tags=["intelligence"])
async def contribute(
    req:  ContributeRequest,
    auth: tuple = Depends(require_pro),
):
    """
    Submit anonymized transition counts to the global prior.

    Requires Pro tier API key.

    The client must apply Laplace noise (epsilon=0.1) before submitting.
    The server applies additional Gaussian noise before broadcasting.
    No raw events, no agent identifiers, no session data -- only
    noisy unigram counts over the 39-element rule vocabulary.
    """
    accepted = _aggregator.ingest(req)

    if accepted:
        store = get_store()
        store.record_contribution(
            approx_sessions = req.approx_sessions,
            vocab_size      = req.vocab_size,
            epsilon         = req.epsilon,
            version         = req.aiglos_version,
        )

    stats = _aggregator.stats()

    return ContributeResponse(
        accepted      = accepted,
        message       = "Contribution accepted. Thank you for strengthening the network." if accepted
                        else "Contribution rejected. Check epsilon value.",
        prior_version = stats["prior_version"],
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code = 500,
        content     = {"detail": "Internal server error.", "type": type(exc).__name__},
    )


# ── Dev entrypoint ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server.main:app", host="0.0.0.0", port=8000, reload=True)
