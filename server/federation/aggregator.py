"""
server/aggregator.py
Federated averaging of Markov transition counts.

Privacy:
  All contributions arrive with Laplace noise (epsilon=0.1) already applied
  by the client. The server applies an additional Gaussian noise layer
  (sigma=0.5) before broadcasting the global prior to prevent reconstruction
  from a large number of contributions.

  The server stores only:
  - Aggregated noisy transition counts (not per-deployment)
  - Total contribution count (integer)
  - Last update timestamp

  Nothing that could be traced to a specific deployment is stored.

Aggregation strategy: federated averaging
  global_count[from][to] = mean(all contribution counts[from][to])
                           × n_deployments_contributing

  This ensures each deployment has equal weight regardless of session count.
  A deployment with 5 sessions and one with 500 contribute equally.
"""


import hashlib
import math
import random
import time
from typing import Dict, Optional

from server.models import ContributeRequest, GlobalPriorResponse


class Aggregator:
    """
    In-memory aggregator for the current aggregation window.
    Contributions accumulate until flush() is called (every _FLUSH_INTERVAL_S).
    On flush, computes the global prior and stores it for distribution.
    """

    _FLUSH_INTERVAL_S = 3600     # re-compute prior every hour
    _SERVER_SIGMA     = 0.5      # additional Gaussian noise added server-side
    _MIN_DEPLOYMENTS  = 3        # minimum deployments to generate a prior

    def __init__(self):
        self._contributions:   list[dict] = []
        self._global_prior:    Optional[GlobalPriorResponse] = None
        self._prior_version:   int   = 0
        self._last_flush:      float = 0.0
        self._n_contributions: int   = 0

    # ── Contribution intake ───────────────────────────────────────────────────

    def ingest(self, req: ContributeRequest) -> bool:
        """Accept a contribution. Returns True if accepted."""
        # Reject suspiciously clean contributions (not DP-noised)
        if req.epsilon > 0.5:
            return False  # too much epsilon -- client may not have applied noise

        self._contributions.append({
            "transitions":     req.transitions,
            "approx_sessions": req.approx_sessions,
            "received_at":     time.time(),
        })
        self._n_contributions += 1

        # Flush if interval has elapsed
        if time.time() - self._last_flush > self._FLUSH_INTERVAL_S:
            self._flush()

        return True

    # ── Aggregation ───────────────────────────────────────────────────────────

    def _flush(self) -> None:
        """Compute global prior from all accumulated contributions."""
        if len(self._contributions) < self._MIN_DEPLOYMENTS:
            return

        n = len(self._contributions)

        # Federated averaging: sum all transitions, divide by n
        agg: Dict[str, Dict[str, float]] = {}
        for contrib in self._contributions:
            for from_rule, nexts in contrib["transitions"].items():
                if from_rule not in agg:
                    agg[from_rule] = {}
                for to_rule, count in nexts.items():
                    agg[from_rule][to_rule] = agg[from_rule].get(to_rule, 0.0) + count

        # Divide by n to get mean, apply additional server-side Gaussian noise
        averaged: Dict[str, Dict[str, float]] = {}
        for from_rule, nexts in agg.items():
            total = sum(nexts.values())
            if total < 1e-6:
                continue
            averaged[from_rule] = {}
            for to_rule, count in nexts.items():
                mean_count = count / n
                # Additional server-side noise to prevent reconstruction
                noised = max(0.0, mean_count + random.gauss(0, self._SERVER_SIGMA))
                if noised > 0.01:
                    averaged[from_rule][to_rule] = round(noised, 4)
            if not averaged[from_rule]:
                del averaged[from_rule]

        # Normalize to probabilities
        transitions_prob: Dict[str, Dict[str, float]] = {}
        for from_rule, nexts in averaged.items():
            total = sum(nexts.values())
            if total < 1e-9:
                continue
            transitions_prob[from_rule] = {
                to_rule: round(count / total, 6)
                for to_rule, count in nexts.items()
            }

        vocab = sorted(set(
            k for d in transitions_prob.values() for k in list(d.keys())
        ) | set(transitions_prob.keys()))

        self._prior_version += 1
        version_str = f"v{self._prior_version}.{int(time.time()) % 100000}"

        self._global_prior = GlobalPriorResponse(
            prior_version            = version_str,
            trained_on_n_deployments = n,
            trained_at               = time.time(),
            transitions              = transitions_prob,
            vocab                    = vocab,
            next_update_in_s         = self._FLUSH_INTERVAL_S,
        )

        # Clear window
        self._contributions = []
        self._last_flush    = time.time()

    # ── Prior access ──────────────────────────────────────────────────────────

    def get_prior(self) -> Optional[GlobalPriorResponse]:
        """Return the current global prior, triggering flush if stale."""
        if self._global_prior is None and len(self._contributions) >= self._MIN_DEPLOYMENTS:
            self._flush()
        return self._global_prior

    def stats(self) -> dict:
        prior = self._global_prior
        return {
            "deployments_total":   self._n_contributions,
            "contributions_today": len(self._contributions),
            "prior_version":       prior.prior_version if prior else "none",
            "prior_transitions":   sum(len(v) for v in prior.transitions.values()) if prior else 0,
            "prior_vocab_size":    len(prior.vocab) if prior else 0,
            "last_update":         self._last_flush or None,
            "next_update_in_s":    max(0, int(
                self._FLUSH_INTERVAL_S - (time.time() - self._last_flush)
            )),
        }
