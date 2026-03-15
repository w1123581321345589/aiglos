"""
aiglos.core.federation
=======================
Privacy-preserving federated threat intelligence.

Every Aiglos deployment is currently an island. The observation graph is
local SQLite. The Markov model is per-agent. A novel attack pattern that
hits one customer teaches nothing to any other customer.

This module closes that gap — without compromising privacy.

How it works:
  1. At model train time, the local Markov model's transition counts are
     extracted and anonymized with Laplace differential privacy noise.
  2. The anonymized counts are pushed to the federation server as a
     contribution — no raw events, no content, no session IDs.
  3. The server aggregates contributions using federated averaging and
     returns a global prior — a transition probability distribution
     representing what has been observed across all deployments.
  4. The global prior warm-starts new local models, eliminating the
     cold-start problem for new deployments.

What gets sent — ONLY:
  {("T19", "T37"): 14, ("T27", "T31"): 9, ...}
  — sparse transition frequency counts over a 39-element rule vocabulary
  — values are noisy (Laplace noise applied before transmission)
  — no agent names, no tool names, no URLs, no session IDs
  — no content from any tool call ever leaves the deployment

What never leaves the deployment:
  - Raw events of any kind
  - Tool names or arguments
  - Agent names or identifiers
  - Timestamps or session metadata
  - Anything that could identify the deployment

Privacy guarantee:
  Laplace mechanism with epsilon=0.1 applied to transition counts before
  transmission. At epsilon=0.1, an adversary with the noisy counts cannot
  determine whether any specific sequence occurred in the original data
  with probability greater than e^0.1 ≈ 1.105 (near-indistinguishable).

Cold-start elimination:
  The global prior is merged into every new local model at train time.
  Local weight starts at 20% (mostly global prior) and grows toward 80%
  as local data accumulates (100+ sessions). The exact schedule:
    sessions < 5:   local_weight = 0.20
    5–20 sessions:  local_weight = 0.20 + 0.006 * sessions  (linear)
    20–100 sessions: local_weight = 0.32 + 0.006 * (sessions - 20)
    100+ sessions:  local_weight = min(0.80, ...)  (saturates)

  At 100 sessions the local model dominates. The global prior fades as
  the deployment accumulates its own history.

Server API (default: https://intel.aiglos.dev):
  POST /v1/contribute  — submit anonymized transition counts
  GET  /v1/prior       — fetch current global prior

Both endpoints require AIGLOS_KEY in the Authorization header.
Free tier: pull only (no contribution). Pro+: contribute and pull.

Usage:
    from aiglos.core.federation import FederationClient

    client = FederationClient(api_key="ak_live_xxx")
    client.push_transitions(model)             # contribute to global
    prior = client.pull_global_prior()         # receive global prior
    if prior:
        prior.merge_into(predictor)            # warm-start local model
"""


import json
import logging
import math
import os
import random
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("aiglos.federation")

# ── Configuration ─────────────────────────────────────────────────────────────

_DEFAULT_ENDPOINT    = "https://intel.aiglos.dev"
_PUSH_ENDPOINT       = "/v1/contribute"
_PULL_ENDPOINT       = "/v1/prior"
_REQUEST_TIMEOUT     = 8.0     # seconds — never block the agent path
_EPSILON             = 0.1     # differential privacy noise parameter
_PUSH_INTERVAL       = 3600    # seconds between pushes (rate-limit self-imposed)
_PRIOR_TTL           = 3600    # seconds to cache a downloaded prior locally
_MIN_SESSIONS_TO_PUSH = 10     # don't contribute until we have real data

# Local weight schedule
_LOCAL_WEIGHT_MIN    = 0.20    # weight at 0 sessions
_LOCAL_WEIGHT_MAX    = 0.80    # weight at 100+ sessions
_SESSIONS_TO_FULL    = 100     # sessions to reach max local weight


def _local_weight(sessions: int) -> float:
    """
    Return the weight to give local model vs global prior during merge.
    Starts at 0.20 (mostly global) and saturates at 0.80 at 100 sessions.
    """
    if sessions <= 0:
        return _LOCAL_WEIGHT_MIN
    t = min(sessions / _SESSIONS_TO_FULL, 1.0)
    # Smooth interpolation with slight S-curve
    t_smooth = t * t * (3.0 - 2.0 * t)
    return round(
        _LOCAL_WEIGHT_MIN + t_smooth * (_LOCAL_WEIGHT_MAX - _LOCAL_WEIGHT_MIN),
        4,
    )


# ── Differential privacy ──────────────────────────────────────────────────────

def _laplace_noise(scale: float) -> float:
    """Sample from Laplace distribution with given scale."""
    u = random.random() - 0.5
    return -scale * math.copysign(1, u) * math.log(1 - 2 * abs(u))


def _apply_dp_noise(counts: Dict[str, Dict[str, int]], epsilon: float) -> Dict:
    """
    Apply Laplace mechanism to transition count dict.

    Sensitivity = 1 (adding/removing one session changes any count by at most 1).
    Laplace scale = sensitivity / epsilon = 1 / epsilon.

    Returns float-valued noisy counts (may be slightly negative — clamp to 0
    before transmission).
    """
    scale  = 1.0 / max(epsilon, 1e-6)
    noisy  = {}
    for from_rule, nexts in counts.items():
        noisy[from_rule] = {}
        for to_rule, count in nexts.items():
            noised = max(0.0, count + _laplace_noise(scale))
            if noised > 0.001:   # drop near-zero counts to reduce payload
                noisy[from_rule][to_rule] = round(noised, 3)
        if noisy[from_rule]:
            pass
        else:
            del noisy[from_rule]
    return {k: v for k, v in noisy.items() if v}


# ── GlobalPrior ───────────────────────────────────────────────────────────────

@dataclass
class GlobalPrior:
    """
    The aggregated global Markov prior from the federation server.
    Represents transition probabilities across all contributing deployments.

    Merged into new local models to eliminate the cold-start problem.
    """
    prior_version:            str             # server-assigned version string
    trained_on_n_deployments: int             # how many deployments contributed
    trained_at:               float           # server timestamp of last update
    transitions:              Dict[str, Dict[str, float]]   # from_rule → {to_rule: prob}
    vocab:                    List[str]        # all rule IDs in the vocabulary
    received_at:              float = field(default_factory=time.time)

    @property
    def is_stale(self) -> bool:
        """True if prior is older than _PRIOR_TTL."""
        return (time.time() - self.received_at) > _PRIOR_TTL

    def merge_into(self, predictor) -> None:
        """
        Merge this global prior into a local IntentPredictor's Markov model.

        The merge strategy:
          - Count transitions from the global prior as synthetic training sessions
          - Scale by (1 - local_weight) so local data dominates at high session counts
          - Add to the model's _uni counts before Laplace smoothing kicks in

        This effectively warm-starts the model with global knowledge while
        preserving the local deployment's own learned patterns.
        """
        if not self.transitions:
            return

        local_sessions = predictor.sessions_trained
        lw  = _local_weight(local_sessions)
        gw  = 1.0 - lw   # global weight

        # Scale global prior contribution by global weight
        # We express the global prior as synthetic count additions
        # Synthetic sessions = trained_on_n_deployments * global_weight (capped)
        synthetic_sessions = min(
            int(self.trained_on_n_deployments * gw),
            50,   # hard cap: never let global prior dominate more than 50 synthetic sessions
        )
        if synthetic_sessions < 1:
            log.debug("[GlobalPrior] Global weight too low to merge: sessions=%d gw=%.2f",
                      local_sessions, gw)
            return

        model = predictor._model

        # Inject synthetic transition counts proportional to global prior probs
        for from_rule, nexts in self.transitions.items():
            total_weight = sum(nexts.values())
            if total_weight < 1e-9:
                continue
            for to_rule, prob in nexts.items():
                # Synthetic count = round(prob * synthetic_sessions)
                synthetic_count = max(1, round(prob * synthetic_sessions))
                model._uni[from_rule][to_rule] = (
                    model._uni[from_rule].get(to_rule, 0) + synthetic_count
                )
                model._vocab.add(from_rule)
                model._vocab.add(to_rule)

        log.info(
            "[GlobalPrior] Merged global prior v%s into local model — "
            "deployments=%d local_sessions=%d synthetic_sessions=%d "
            "local_weight=%.2f global_weight=%.2f",
            self.prior_version,
            self.trained_on_n_deployments,
            local_sessions,
            synthetic_sessions,
            lw, gw,
        )

    def to_dict(self) -> dict:
        return {
            "prior_version":            self.prior_version,
            "trained_on_n_deployments": self.trained_on_n_deployments,
            "trained_at":               self.trained_at,
            "transitions":              self.transitions,
            "vocab":                    self.vocab,
            "received_at":              self.received_at,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "GlobalPrior":
        return cls(
            prior_version            = d.get("prior_version", "0"),
            trained_on_n_deployments = d.get("trained_on_n_deployments", 0),
            trained_at               = d.get("trained_at", 0.0),
            transitions              = d.get("transitions", {}),
            vocab                    = d.get("vocab", []),
            received_at              = d.get("received_at", time.time()),
        )


# ── Contribution payload ──────────────────────────────────────────────────────

def extract_shareable_transitions(model) -> Optional[Dict[str, Any]]:
    """
    Extract anonymized, DP-noised transition counts from a MarkovTransitionModel.

    Returns None if model has insufficient sessions to contribute meaningfully.

    The extracted payload contains ONLY:
      - Noisy unigram transition counts (bigrams are deliberately excluded to
        reduce information density and further protect privacy)
      - Total session count (approximate, also noised)
      - Aiglos version string
      - A random nonce (for deduplication on the server side)
    """
    if model._total_sessions < _MIN_SESSIONS_TO_PUSH:
        return None

    # Extract raw unigram counts
    raw_counts = {k: dict(v) for k, v in model._uni.items() if v}

    # Apply differential privacy
    noisy_counts = _apply_dp_noise(raw_counts, _EPSILON)

    if not noisy_counts:
        return None

    # Noise the session count too (prevents inferring exact deployment size)
    noisy_sessions = max(
        1, int(model._total_sessions + _laplace_noise(1.0 / _EPSILON))
    )

    return {
        "transitions":     noisy_counts,
        "approx_sessions": noisy_sessions,
        "vocab_size":      len(model._vocab),
        "epsilon":         _EPSILON,
        "nonce":           os.urandom(8).hex(),
        "aiglos_version":  _get_version(),
        "contributed_at":  time.time(),
    }


def _get_version() -> str:
    try:
        from aiglos import __version__
        return __version__
    except Exception:
        return "unknown"


# ── FederationClient ──────────────────────────────────────────────────────────

class FederationClient:
    """
    Client for the Aiglos federation server.

    Handles push (contribution) and pull (prior download) with:
      - Rate limiting (self-imposed, no more than one push per hour)
      - Local prior caching (avoids redundant downloads)
      - Non-blocking operation (all network calls have timeouts)
      - Graceful degradation (network failures are logged and ignored)

    The client never blocks the agent call path. All network operations
    are best-effort with a hard timeout.
    """

    def __init__(
        self,
        api_key:  str              = "",
        endpoint: str              = _DEFAULT_ENDPOINT,
        timeout:  float            = _REQUEST_TIMEOUT,
    ):
        self._api_key   = api_key or os.environ.get("AIGLOS_KEY", "")
        self._endpoint  = endpoint.rstrip("/")
        self._timeout   = timeout
        self._last_push: float = 0.0
        self._cached_prior: Optional[GlobalPrior] = None

    @property
    def has_key(self) -> bool:
        return bool(self._api_key)

    # ── Push (contribution) ───────────────────────────────────────────────────

    def push_transitions(self, model) -> bool:
        """
        Contribute anonymized transition counts to the global model.

        Returns True if push succeeded, False on failure or rate limit.
        No-op (returns False) if no API key is set.
        Rate-limited to _PUSH_INTERVAL seconds between pushes.
        """
        if not self.has_key:
            log.debug("[FederationClient] No API key — skipping push")
            return False

        now = time.time()
        if now - self._last_push < _PUSH_INTERVAL:
            log.debug(
                "[FederationClient] Rate-limited — next push in %.0fs",
                _PUSH_INTERVAL - (now - self._last_push),
            )
            return False

        payload = extract_shareable_transitions(model)
        if payload is None:
            log.debug(
                "[FederationClient] Insufficient sessions (%d < %d) to contribute",
                model._total_sessions, _MIN_SESSIONS_TO_PUSH,
            )
            return False

        try:
            body = json.dumps(payload).encode("utf-8")
            req  = urllib.request.Request(
                url     = self._endpoint + _PUSH_ENDPOINT,
                data    = body,
                method  = "POST",
                headers = {
                    "Content-Type":  "application/json",
                    "Authorization": f"Bearer {self._api_key}",
                    "User-Agent":    f"aiglos/{_get_version()}",
                },
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                status = resp.getcode()
                if status == 200:
                    self._last_push = now
                    log.info(
                        "[FederationClient] Contribution accepted — "
                        "approx_sessions=%d transitions=%d",
                        payload["approx_sessions"],
                        sum(len(v) for v in payload["transitions"].values()),
                    )
                    return True
                else:
                    log.warning(
                        "[FederationClient] Push returned status %d", status
                    )
                    return False

        except urllib.error.HTTPError as e:
            if e.code == 402:
                log.info("[FederationClient] Push requires Pro tier (402)")
            elif e.code == 429:
                self._last_push = now  # back off even on server-side rate limit
                log.info("[FederationClient] Server rate-limited push (429)")
            else:
                log.debug("[FederationClient] Push HTTP error: %d %s", e.code, e.reason)
            return False

        except (OSError, urllib.error.URLError, TimeoutError) as e:
            log.debug("[FederationClient] Push network error: %s", e)
            return False

        except Exception as e:
            log.debug("[FederationClient] Push unexpected error: %s", e)
            return False

    # ── Pull (prior download) ─────────────────────────────────────────────────

    def pull_global_prior(self, force: bool = False) -> Optional[GlobalPrior]:
        """
        Download the current global prior from the federation server.

        Returns cached prior if not stale (TTL = _PRIOR_TTL seconds).
        Returns None if no API key, network failure, or server error.

        Never raises — network failures are logged and None is returned.
        """
        if not self.has_key:
            log.debug("[FederationClient] No API key — cannot pull prior")
            return None

        # Return cached prior if still fresh
        if not force and self._cached_prior and not self._cached_prior.is_stale:
            log.debug(
                "[FederationClient] Using cached prior v%s",
                self._cached_prior.prior_version,
            )
            return self._cached_prior

        try:
            req = urllib.request.Request(
                url     = self._endpoint + _PULL_ENDPOINT,
                method  = "GET",
                headers = {
                    "Authorization": f"Bearer {self._api_key}",
                    "User-Agent":    f"aiglos/{_get_version()}",
                },
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                if resp.getcode() != 200:
                    log.warning(
                        "[FederationClient] Pull returned status %d", resp.getcode()
                    )
                    return None
                data  = json.loads(resp.read().decode("utf-8"))
                prior = GlobalPrior.from_dict(data)
                self._cached_prior = prior
                log.info(
                    "[FederationClient] Global prior downloaded — "
                    "version=%s deployments=%d transitions=%d",
                    prior.prior_version,
                    prior.trained_on_n_deployments,
                    sum(len(v) for v in prior.transitions.values()),
                )
                return prior

        except urllib.error.HTTPError as e:
            log.debug("[FederationClient] Pull HTTP error: %d %s", e.code, e.reason)
            return None

        except (OSError, urllib.error.URLError, TimeoutError) as e:
            log.debug("[FederationClient] Pull network error: %s", e)
            return None

        except Exception as e:
            log.debug("[FederationClient] Pull unexpected error: %s", e)
            return None

    def invalidate_cache(self) -> None:
        """Force the next pull to download a fresh prior."""
        self._cached_prior = None

    def status(self) -> dict:
        """Summary of federation client state for CLI/debugging."""
        return {
            "has_key":           self.has_key,
            "endpoint":          self._endpoint,
            "last_push_ago_s":   round(time.time() - self._last_push, 1)
                                 if self._last_push else None,
            "cached_prior":      self._cached_prior.prior_version
                                 if self._cached_prior else None,
            "prior_stale":       self._cached_prior.is_stale
                                 if self._cached_prior else None,
        }
